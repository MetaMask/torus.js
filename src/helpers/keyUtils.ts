import { mod } from "@noble/curves/abstract/modular.js";
import { bs58 } from "@toruslabs/bs58";
import { INodePub, KEY_TYPE } from "@toruslabs/constants";
import { Ecies, encrypt } from "@toruslabs/eccrypto";
import { keccak256 as keccakHash } from "ethereum-cryptography/keccak";
import { sha512 } from "ethereum-cryptography/sha512";
import stringify from "json-stable-stringify";
import log from "loglevel";

import { EncryptedSeed, ImportedShare, KeyType, Point2D, PrivateKeyData } from "../interfaces";
import {
  bigintToHex,
  bytesToBase64,
  bytesToHex,
  bytesToNumberBE,
  bytesToNumberLE,
  Curve,
  encParamsBufToHex,
  generatePrivateKey,
  getKeyCurve,
  getSecp256k1,
  hexToBytes,
  keccak256,
  toBigIntBE,
  utf8ToBytes,
} from "./common";
import { generateRandomPolynomial } from "./langrangeInterpolatePoly";
import { generateNonceMetadataParams, getSecpKeyFromEd25519 } from "./metadataUtils";

export function stripHexPrefix(str: string): string {
  return str.startsWith("0x") ? str.slice(2) : str;
}

export function toChecksumAddress(hexAddress: string): string {
  const address = stripHexPrefix(hexAddress).toLowerCase();

  const hash = bytesToHex(keccakHash(utf8ToBytes(address)));
  let ret = "0x";

  for (let i = 0; i < address.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      ret += address[i].toUpperCase();
    } else {
      ret += address[i];
    }
  }

  return ret;
}

function adjustScalarBytes(bytes: Uint8Array): Uint8Array {
  // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
  // set the three least significant bits of the first byte
  bytes[0] &= 248; // 0b1111_1000
  // and the most significant bit of the last to zero,
  bytes[31] &= 127; // 0b0111_1111
  // set the second most significant bit of the last byte to 1
  bytes[31] |= 64; // 0b0100_0000
  return bytes;
}

/** Convenience method that creates public key and other stuff. RFC8032 5.1.5 */
export function getEd25519ExtendedPublicKey(keyBuffer: Uint8Array): {
  scalar: bigint;
  point: Point2D;
} {
  const ed25519Curve = getKeyCurve(KEY_TYPE.ED25519);
  const len = 32;
  const N = ed25519Curve.Point.CURVE().n;

  if (keyBuffer.length !== 32) {
    log.error("Invalid seed for ed25519 key derivation", keyBuffer.length);
    throw new Error("Invalid seed for ed25519 key derivation");
  }
  // Hash private key with curve's hash function to produce uniformingly random input
  // Check byte lengths: ensure(64, h(ensure(32, key)))
  const hashed = sha512(keyBuffer);
  if (hashed.length !== 64) {
    throw new Error("Invalid hash length for ed25519 seed");
  }
  const head = bytesToNumberLE(adjustScalarBytes(new Uint8Array(hashed.slice(0, len))));
  const scalar = mod(head, N); // The actual private scalar
  const point = ed25519Curve.Point.BASE.multiply(scalar).toAffine(); // Point on Edwards curve aka public key
  return { scalar, point };
}

export function encodeEd25519Point(point: Point2D): Uint8Array {
  const ed25519Curve = getKeyCurve(KEY_TYPE.ED25519);
  return ed25519Curve.Point.fromAffine(point).toBytes();
}

export const generateEd25519KeyData = async (ed25519Seed: Uint8Array): Promise<PrivateKeyData> => {
  const ed25519Curve = getKeyCurve(KEY_TYPE.ED25519);
  const N = ed25519Curve.Point.CURVE().n;

  const finalEd25519Key = getEd25519ExtendedPublicKey(ed25519Seed);
  const encryptionKey = getSecpKeyFromEd25519(finalEd25519Key.scalar);

  const encPubKeyBytes = getSecp256k1().Point.fromAffine(encryptionKey.point).toBytes(true);
  const encryptedSeed = await encrypt(encPubKeyBytes, ed25519Seed);
  const encData: EncryptedSeed = {
    enc_text: bytesToHex(encryptedSeed.ciphertext),
    metadata: encParamsBufToHex(encryptedSeed),
    public_key: bytesToHex(encodeEd25519Point(finalEd25519Key.point)),
  };

  const encDataBase64 = bytesToBase64(utf8ToBytes(JSON.stringify(encData)));
  const metadataPrivNonce = bytesToNumberBE(generatePrivateKey(KEY_TYPE.ED25519));
  const oauthKey = mod(finalEd25519Key.scalar - metadataPrivNonce, N);
  const oauthPub = ed25519Curve.Point.BASE.multiply(oauthKey).toAffine();
  const metadataSigningKey = getSecpKeyFromEd25519(oauthKey);
  return {
    oAuthKeyScalar: oauthKey,
    oAuthPubX: oauthPub.x,
    oAuthPubY: oauthPub.y,
    SigningPubX: metadataSigningKey.point.x,
    SigningPubY: metadataSigningKey.point.y,
    metadataNonce: metadataPrivNonce,
    metadataSigningKey: metadataSigningKey.scalar,
    encryptedSeed: encDataBase64,
    finalUserPubKeyPoint: finalEd25519Key.point,
  };
};

export const generateSecp256k1KeyData = async (scalarBuffer: Uint8Array): Promise<PrivateKeyData> => {
  const secp256k1Curve = getKeyCurve(KEY_TYPE.SECP256K1);
  const N = secp256k1Curve.Point.CURVE().n;

  const scalar = bytesToNumberBE(scalarBuffer);
  const randomNonce = bytesToNumberBE(generatePrivateKey(KEY_TYPE.SECP256K1));
  const oAuthKey = mod(scalar - randomNonce, N);
  const oAuthPub = secp256k1Curve.Point.BASE.multiply(oAuthKey).toAffine();

  const finalUserPub = secp256k1Curve.Point.BASE.multiply(scalar).toAffine();

  return {
    oAuthKeyScalar: oAuthKey,
    oAuthPubX: oAuthPub.x,
    oAuthPubY: oAuthPub.y,
    SigningPubX: oAuthPub.x,
    SigningPubY: oAuthPub.y,
    metadataNonce: randomNonce,
    encryptedSeed: "",
    metadataSigningKey: oAuthKey,
    finalUserPubKeyPoint: finalUserPub,
  };
};

function generateAddressFromPoint(keyType: KeyType, point: Point2D): string {
  if (keyType === KEY_TYPE.SECP256K1) {
    const uncompressed = bytesToHex(getSecp256k1().Point.fromAffine(point).toBytes(false));
    const publicKey = uncompressed.slice(2); // remove 04 prefix
    const evmAddressLower = `0x${keccak256(hexToBytes(publicKey)).slice(64 - 38)}`;
    return toChecksumAddress(evmAddressLower);
  } else if (keyType === KEY_TYPE.ED25519) {
    const publicKey = encodeEd25519Point(point);
    const address = bs58.encode(publicKey);
    return address;
  }
  throw new Error(`Invalid keyType: ${keyType}`);
}

export function generateAddressFromPrivKey(keyType: KeyType, privateKey: bigint): string {
  const ecCurve = getKeyCurve(keyType);
  const point = ecCurve.Point.BASE.multiply(privateKey).toAffine();
  return generateAddressFromPoint(keyType, point);
}

export function generateAddressFromPubKey(keyType: KeyType, publicKeyX: bigint, publicKeyY: bigint): string {
  return generateAddressFromPoint(keyType, { x: publicKeyX, y: publicKeyY });
}

export function getPostboxKeyFrom1OutOf1(ecCurve: Curve, privKey: string, nonce: string): string {
  const privKeyBI = toBigIntBE(privKey);
  const nonceBI = toBigIntBE(nonce);
  return bigintToHex(mod(privKeyBI - nonceBI, ecCurve.Point.CURVE().n));
}

export function derivePubKey(ecCurve: Curve, sk: bigint): Point2D {
  return ecCurve.Point.BASE.multiply(sk).toAffine();
}

export const generateShares = async (
  ecCurve: Curve,
  keyType: KeyType,
  serverTimeOffset: number,
  nodeIndexes: number[],
  nodePubkeys: INodePub[],
  privKey: Uint8Array
) => {
  const keyData = keyType === KEY_TYPE.ED25519 ? await generateEd25519KeyData(privKey) : await generateSecp256k1KeyData(privKey);
  const { metadataNonce, oAuthKeyScalar: oAuthKey, encryptedSeed, metadataSigningKey } = keyData;
  const threshold = ~~(nodePubkeys.length / 2) + 1;
  const degree = threshold - 1;
  const nodeIndexesBigInt: bigint[] = nodeIndexes.map((i) => BigInt(i));

  const oAuthPub = ecCurve.Point.BASE.multiply(oAuthKey).toAffine();
  const poly = generateRandomPolynomial(ecCurve, keyType, degree, oAuthKey);
  const shares = poly.generateShares(nodeIndexesBigInt);
  const nonceParams = generateNonceMetadataParams(serverTimeOffset, "getOrSetNonce", metadataSigningKey, keyType, metadataNonce, encryptedSeed);
  const nonceData = bytesToBase64(utf8ToBytes(stringify(nonceParams.set_data)));
  const sharesData: ImportedShare[] = [];
  const encPromises: Promise<Ecies>[] = [];
  for (let i = 0; i < nodeIndexesBigInt.length; i++) {
    const shareJson = shares[bigintToHex(nodeIndexesBigInt[i])].toJSON() as Record<string, string>;
    if (!nodePubkeys[i]) {
      throw new Error(`Missing node pub key for node index: ${bigintToHex(nodeIndexesBigInt[i])}`);
    }
    const nodePubPoint = getSecp256k1().Point.fromAffine({
      x: toBigIntBE(nodePubkeys[i].X),
      y: toBigIntBE(nodePubkeys[i].Y),
    });
    encPromises.push(encrypt(nodePubPoint.toBytes(), hexToBytes(shareJson.share.padStart(64, "0"))));
  }
  const encShares = await Promise.all(encPromises);
  for (let i = 0; i < nodeIndexesBigInt.length; i += 1) {
    const shareJson = shares[bigintToHex(nodeIndexesBigInt[i])].toJSON() as Record<string, string>;
    const encParams = encShares[i];
    const encParamsMetadata = encParamsBufToHex(encParams);
    const shareData: ImportedShare = {
      encrypted_seed: keyData.encryptedSeed,
      final_user_point: keyData.finalUserPubKeyPoint,
      oauth_pub_key_x: bigintToHex(oAuthPub.x),
      oauth_pub_key_y: bigintToHex(oAuthPub.y),
      signing_pub_key_x: bigintToHex(keyData.SigningPubX),
      signing_pub_key_y: bigintToHex(keyData.SigningPubY),
      encrypted_share: encParamsMetadata.ciphertext,
      encrypted_share_metadata: encParamsMetadata,
      node_index: Number.parseInt(shareJson.shareIndex, 16),
      key_type: keyType,
      nonce_data: nonceData,
      nonce_signature: nonceParams.signature,
    };
    sharesData.push(shareData);
  }

  return sharesData;
};
