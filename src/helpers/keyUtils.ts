import { mod } from "@noble/curves/abstract/modular.js";
import { hexToBytes } from "@noble/curves/utils.js";
import { INodePub, KEY_TYPE } from "@toruslabs/constants";
import { Ecies, encrypt } from "@toruslabs/eccrypto";
import {
  bigIntToHexPaddedString,
  bytesToBase64,
  bytesToHex,
  bytesToNumberBE,
  Curve,
  derivePubKey,
  encodeEd25519Point,
  generateAddressFromPrivKey,
  generateAddressFromPubKey,
  generatePrivateKey,
  generateRandomPolynomial,
  getEd25519ExtendedPublicKey,
  getKeyCurve,
  getPostboxKeyFrom1OutOf1,
  getSecp256k1,
  getSecp256k1PublicKeyFromAffinePoint,
  getSecpKeyFromEd25519,
  keccak256HexString,
  KeyType,
  toBigIntBE,
  utf8ToBytes,
} from "@toruslabs/metadata-helpers";
import stringify from "json-stable-stringify";

import { EncryptedSeed, GetOrSetNonceResult, ImportedShare, PrivateKeyData, ShareJSON, v2NonceResultType } from "../interfaces";
import { encParamsBufToHex } from "./common";
import { generateNonceMetadataParams } from "./metadataUtils";

// Re-export migrated helpers so existing consumers of keyUtils don't break
export {
  encodeEd25519Point,
  generateAddressFromPrivKey,
  generateAddressFromPubKey,
  getEd25519ExtendedPublicKey,
  getPostboxKeyFrom1OutOf1,
  getSecp256k1PublicKeyFromAffinePoint,
};

export function isV2NonceResult(r: GetOrSetNonceResult): r is v2NonceResultType {
  if (!r) return false;
  return (r as v2NonceResultType).pubNonce !== undefined || r.typeOfUser === "v2";
}

export function stripHexPrefix(str: string): string {
  return str.startsWith("0x") ? str.slice(2) : str;
}

export function toChecksumAddress(hexAddress: string): string {
  const address = stripHexPrefix(hexAddress).toLowerCase();
  const hash = keccak256HexString(utf8ToBytes(address), { prefixed: false });
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
  const oauthPub = derivePubKey(ed25519Curve, oauthKey);
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

export const generateSecp256k1KeyData = async (scalarBytes: Uint8Array): Promise<PrivateKeyData> => {
  const secp256k1Curve = getKeyCurve(KEY_TYPE.SECP256K1);
  const N = secp256k1Curve.Point.CURVE().n;

  const scalar = bytesToNumberBE(scalarBytes);
  const randomNonce = bytesToNumberBE(generatePrivateKey(KEY_TYPE.SECP256K1));
  const oAuthKey = mod(scalar - randomNonce, N);
  const oAuthPub = derivePubKey(secp256k1Curve, oAuthKey);

  const finalUserPub = derivePubKey(secp256k1Curve, scalar);

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

  const oAuthPub = derivePubKey(ecCurve, oAuthKey);
  const poly = generateRandomPolynomial(ecCurve, keyType, degree, oAuthKey);
  const shares = poly.generateShares(nodeIndexesBigInt);
  const nonceParams = generateNonceMetadataParams(serverTimeOffset, "getOrSetNonce", metadataSigningKey, keyType, metadataNonce, encryptedSeed);
  const nonceData = bytesToBase64(utf8ToBytes(stringify(nonceParams.set_data)));
  const sharesData: ImportedShare[] = [];
  const encPromises: Promise<Ecies>[] = [];
  for (let i = 0; i < nodeIndexesBigInt.length; i++) {
    const shareJson: ShareJSON = shares[bigIntToHexPaddedString(nodeIndexesBigInt[i])].toJSON();
    if (!nodePubkeys[i]) {
      throw new Error(`Missing node pub key for node index: ${bigIntToHexPaddedString(nodeIndexesBigInt[i])}`);
    }
    const nodePubPoint = getSecp256k1().Point.fromAffine({
      x: toBigIntBE(nodePubkeys[i].X),
      y: toBigIntBE(nodePubkeys[i].Y),
    });
    encPromises.push(encrypt(nodePubPoint.toBytes(), hexToBytes(shareJson.share.padStart(64, "0"))));
  }
  const encShares = await Promise.all(encPromises);
  for (let i = 0; i < nodeIndexesBigInt.length; i += 1) {
    const shareJson: ShareJSON = shares[bigIntToHexPaddedString(nodeIndexesBigInt[i])].toJSON();
    const encParams = encShares[i];
    const encParamsMetadata = encParamsBufToHex(encParams);
    const shareData: ImportedShare = {
      encrypted_seed: keyData.encryptedSeed,
      final_user_point: keyData.finalUserPubKeyPoint,
      oauth_pub_key_x: bigIntToHexPaddedString(oAuthPub.x),
      oauth_pub_key_y: bigIntToHexPaddedString(oAuthPub.y),
      signing_pub_key_x: bigIntToHexPaddedString(keyData.SigningPubX),
      signing_pub_key_y: bigIntToHexPaddedString(keyData.SigningPubY),
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
