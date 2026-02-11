import { mod } from "@noble/curves/abstract/modular.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { KEY_TYPE, TORUS_NETWORK_TYPE, TORUS_SAPPHIRE_NETWORK } from "@toruslabs/constants";
import { decrypt } from "@toruslabs/eccrypto";
import { Data, post } from "@toruslabs/http-helpers";
import { keccak256 as keccakHash } from "ethereum-cryptography/keccak";
import stringify from "json-stable-stringify";
import log from "loglevel";

import { SAPPHIRE_DEVNET_METADATA_URL, SAPPHIRE_METADATA_URL } from "../constants";
import {
  EciesHex,
  EncryptedSeed,
  GetOrSetNonceResult,
  KeyType,
  MetadataParams,
  NonceMetadataParams,
  Point2D,
  SapphireMetadataParams,
  SetNonceData,
} from "../interfaces";
import {
  base64ToBytes,
  bigintToHex,
  bytesToBase64,
  bytesToNumberBE,
  concatBytes,
  Curve,
  derivePubKey,
  encParamsHexToBuf,
  hexToBytes,
  keccak256Bytes,
  numberToBytesBE,
  toBigIntBE,
  utf8ToBytes,
} from "./common";
import { isLegacyNetwork } from "./networkUtils";

export const getSecpKeyFromEd25519 = (
  ed25519Scalar: bigint
): {
  scalar: bigint;
  point: Point2D;
} => {
  const N = secp256k1.Point.CURVE().n;

  const keyHash = keccakHash(numberToBytesBE(ed25519Scalar, 32));
  const secpScalar = mod(bytesToNumberBE(keyHash), N);
  const point = derivePubKey(secp256k1, secpScalar);

  return {
    scalar: secpScalar,
    point,
  };
};

export function convertMetadataToNonce(params: { message?: string }): bigint {
  if (!params || !params.message) {
    return 0n;
  }
  return toBigIntBE(params.message);
}

export async function decryptNodeData(eciesData: EciesHex, ciphertextHex: string, privKey: Uint8Array): Promise<Uint8Array> {
  const metadata = encParamsHexToBuf(eciesData);
  const decryptedSigBytes = await decrypt(privKey, {
    ...metadata,
    ciphertext: hexToBytes(ciphertextHex),
  });
  return decryptedSigBytes;
}

export async function decryptNodeDataWithPadding(eciesData: EciesHex, ciphertextHex: string, privKey: Uint8Array): Promise<Uint8Array> {
  const metadata = encParamsHexToBuf(eciesData);
  try {
    const decryptedSigBytes = await decrypt(privKey, {
      ...metadata,
      ciphertext: hexToBytes(ciphertextHex),
    });
    return decryptedSigBytes;
  } catch (error) {
    // ciphertext can be any length. not just 64. depends on input. we have this for legacy reason
    const ciphertextHexPadding = ciphertextHex.padStart(64, "0");

    log.warn("Failed to decrypt padded share cipher", error);
    // try without cipher text padding
    return decrypt(privKey, { ...metadata, ciphertext: hexToBytes(ciphertextHexPadding) });
  }
}

export function generateMetadataParams(ecCurve: Curve, serverTimeOffset: number, message: string, privateKey: bigint): MetadataParams {
  const setData = {
    data: message,
    timestamp: (~~(serverTimeOffset + Date.now() / 1000)).toString(16),
  };
  const msgHash = keccak256Bytes(utf8ToBytes(stringify(setData)));
  // metadata only uses secp for sig validation; prehash: false because msgHash is already hashed
  const sig = secp256k1.sign(msgHash, numberToBytesBE(privateKey, 32), { prehash: false });
  const pubKey = derivePubKey(ecCurve, privateKey);
  return {
    pub_key_X: pubKey.x.toString(16), // DO NOT PAD THIS. BACKEND DOESN'T
    pub_key_Y: pubKey.y.toString(16), // DO NOT PAD THIS. BACKEND DOESN'T
    set_data: setData,
    signature: bytesToBase64(concatBytes(sig, hexToBytes("00"))),
  };
}

export async function getMetadata(
  legacyMetadataHost: string,
  data: Omit<MetadataParams, "set_data" | "signature">,
  options: RequestInit = {}
): Promise<bigint> {
  try {
    const metadataResponse = await post<{ message?: string }>(`${legacyMetadataHost}/get`, data, options, { useAPIKey: true });
    if (!metadataResponse || !metadataResponse.message) {
      return 0n;
    }
    return toBigIntBE(metadataResponse.message); // nonce
  } catch (error) {
    log.error("get metadata error", error);
    return 0n;
  }
}

export function generateNonceMetadataParams(
  serverTimeOffset: number,
  operation: string,
  privateKey: bigint,
  keyType: KeyType,
  nonce?: bigint,
  seed?: string
): NonceMetadataParams {
  // metadata only uses secp for sig validation
  const setData: Partial<SetNonceData> = {
    operation,
    timestamp: (~~(serverTimeOffset + Date.now() / 1000)).toString(16),
  };

  if (nonce) {
    setData.data = bigintToHex(nonce);
  }

  if (seed) {
    setData.seed = seed;
  } else {
    setData.seed = ""; // setting it as empty to keep ordering same while serializing the data on backend.
  }

  const msgHash = keccak256Bytes(utf8ToBytes(stringify(setData)));
  const sig = secp256k1.sign(msgHash, numberToBytesBE(privateKey, 32), { prehash: false });
  const pubKey = derivePubKey(secp256k1, privateKey);
  return {
    pub_key_X: bigintToHex(pubKey.x),
    pub_key_Y: bigintToHex(pubKey.y),
    set_data: setData,
    key_type: keyType,
    signature: bytesToBase64(concatBytes(sig, hexToBytes("00"))),
  };
}

export async function getOrSetNonce(
  metadataHost: string,
  ecCurve: Curve,
  serverTimeOffset: number,
  X: string,
  Y: string,
  privKey?: bigint,
  getOnly = false,
  isLegacyMetadata = true,
  nonce = 0n,
  keyType: KeyType = "secp256k1",
  seed = ""
): Promise<GetOrSetNonceResult> {
  // for legacy metadata
  if (isLegacyMetadata) {
    let data: Data;
    const msg = getOnly ? "getNonce" : "getOrSetNonce";
    if (privKey) {
      data = generateMetadataParams(ecCurve, serverTimeOffset, msg, privKey);
    } else {
      data = {
        pub_key_X: X,
        pub_key_Y: Y,
        set_data: { data: msg },
      };
    }
    return post<GetOrSetNonceResult>(`${metadataHost}/get_or_set_nonce`, data, undefined, { useAPIKey: true });
  }

  // for sapphire metadata
  const operation = getOnly ? "getNonce" : "getOrSetNonce";
  if (operation === "getOrSetNonce") {
    if (!privKey) {
      throw new Error("privKey is required while `getOrSetNonce` for non legacy metadata");
    }
    if (nonce === 0n) {
      throw new Error("nonce is required while `getOrSetNonce` for non legacy metadata");
    }
    if (keyType === KEY_TYPE.ED25519 && !seed) {
      throw new Error("seed is required while `getOrSetNonce` for non legacy metadata for ed25519 key type");
    }
    const data = generateNonceMetadataParams(serverTimeOffset, operation, privKey, keyType, nonce, seed);

    return post<GetOrSetNonceResult>(`${metadataHost}/get_or_set_nonce`, data, undefined, { useAPIKey: true });
  }
  const data = {
    pub_key_X: X,
    pub_key_Y: Y,
    set_data: { operation },
    key_type: keyType,
  };
  return post<GetOrSetNonceResult>(`${metadataHost}/get_or_set_nonce`, data, undefined, { useAPIKey: true });
}
export async function getNonce(
  legacyMetadataHost: string,
  ecCurve: Curve,
  serverTimeOffset: number,
  X: string,
  Y: string,
  privKey?: bigint
): Promise<GetOrSetNonceResult> {
  return getOrSetNonce(legacyMetadataHost, ecCurve, serverTimeOffset, X, Y, privKey, true);
}

export const decryptSeedData = async (seedBase64: string, finalUserKey: bigint) => {
  const decryptionKey = getSecpKeyFromEd25519(finalUserKey);
  const seedUtf8 = new TextDecoder().decode(base64ToBytes(seedBase64));
  const seedJson = JSON.parse(seedUtf8) as EncryptedSeed;
  const eciesMetadata = { ...encParamsHexToBuf(seedJson.metadata), mode: "AES256" };
  const keyBytes = numberToBytesBE(decryptionKey.scalar, 32);
  const decText = await decrypt(keyBytes, {
    ...eciesMetadata,
    ciphertext: hexToBytes(seedJson.enc_text),
  });

  return decText;
};

export async function getOrSetSapphireMetadataNonce(
  network: TORUS_NETWORK_TYPE,
  X: string,
  Y: string,
  serverTimeOffset?: number,
  privKey?: bigint
): Promise<GetOrSetNonceResult> {
  if (isLegacyNetwork(network)) {
    throw new Error("getOrSetSapphireMetadataNonce should only be used for sapphire networks");
  }
  let data: SapphireMetadataParams = {
    pub_key_X: X,
    pub_key_Y: Y,
    key_type: "secp256k1",
    set_data: { operation: "getOrSetNonce" },
  };
  if (privKey) {
    const setData = {
      operation: "getOrSetNonce",
      timestamp: (~~(serverTimeOffset + Date.now() / 1000)).toString(16),
    };
    const msgHash = keccak256Bytes(utf8ToBytes(stringify(setData)));
    const sig = secp256k1.sign(msgHash, numberToBytesBE(privKey, 32), { prehash: false });
    const pubKey = derivePubKey(secp256k1, privKey);
    data = {
      ...data,
      pub_key_X: bigintToHex(pubKey.x),
      pub_key_Y: bigintToHex(pubKey.y),
      set_data: setData,
      signature: bytesToBase64(concatBytes(sig, hexToBytes("00"))),
    };
  }

  const metadataUrl = network === TORUS_SAPPHIRE_NETWORK.SAPPHIRE_DEVNET ? SAPPHIRE_DEVNET_METADATA_URL : SAPPHIRE_METADATA_URL;

  return post<GetOrSetNonceResult>(`${metadataUrl}/get_or_set_nonce`, data, undefined, { useAPIKey: true });
}
