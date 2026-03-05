import { bytesToHex as nobleBytesToHex, concatBytes as nobleConcatBytes, hexToBytes as nobleHexToBytes } from "@noble/curves/utils.js";
import { JRPCResponse } from "@toruslabs/constants";
import { Ecies } from "@toruslabs/eccrypto";
import {
  base64ToBytes as mhBase64ToBytes,
  bigintToHex,
  bytesToBase64 as mhBytesToBase64,
  bytesToHex,
  bytesToNumberBE,
  bytesToNumberLE,
  calculateMedian,
  Curve,
  derivePubKey,
  generatePrivateKey,
  getEd25519,
  getKeyCurve,
  getSecp256k1,
  hexToBytes,
  invert,
  kCombinations,
  keccak256,
  keccak256Bytes,
  mod,
  numberToBytesBE,
  thresholdSame,
  toBigIntBE,
  utf8ToBytes,
} from "@toruslabs/metadata-helpers";

import { CommitmentRequestResult, EciesHex, GetORSetKeyResponse, VerifierLookupResponse } from "../interfaces";

// Re-export everything from metadata-helpers that consumers of common.ts expect
export {
  bigintToHex,
  bytesToHex,
  bytesToNumberBE,
  bytesToNumberLE,
  calculateMedian,
  derivePubKey,
  generatePrivateKey,
  getEd25519,
  getKeyCurve,
  getSecp256k1,
  hexToBytes,
  invert,
  kCombinations,
  keccak256,
  keccak256Bytes,
  mod,
  numberToBytesBE,
  thresholdSame,
  toBigIntBE,
  utf8ToBytes,
};
export type { Curve };

export const bytesToBase64 = mhBytesToBase64;
export const base64ToBytes = mhBase64ToBytes;
export const concatBytes = nobleConcatBytes;

// ---------------------------------------------------------------------------
// Torus-specific helpers (NOT migrated to metadata-helpers)
// ---------------------------------------------------------------------------

export const normalizeKeysResult = (result: GetORSetKeyResponse) => {
  const finalResult: Pick<GetORSetKeyResponse, "keys" | "is_new_key"> = {
    keys: [],
    is_new_key: result.is_new_key,
  };
  if (result && result.keys && result.keys.length > 0) {
    const finalKey = result.keys[0];
    finalResult.keys = [
      {
        pub_key_X: finalKey.pub_key_X,
        pub_key_Y: finalKey.pub_key_Y,
        address: finalKey.address,
      },
    ];
  }
  return finalResult;
};

export const normalizeLookUpResult = (result: VerifierLookupResponse) => {
  const finalResult: Pick<VerifierLookupResponse, "keys"> = {
    keys: [],
  };
  if (result && result.keys && result.keys.length > 0) {
    const finalKey = result.keys[0];
    finalResult.keys = [
      {
        pub_key_X: finalKey.pub_key_X,
        pub_key_Y: finalKey.pub_key_Y,
        address: finalKey.address,
      },
    ];
  }
  return finalResult;
};

/** ECIES params: bytes → hex. Uses noble bytesToHex so round-trip with encParamsHexToBuf (noble hexToBytes) is consistent. */
export function encParamsBufToHex(encParams: Ecies): EciesHex {
  return {
    iv: nobleBytesToHex(encParams.iv),
    ephemPublicKey: nobleBytesToHex(encParams.ephemPublicKey),
    ciphertext: nobleBytesToHex(encParams.ciphertext),
    mac: nobleBytesToHex(encParams.mac),
    mode: "AES256",
  };
}

/** ECIES params: hex → bytes. */
export function encParamsHexToBuf(eciesData: Omit<EciesHex, "ciphertext">): Omit<Ecies, "ciphertext"> {
  return {
    ephemPublicKey: nobleHexToBytes(eciesData.ephemPublicKey),
    iv: nobleHexToBytes(eciesData.iv),
    mac: nobleHexToBytes(eciesData.mac),
  };
}

export function getProxyCoordinatorEndpointIndex(endpoints: string[], verifier: string, verifierId: string) {
  const verifierIdStr = `${verifier}${verifierId}`;
  const hashedVerifierId = keccak256(utf8ToBytes(verifierIdStr), { prefixed: false });
  const proxyEndpointNum = Number(BigInt(`0x${hashedVerifierId}`) % BigInt(endpoints.length));
  return proxyEndpointNum;
}

export function waitFor(milliseconds: number) {
  return new Promise((resolve, reject) => {
    if (milliseconds > 0) {
      setTimeout(resolve, milliseconds);
    } else {
      reject(new Error("value of milliseconds must be greater than 0"));
    }
  });
}

export function retryCommitment(executionPromise: () => Promise<JRPCResponse<CommitmentRequestResult>>, maxRetries: number) {
  async function retryWithBackoff(retries: number) {
    try {
      if (retries > 0) {
        const timeToWait = 2 ** retries * 100;
        await waitFor(timeToWait);
      }
      const a = await executionPromise();
      return a;
    } catch (e: unknown) {
      const errorMsg = e instanceof Error ? e.message : String(e);
      const acceptedErrorMsgs = [
        "Timed out",
        "Failed to fetch",
        "fetch failed",
        "Load failed",
        "cancelled",
        "NetworkError when attempting to fetch resource.",
        "TypeError: Failed to fetch",
        "TypeError: cancelled",
        "TypeError: NetworkError when attempting to fetch resource.",
      ];

      if (retries < maxRetries && (acceptedErrorMsgs.includes(errorMsg) || (errorMsg && errorMsg.includes("reason: getaddrinfo EAI_AGAIN")))) {
        return retryWithBackoff(retries + 1);
      }
      throw e;
    }
  }

  return retryWithBackoff(0);
}
