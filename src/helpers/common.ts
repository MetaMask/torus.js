import { invert, mod } from "@noble/curves/abstract/modular.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, bytesToNumberBE, concatBytes, hexToBytes, hexToNumber, numberToBytesBE, numberToHexUnpadded } from "@noble/curves/utils.js";
import { JRPCResponse, KEY_TYPE } from "@toruslabs/constants";
import { Ecies } from "@toruslabs/eccrypto";
import { keccak256 as keccakHash } from "ethereum-cryptography/keccak";
import JsonStringify from "json-stable-stringify";

import { CommitmentRequestResult, EciesHex, GetORSetKeyResponse, KeyType, VerifierLookupResponse } from "../interfaces";

export type Curve = typeof secp256k1 | typeof ed25519;

// Re-export noble utilities for use across the codebase
export { bytesToHex, bytesToNumberBE, concatBytes, hexToBytes, invert, mod, numberToBytesBE };

// Convert a hex string or bigint to bigint. Wraps noble's hexToNumber with empty-string safety.
export function toBigIntBE(val: string | bigint): bigint {
  if (typeof val === "bigint") return val;
  const cleaned = val.replace(/^0x/, "");
  if (!cleaned) return 0n;
  return hexToNumber(cleaned);
}

// Format a bigint as a zero-padded hex string. Wraps noble's numberToHexUnpadded with padding.
export function bigintToHex(val: bigint, padLength = 64): string {
  return numberToHexUnpadded(val).padStart(padLength, "0");
}

// Custom encoding helpers (not provided by @noble/curves)
export function utf8ToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

export function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function keccak256(a: Uint8Array): string {
  const hash = bytesToHex(keccakHash(a));
  return `0x${hash}`;
}

export const generatePrivateKey = (keyType: KeyType): Uint8Array => {
  if (keyType === KEY_TYPE.SECP256K1) {
    return secp256k1.utils.randomSecretKey();
  } else if (keyType === KEY_TYPE.ED25519) {
    return ed25519.utils.randomSecretKey();
  }
  throw new Error(`Invalid keyType: ${keyType}`);
};

export const getSecp256k1 = () => secp256k1;
export const getEd25519 = () => ed25519;

export const getKeyCurve = (keyType: KeyType): Curve => {
  if (keyType === KEY_TYPE.SECP256K1) {
    return secp256k1;
  } else if (keyType === KEY_TYPE.ED25519) {
    return ed25519;
  }
  throw new Error(`Invalid keyType: ${keyType}`);
};
// this function normalizes the result from nodes before passing the result to threshold check function
// For ex: some fields returns by nodes might be different from each other
// like created_at field might vary and nonce_data might not be returned by all nodes because
// of the metadata implementation in sapphire.
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

export const kCombinations = (s: number | number[], k: number): number[][] => {
  let set = s;
  if (typeof set === "number") {
    set = Array.from({ length: set }, (_, i) => i);
  }
  if (k > set.length || k <= 0) {
    return [];
  }

  if (k === set.length) {
    return [set];
  }

  if (k === 1) {
    return set.reduce((acc, cur) => [...acc, [cur]], [] as number[][]);
  }

  const combs: number[][] = [];
  let tailCombs: number[][] = [];

  for (let i = 0; i <= set.length - k + 1; i += 1) {
    tailCombs = kCombinations(set.slice(i + 1), k - 1);
    for (let j = 0; j < tailCombs.length; j += 1) {
      combs.push([set[i], ...tailCombs[j]]);
    }
  }

  return combs;
};

export const thresholdSame = <T>(arr: T[], t: number): T | undefined => {
  const hashMap: Record<string, number> = {};
  for (let i = 0; i < arr.length; i += 1) {
    const str = JsonStringify(arr[i]);
    hashMap[str] = hashMap[str] ? hashMap[str] + 1 : 1;
    if (hashMap[str] === t) {
      return arr[i];
    }
  }
  return undefined;
};

export function encParamsBufToHex(encParams: Ecies): EciesHex {
  return {
    iv: bytesToHex(encParams.iv),
    ephemPublicKey: bytesToHex(encParams.ephemPublicKey),
    ciphertext: bytesToHex(encParams.ciphertext),
    mac: bytesToHex(encParams.mac),
    mode: "AES256",
  };
}

export function encParamsHexToBuf(eciesData: Omit<EciesHex, "ciphertext">): Omit<Ecies, "ciphertext"> {
  return {
    ephemPublicKey: hexToBytes(eciesData.ephemPublicKey),
    iv: hexToBytes(eciesData.iv),
    mac: hexToBytes(eciesData.mac),
  };
}

export function getProxyCoordinatorEndpointIndex(endpoints: string[], verifier: string, verifierId: string) {
  const verifierIdStr = `${verifier}${verifierId}`;
  const hashedVerifierId = keccak256(utf8ToBytes(verifierIdStr)).slice(2);
  const proxyEndpointNum = Number(BigInt(`0x${hashedVerifierId}`) % BigInt(endpoints.length));
  return proxyEndpointNum;
}

export function calculateMedian(arr: number[]): number {
  const arrSize = arr.length;

  if (arrSize === 0) return 0;
  const sortedArr = arr.sort(function (a, b) {
    return a - b;
  });

  // odd length
  if (arrSize % 2 !== 0) {
    return sortedArr[Math.floor(arrSize / 2)];
  }

  // return average of two mid values in case of even arrSize
  const mid1 = sortedArr[arrSize / 2 - 1];

  const mid2 = sortedArr[arrSize / 2];
  return (mid1 + mid2) / 2;
}

export function waitFor(milliseconds: number) {
  return new Promise((resolve, reject) => {
    // hack to bypass eslint warning.
    if (milliseconds > 0) {
      setTimeout(resolve, milliseconds);
    } else {
      reject(new Error("value of milliseconds must be greater than 0"));
    }
  });
}

export function retryCommitment(executionPromise: () => Promise<JRPCResponse<CommitmentRequestResult>>, maxRetries: number) {
  // Notice that we declare an inner function here
  // so we can encapsulate the retries and don't expose
  // it to the caller. This is also a recursive function
  async function retryWithBackoff(retries: number) {
    try {
      // we don't wait on the first attempt
      if (retries > 0) {
        // on every retry, we exponentially increase the time to wait.
        // Here is how it looks for a `maxRetries` = 4
        // (2 ** 1) * 100 = 200 ms
        // (2 ** 2) * 100 = 400 ms
        // (2 ** 3) * 100 = 800 ms
        const timeToWait = 2 ** retries * 100;
        await waitFor(timeToWait);
      }
      const a = await executionPromise();
      return a;
    } catch (e: unknown) {
      const errorMsg = (e as Error).message;
      const acceptedErrorMsgs = [
        // Slow node
        "Timed out",
        "Failed to fetch",
        "fetch failed",
        "Load failed",
        "cancelled",
        "NetworkError when attempting to fetch resource.",
        // Happens when the node is not reachable (dns issue etc)
        "TypeError: Failed to fetch", // All except iOS and Firefox
        "TypeError: cancelled", // iOS
        "TypeError: NetworkError when attempting to fetch resource.", // Firefox
      ];

      if (retries < maxRetries && (acceptedErrorMsgs.includes(errorMsg) || (errorMsg && errorMsg.includes("reason: getaddrinfo EAI_AGAIN")))) {
        // only retry if we didn't reach the limit
        // otherwise, let the caller handle the error
        return retryWithBackoff(retries + 1);
      }
      throw e;
    }
  }

  return retryWithBackoff(0);
}
