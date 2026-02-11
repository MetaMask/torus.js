import { INodePub, KEY_TYPE, LEGACY_NETWORKS_ROUTE_MAP, SIGNER_MAP, TORUS_LEGACY_NETWORK_TYPE, TORUS_NETWORK_TYPE } from "@toruslabs/constants";
import { generatePrivate, getPublic } from "@toruslabs/eccrypto";
import { generateJsonRPCObject, get, post } from "@toruslabs/http-helpers";

import { config } from "../config";
import { JRPC_METHODS } from "../constants";
import {
  CommitmentRequestResult,
  ExtendedPublicKey,
  GetORSetKeyResponse,
  GetOrSetNonceResult,
  ImportedShare,
  ImportShareRequestResult,
  JRPCResponse,
  KeyLookupResult,
  KeyType,
  Point2D,
  SessionToken,
  ShareRequestResult,
  TorusKey,
  UserType,
  VerifierLookupResponse,
  VerifierLookupResult,
  VerifierParams,
} from "../interfaces";
import log from "../loglevel";
import { Some } from "../some";
import { TorusUtilsExtraParams } from "../TorusUtilsExtraParams";
import {
  base64ToBytes,
  bigintToHex,
  bytesToBase64,
  bytesToHex,
  bytesToNumberBE,
  calculateMedian,
  Curve,
  derivePubKey,
  generatePrivateKey,
  getProxyCoordinatorEndpointIndex,
  hexToBytes,
  kCombinations,
  keccak256,
  mod,
  normalizeKeysResult,
  normalizeLookUpResult,
  retryCommitment,
  thresholdSame,
  toBigIntBE,
  utf8ToBytes,
} from "./common";
import { generateAddressFromPrivKey, generateAddressFromPubKey, generateShares, isV2NonceResult } from "./keyUtils";
import { lagrangeInterpolation } from "./langrangeInterpolatePoly";
import {
  decryptNodeData,
  decryptNodeDataWithPadding,
  decryptSeedData,
  getMetadata,
  getOrSetNonce,
  getOrSetSapphireMetadataNonce,
  getSecpKeyFromEd25519,
} from "./metadataUtils";

export const GetPubKeyOrKeyAssign = async (params: {
  endpoints: string[];
  network: TORUS_NETWORK_TYPE;
  verifier: string;
  verifierId: string;
  keyType: KeyType;
  extendedVerifierId?: string;
}): Promise<KeyLookupResult> => {
  const { endpoints, network, verifier, verifierId, extendedVerifierId, keyType } = params;
  const minThreshold = ~~(endpoints.length / 2) + 1;
  const lookupPromises = endpoints.map((x) =>
    post<JRPCResponse<GetORSetKeyResponse>>(
      x,
      generateJsonRPCObject(JRPC_METHODS.GET_OR_SET_KEY, {
        distributed_metadata: true,
        verifier,
        verifier_id: verifierId.toString(),
        extended_verifier_id: extendedVerifierId,
        one_key_flow: true,
        key_type: keyType,
        fetch_node_index: true,
        client_time: Math.floor(Date.now() / 1000).toString(),
      }),
      {},
      { logTracingHeader: config.logRequestTracing }
    ).catch((err) => log.error(`${JRPC_METHODS.GET_OR_SET_KEY} request failed`, err))
  );

  let nonceResult: GetOrSetNonceResult | undefined;
  const nodeIndexes: number[] = [];
  const result = await Some<void | JRPCResponse<GetORSetKeyResponse>, KeyLookupResult>(lookupPromises, async (lookupResults) => {
    const lookupPubKeys = lookupResults.filter((x1) => {
      if (x1 && !x1.error) {
        return x1;
      }
      return false;
    });

    const errorResult = thresholdSame(
      lookupResults.map((x2) => x2 && x2.error),
      minThreshold
    );

    const keyResult = thresholdSame(
      lookupPubKeys.map((x3) => x3 && normalizeKeysResult(x3.result)),
      minThreshold
    );

    // check for nonce result in response if not a extendedVerifierId and not a legacy network
    if (keyResult && !nonceResult && !extendedVerifierId && !LEGACY_NETWORKS_ROUTE_MAP[network as TORUS_LEGACY_NETWORK_TYPE]) {
      for (let i = 0; i < lookupResults.length; i++) {
        const x1 = lookupResults[i];
        if (x1 && !x1.error) {
          const currentNodePubKey = x1.result.keys[0].pub_key_X.toLowerCase();
          const thresholdPubKey = keyResult.keys[0].pub_key_X.toLowerCase();
          const nonceData = x1.result?.keys[0].nonce_data;
          const pubNonceX = nonceData && isV2NonceResult(nonceData) ? nonceData.pubNonce?.x : undefined;
          if (pubNonceX && currentNodePubKey === thresholdPubKey) {
            nonceResult = x1.result.keys[0].nonce_data;
            break;
          }
        }
      }

      // if nonce result is not returned by nodes, fetch directly from metadata
      if (!nonceResult) {
        const metadataNonceResult = await getOrSetSapphireMetadataNonce(network, keyResult.keys[0].pub_key_X, keyResult.keys[0].pub_key_Y);
        // rechecking nonceResult to avoid promise race condition.
        if (!nonceResult && metadataNonceResult) {
          nonceResult = metadataNonceResult;
          if (nonceResult.nonce) {
            delete nonceResult.nonce;
          }
        }
      }
    }

    const serverTimeOffsets: number[] = [];
    // nonceResult must exist except for extendedVerifierId and legacy networks along with keyResult
    if ((keyResult && (nonceResult || extendedVerifierId || LEGACY_NETWORKS_ROUTE_MAP[network as TORUS_LEGACY_NETWORK_TYPE])) || errorResult) {
      if (keyResult) {
        lookupResults.forEach((x1) => {
          if (x1 && x1.result) {
            const currentNodePubKey = x1.result.keys[0].pub_key_X.toLowerCase();
            const thresholdPubKey = keyResult.keys[0].pub_key_X.toLowerCase();
            // push only those indexes for nodes who are returning pub key matching with threshold pub key.
            // this check is important when different nodes have different keys assigned to a user.
            if (currentNodePubKey === thresholdPubKey) {
              const nodeIndex = Number.parseInt(x1.result.node_index);
              if (nodeIndex) nodeIndexes.push(nodeIndex);
            }
            const serverTimeOffset = x1.result.server_time_offset ? Number.parseInt(x1.result.server_time_offset, 10) : 0;
            serverTimeOffsets.push(serverTimeOffset);
          }
        });
      }

      const serverTimeOffset = keyResult ? calculateMedian(serverTimeOffsets) : 0;
      return Promise.resolve({ keyResult, serverTimeOffset, nodeIndexes, errorResult, nonceResult });
    }
    return Promise.reject(
      new Error(
        `invalid public key result: ${JSON.stringify(lookupResults)} and nonce result:${JSON.stringify(
          nonceResult || {}
        )} for verifier: ${verifier}, verifierId: ${verifierId} and extendedVerifierId: ${extendedVerifierId} `
      )
    );
  });

  return result;
};

export const VerifierLookupRequest = async (params: {
  endpoints: string[];
  verifier: string;
  verifierId: string;
  keyType: KeyType;
}): Promise<VerifierLookupResult> => {
  const { endpoints, verifier, verifierId, keyType } = params;
  const minThreshold = ~~(endpoints.length / 2) + 1;
  const lookupPromises = endpoints.map((x) =>
    post<JRPCResponse<VerifierLookupResponse>>(
      x,
      generateJsonRPCObject(JRPC_METHODS.VERIFIER_LOOKUP, {
        verifier,
        verifier_id: verifierId.toString(),
        key_type: keyType,
        client_time: Math.floor(Date.now() / 1000).toString(),
      }),
      {},
      { logTracingHeader: config.logRequestTracing }
    ).catch((err) => log.error(`${JRPC_METHODS.GET_OR_SET_KEY} request failed`, err))
  );

  const result = await Some<void | JRPCResponse<VerifierLookupResponse>, VerifierLookupResult>(lookupPromises, async (lookupResults) => {
    const lookupPubKeys = lookupResults.filter((x1) => {
      if (x1 && !x1.error) {
        return x1;
      }
      return false;
    });

    const errorResult = thresholdSame(
      lookupResults.map((x2) => x2 && x2.error),
      minThreshold
    );

    const keyResult = thresholdSame(
      lookupPubKeys.map((x3) => x3 && normalizeLookUpResult(x3.result)),
      minThreshold
    );

    const serverTimeOffsets: number[] = [];
    if (keyResult || errorResult) {
      const serverTimeOffset = keyResult ? calculateMedian(serverTimeOffsets) : 0;
      return Promise.resolve({ keyResult, serverTimeOffset, errorResult });
    }
    return Promise.reject(
      new Error(
        `invalid lookup result: ${JSON.stringify(lookupResults)}
        )} for verifier: ${verifier}, verifierId: ${verifierId}`
      )
    );
  });

  return result;
};

const commitmentRequest = async (params: {
  idToken: string;
  endpoints: string[];
  indexes: number[];
  keyType: KeyType;
  verifier: string;
  verifierParams: VerifierParams;
  pubKeyX: string;
  pubKeyY: string;
  finalImportedShares: ImportedShare[];
  overrideExistingKey: boolean;
}): Promise<(void | JRPCResponse<CommitmentRequestResult>)[]> => {
  const { idToken, endpoints, indexes, keyType, verifier, verifierParams, pubKeyX, pubKeyY, finalImportedShares, overrideExistingKey } = params;
  const tokenCommitment = keccak256(utf8ToBytes(idToken));
  const threeFourthsThreshold = ~~((endpoints.length * 3) / 4) + 1;
  const halfThreshold = ~~(endpoints.length / 2) + 1;

  const promiseArr: Promise<JRPCResponse<CommitmentRequestResult>>[] = [];
  // make commitment requests to endpoints
  for (let i = 0; i < endpoints.length; i += 1) {
    /*
      CommitmentRequestParams struct {
        MessagePrefix      string `json:"messageprefix"`
        TokenCommitment    string `json:"tokencommitment"`
        TempPubX           string `json:"temppubx"`
        TempPubY           string `json:"temppuby"`
        VerifierIdentifier string `json:"verifieridentifier"`
      } 
      */
    const p = () =>
      post<JRPCResponse<CommitmentRequestResult>>(
        endpoints[i],
        generateJsonRPCObject(JRPC_METHODS.COMMITMENT_REQUEST, {
          messageprefix: "mug00",
          keytype: keyType,
          tokencommitment: tokenCommitment.slice(2),
          temppubx: pubKeyX,
          temppuby: pubKeyY,
          verifieridentifier: verifier,
          verifier_id: verifierParams.verifier_id,
          extended_verifier_id: verifierParams.extended_verifier_id,
          is_import_key_flow: true,
        }),
        {},
        { logTracingHeader: config.logRequestTracing }
      );
    const r = retryCommitment(p, 4);
    promiseArr.push(r);
  }
  return new Promise<(void | JRPCResponse<CommitmentRequestResult>)[]>((resolve, reject) => {
    // send share request once k + t number of commitment requests have completed
    Some<void | JRPCResponse<CommitmentRequestResult>, (void | JRPCResponse<CommitmentRequestResult>)[]>(promiseArr, (resultArr) => {
      const completedRequests = resultArr.filter((x): x is JRPCResponse<CommitmentRequestResult> => {
        if (!x || typeof x !== "object") {
          return false;
        }
        if (x.error) {
          return false;
        }
        return true;
      });

      if (finalImportedShares.length > 0) {
        // this is a optimization is for imported keys
        // for new imported keys registration we need to wait for all nodes to agree on commitment
        // for fetching existing imported keys we can rely on threshold nodes commitment
        if (overrideExistingKey && completedRequests.length === endpoints.length) {
          const requiredNodeResult = completedRequests.find((resp) => !!resp);
          if (requiredNodeResult) {
            return Promise.resolve(resultArr);
          }
        } else if (!overrideExistingKey && completedRequests.length >= threeFourthsThreshold) {
          const nodeSigs: CommitmentRequestResult[] = [];
          for (let i = 0; i < completedRequests.length; i += 1) {
            const x = completedRequests[i];
            if (!x || typeof x !== "object" || x.error) {
              continue;
            }
            nodeSigs.push(x.result);
          }
          const existingPubKey = thresholdSame(
            nodeSigs.map((x) => x && x.pub_key_x),
            halfThreshold
          );
          const proxyEndpointNum = getProxyCoordinatorEndpointIndex(endpoints, verifier, verifierParams.verifier_id);
          // for import shares, proxy node response is required.
          // proxy node returns metadata.
          // if user's account already
          const requiredNodeIndex = indexes[proxyEndpointNum].toString(10);

          // if not a existing key we need to wait for nodes to agree on commitment
          if (existingPubKey || (!existingPubKey && completedRequests.length === endpoints.length)) {
            const requiredNodeResult = completedRequests.find((resp) => resp.result?.nodeindex === requiredNodeIndex);
            if (requiredNodeResult) {
              return Promise.resolve(resultArr);
            }
          }
        }
      } else if (completedRequests.length >= threeFourthsThreshold) {
        // this case is for dkg keys
        const requiredNodeResult = completedRequests.find((resp) => !!resp);
        if (requiredNodeResult) {
          return Promise.resolve(resultArr);
        }
      }

      return Promise.reject(new Error(`invalid commitment results ${JSON.stringify(resultArr)}`));
    })
      .then((resultArr: (void | JRPCResponse<CommitmentRequestResult>)[]) => {
        return resolve(resultArr);
      })
      .catch(reject);
  });
};
export async function retrieveOrImportShare(params: {
  legacyMetadataHost: string;
  serverTimeOffset: number;
  enableOneKey: boolean;
  ecCurve: Curve;
  keyType: KeyType;
  network: TORUS_NETWORK_TYPE;
  clientId: string;
  endpoints: string[];
  indexes: number[];
  verifier: string;
  verifierParams: VerifierParams;
  idToken: string;
  useDkg: boolean;
  overrideExistingKey: boolean;
  nodePubkeys: INodePub[];
  extraParams: TorusUtilsExtraParams;
  newImportedShares?: ImportedShare[];
  checkCommitment?: boolean;
  source?: string;
  authorizationServerUrl?: string;
}): Promise<TorusKey> {
  const {
    legacyMetadataHost,
    enableOneKey,
    ecCurve,
    keyType,
    network,
    clientId,
    endpoints,
    nodePubkeys,
    indexes,
    verifier,
    verifierParams,
    idToken,
    overrideExistingKey,
    newImportedShares,
    extraParams,
    useDkg = true,
    serverTimeOffset,
    checkCommitment = true,
    source,
    authorizationServerUrl,
  } = params;
  if (authorizationServerUrl) {
    await post<void>(
      authorizationServerUrl,
      {
        verifier,
        verifier_id: verifierParams.verifier_id,
        network,
        client_id: clientId,
        enable_gating: "true",
        ...(source ? { source } : {}),
      },
      {},
      { useAPIKey: true }
    );
  } else {
    await get<void>(
      `${SIGNER_MAP[network]}/api/allow`,
      {
        headers: {
          verifier,
          verifierid: verifierParams.verifier_id,
          network,
          clientid: clientId,
          enablegating: "true",
        },
      },
      { useAPIKey: true }
    );
  }

  // generate temporary private and public key that is used to secure receive shares
  const sessionAuthKey = generatePrivate();
  const pubKey = bytesToHex(getPublic(sessionAuthKey));
  const sessionPubX = pubKey.slice(2, 66);
  const sessionPubY = pubKey.slice(66);
  let finalImportedShares: ImportedShare[] = [];
  const halfThreshold = ~~(endpoints.length / 2) + 1;

  if (newImportedShares?.length > 0) {
    if (newImportedShares.length !== endpoints.length) {
      throw new Error("Invalid imported shares length");
    }
    finalImportedShares = newImportedShares;
  } else if (!useDkg) {
    const privateKey = keyType === KEY_TYPE.SECP256K1 ? generatePrivateKey(KEY_TYPE.SECP256K1) : generatePrivateKey(KEY_TYPE.ED25519);
    const generatedShares = await generateShares(ecCurve, keyType, serverTimeOffset, indexes, nodePubkeys, privateKey);
    finalImportedShares = [...finalImportedShares, ...generatedShares];
  }

  let commitmentRequestResult: (void | JRPCResponse<CommitmentRequestResult>)[] = [];
  let isExistingKey: boolean;
  const nodeSigs: CommitmentRequestResult[] = [];
  if (checkCommitment) {
    commitmentRequestResult = await commitmentRequest({
      idToken,
      endpoints,
      indexes,
      keyType,
      verifier,
      verifierParams,
      pubKeyX: sessionPubX,
      pubKeyY: sessionPubY,
      finalImportedShares,
      overrideExistingKey,
    });
    const validCommitments = commitmentRequestResult.filter(
      (x): x is JRPCResponse<CommitmentRequestResult> => !!x && typeof x === "object" && !x.error
    );
    for (const x of validCommitments) {
      nodeSigs.push(x.result);
    }
    // if user's account already
    isExistingKey = !!thresholdSame(
      nodeSigs.map((x) => x && x.pub_key_x),
      halfThreshold
    );
  } else if (!checkCommitment && finalImportedShares.length > 0) {
    // in case not allowed to override existing key for import request
    // check if key exists
    if (!overrideExistingKey) {
      const keyLookupResult = await VerifierLookupRequest({ endpoints, verifier, verifierId: verifierParams.verifier_id, keyType });
      if (
        keyLookupResult.errorResult &&
        !(keyLookupResult.errorResult?.data as string)?.includes("Verifier + VerifierID has not yet been assigned")
      ) {
        throw new Error(
          `node results do not match at first lookup ${JSON.stringify(keyLookupResult.keyResult || {})}, ${JSON.stringify(keyLookupResult.errorResult || {})}`
        );
      }
      if (keyLookupResult.keyResult?.keys?.length > 0) {
        isExistingKey = !!keyLookupResult.keyResult.keys[0];
      }
    }
  }
  const promiseArrRequest = [];

  const canImportedShares = overrideExistingKey || (!useDkg && !isExistingKey);
  if (canImportedShares) {
    const proxyEndpointNum = getProxyCoordinatorEndpointIndex(endpoints, verifier, verifierParams.verifier_id);
    const items: Record<string, unknown>[] = [];
    for (let i = 0; i < endpoints.length; i += 1) {
      const importedShare = finalImportedShares[i];
      if (!importedShare) {
        throw new Error(`invalid imported share at index ${i}`);
      }
      items.push({
        ...verifierParams,
        idtoken: idToken,
        nodesignatures: nodeSigs,
        verifieridentifier: verifier,
        pub_key_x: importedShare.oauth_pub_key_x,
        pub_key_y: importedShare.oauth_pub_key_y,
        signing_pub_key_x: importedShare.signing_pub_key_x,
        signing_pub_key_y: importedShare.signing_pub_key_y,
        encrypted_share: importedShare.encrypted_share,
        encrypted_share_metadata: importedShare.encrypted_share_metadata,
        node_index: importedShare.node_index,
        key_type: importedShare.key_type,
        nonce_data: importedShare.nonce_data,
        nonce_signature: importedShare.nonce_signature,
        sss_endpoint: endpoints[i],
        ...extraParams,
      });
    }
    const p = post<JRPCResponse<ImportShareRequestResult[]>>(
      endpoints[proxyEndpointNum],
      generateJsonRPCObject(JRPC_METHODS.IMPORT_SHARES, {
        encrypted: "yes",
        use_temp: true,
        verifieridentifier: verifier,
        temppubx: nodeSigs.length === 0 && !checkCommitment ? sessionPubX : "", // send session pub key x only if node signatures are not available (Ie. in non commitment flow)
        temppuby: nodeSigs.length === 0 && !checkCommitment ? sessionPubY : "", // send session pub key y only if node signatures are not available (Ie. in non commitment flow)
        item: items,
        key_type: keyType,
        one_key_flow: true,
      }),
      {},
      { logTracingHeader: config.logRequestTracing }
    ).catch((err) => log.error("share req", err));
    promiseArrRequest.push(p);
  } else {
    for (let i = 0; i < endpoints.length; i += 1) {
      const p = post<JRPCResponse<ShareRequestResult>>(
        endpoints[i],
        generateJsonRPCObject(JRPC_METHODS.GET_SHARE_OR_KEY_ASSIGN, {
          encrypted: "yes",
          use_temp: true,
          key_type: keyType,
          distributed_metadata: true,
          verifieridentifier: verifier,
          temppubx: nodeSigs.length === 0 && !checkCommitment ? sessionPubX : "", // send session pub key x only if node signatures are not available (Ie. in non commitment flow)
          temppuby: nodeSigs.length === 0 && !checkCommitment ? sessionPubY : "", // send session pub key y only if node signatures are not available (Ie. in non commitment flow)
          item: [
            {
              ...verifierParams,
              idtoken: idToken,
              key_type: keyType,
              nodesignatures: nodeSigs,
              verifieridentifier: verifier,
              ...extraParams,
            },
          ],
          client_time: Math.floor(Date.now() / 1000).toString(),
          one_key_flow: true,
        }),
        {},
        { logTracingHeader: config.logRequestTracing }
      );
      promiseArrRequest.push(p);
    }
  }
  return Some<
    void | JRPCResponse<ShareRequestResult> | JRPCResponse<ShareRequestResult[]>,
    | {
        privateKey: bigint;
        sessionTokenData: SessionToken[];
        thresholdNonceData: GetOrSetNonceResult;
        thresholdPubKey: ExtendedPublicKey;
        nodeIndexes: bigint[];
        isNewKey: boolean;
        serverTimeOffsetResponse?: number;
      }
    | undefined
  >(promiseArrRequest, async (shareResponseResult, sharedState) => {
    let thresholdNonceData: GetOrSetNonceResult;
    let shareResponses: (void | JRPCResponse<ShareRequestResult>)[] = [];
    // for import shares case, where result is an array
    if (shareResponseResult.length === 1 && shareResponseResult[0] && Array.isArray(shareResponseResult[0].result)) {
      // this is for import shares
      const importedSharesResult = shareResponseResult[0];
      shareResponseResult[0].result.forEach((res) => {
        shareResponses.push({
          id: importedSharesResult.id,
          jsonrpc: "2.0",
          result: res,
          error: importedSharesResult.error,
        });
      });
    } else {
      shareResponses = shareResponseResult as (void | JRPCResponse<ShareRequestResult>)[];
    }
    // check if threshold number of nodes have returned the same user public key
    const completedRequests = shareResponses.filter((x): x is JRPCResponse<ShareRequestResult> => {
      if (!x || typeof x !== "object") {
        return false;
      }
      if (x.error) {
        return false;
      }
      return true;
    });
    const pubkeys = shareResponses.map((x) => {
      if (x && x.result && x.result.keys[0].public_key) {
        return x.result.keys[0].public_key;
      }
      return undefined;
    });

    const thresholdPublicKey = thresholdSame(pubkeys, halfThreshold);

    if (!thresholdPublicKey) {
      throw new Error("invalid result from nodes, threshold number of public key results are not matching");
    }

    shareResponses.forEach((x) => {
      const requiredShareResponse = x && x.result && x.result.keys[0].public_key && x.result.keys[0];
      if (requiredShareResponse && !thresholdNonceData && !verifierParams.extended_verifier_id) {
        const currentPubKey = requiredShareResponse.public_key;
        const nonceData = requiredShareResponse.nonce_data;
        const pubNonce = nonceData && isV2NonceResult(nonceData) ? nonceData.pubNonce?.x : undefined;
        if (pubNonce && currentPubKey.X === thresholdPublicKey.X) {
          thresholdNonceData = requiredShareResponse.nonce_data;
        }
      }
    });

    const thresholdReqCount = canImportedShares ? endpoints.length : halfThreshold;
    // optimistically run lagrange interpolation once threshold number of shares have been received
    // this is matched against the user public key to ensure that shares are consistent
    // Note: no need of thresholdMetadataNonce for extended_verifier_id key
    if (completedRequests.length >= thresholdReqCount && thresholdPublicKey) {
      const sharePromises: Promise<void | Uint8Array>[] = [];
      const sessionTokenSigPromises: Promise<void | Uint8Array>[] = [];
      const sessionTokenPromises: Promise<void | Uint8Array>[] = [];
      const nodeIndexes: bigint[] = [];
      const sessionTokenData: SessionToken[] = [];
      const isNewKeyResponses: {
        isNewKey: string;
        publicKey: string;
      }[] = [];
      const serverTimeOffsetResponses: string[] = [];

      for (let i = 0; i < completedRequests.length; i += 1) {
        const currentShareResponse = completedRequests[i];
        const {
          session_tokens: sessionTokens,
          session_token_metadata: sessionTokenMetadata,
          session_token_sigs: sessionTokenSigs,
          session_token_sig_metadata: sessionTokenSigMetadata,
          keys,
          is_new_key: isNewKey,
          server_time_offset: serverTimeOffsetResponse,
        } = currentShareResponse.result;

        isNewKeyResponses.push({
          isNewKey,
          publicKey: currentShareResponse.result?.keys[0]?.public_key?.X || "",
        });
        serverTimeOffsetResponses.push(serverTimeOffsetResponse || "0");

        if (sessionTokenSigs?.length > 0) {
          // decrypt sessionSig if enc metadata is sent
          if (sessionTokenSigMetadata && sessionTokenSigMetadata[0]?.ephemPublicKey) {
            sessionTokenSigPromises.push(
              decryptNodeData(sessionTokenSigMetadata[0], sessionTokenSigs[0], sessionAuthKey).catch((err) =>
                log.error("session sig decryption", err)
              )
            );
          } else {
            sessionTokenSigPromises.push(Promise.resolve(hexToBytes(sessionTokenSigs[0])));
          }
        } else {
          sessionTokenSigPromises.push(Promise.resolve(undefined));
        }

        if (sessionTokens?.length > 0) {
          // decrypt session token if enc metadata is sent
          if (sessionTokenMetadata && sessionTokenMetadata[0]?.ephemPublicKey) {
            sessionTokenPromises.push(
              decryptNodeData(sessionTokenMetadata[0], sessionTokens[0], sessionAuthKey).catch((err) =>
                log.error("session token sig decryption", err)
              )
            );
          } else {
            sessionTokenPromises.push(Promise.resolve(base64ToBytes(sessionTokens[0])));
          }
        } else {
          sessionTokenPromises.push(Promise.resolve(undefined));
        }

        if (keys?.length > 0) {
          const latestKey = currentShareResponse.result.keys[0];
          nodeIndexes.push(BigInt(latestKey.node_index));
          if (latestKey.share_metadata) {
            sharePromises.push(
              decryptNodeDataWithPadding(latestKey.share_metadata, new TextDecoder().decode(base64ToBytes(latestKey.share)), sessionAuthKey).catch(
                (err) => log.error("share decryption", err)
              )
            );
          }
        } else {
          nodeIndexes.push(undefined);
          sharePromises.push(Promise.resolve(undefined));
        }
      }
      const allPromises = await Promise.all(sharePromises.concat(sessionTokenSigPromises).concat(sessionTokenPromises));
      const sharesResolved = allPromises.slice(0, sharePromises.length);
      const sessionSigsResolved = allPromises.slice(sharePromises.length, sharePromises.length + sessionTokenSigPromises.length);
      const sessionTokensResolved = allPromises.slice(sharePromises.length + sessionTokenSigPromises.length, allPromises.length);
      const validSigs = sessionSigsResolved.filter((sig) => {
        if (sig) {
          return true;
        }
        return false;
      });

      if (!verifierParams.extended_verifier_id && validSigs.length < halfThreshold) {
        throw new Error(`Insufficient number of signatures from nodes, required: ${halfThreshold}, found: ${validSigs.length}`);
      }

      const validTokens = sessionTokensResolved.filter((token) => {
        if (token) {
          return true;
        }
        return false;
      });

      if (!verifierParams.extended_verifier_id && validTokens.length < halfThreshold) {
        throw new Error(`Insufficient number of session tokens from nodes, required: ${halfThreshold}, found: ${validTokens.length}`);
      }
      sessionTokensResolved.forEach((x, index) => {
        const sig = sessionSigsResolved[index];
        if (!x || !sig) sessionTokenData.push(undefined);
        else
          sessionTokenData.push({
            token: bytesToBase64(x),
            signature: bytesToHex(sig),
            node_pubx: completedRequests[index].result.node_pubx,
            node_puby: completedRequests[index].result.node_puby,
          });
      });

      if (sharedState.resolved) return undefined;

      const decryptedShares = sharesResolved.reduce(
        (acc, curr, index) => {
          if (curr) {
            acc.push({ index: nodeIndexes[index], value: bytesToNumberBE(curr) });
          }
          return acc;
        },
        [] as { index: bigint; value: bigint }[]
      );
      // run lagrange interpolation on all subsets, faster in the optimistic scenario than berlekamp-welch due to early exit
      const allCombis = kCombinations(decryptedShares.length, halfThreshold);

      let privateKey: bigint | null = null;
      for (let j = 0; j < allCombis.length; j += 1) {
        const currentCombi = allCombis[j];
        const currentCombiShares = decryptedShares.filter((_, index) => currentCombi.includes(index));
        const shares = currentCombiShares.map((x) => x.value);
        const indices = currentCombiShares.map((x) => x.index);
        const derivedPrivateKey = lagrangeInterpolation(ecCurve, shares, indices);
        if (!derivedPrivateKey) continue;
        const decryptedPubKey = derivePubKey(ecCurve, derivedPrivateKey);
        const decryptedPubKeyX = decryptedPubKey.x;
        const decryptedPubKeyY = decryptedPubKey.y;

        if (decryptedPubKeyX === toBigIntBE(thresholdPublicKey.X) && decryptedPubKeyY === toBigIntBE(thresholdPublicKey.Y)) {
          privateKey = derivedPrivateKey;
          break;
        }
      }

      if (privateKey === undefined || privateKey === null) {
        throw new Error("could not derive private key");
      }

      let isNewKey = false;
      isNewKeyResponses.forEach((x) => {
        if (x.isNewKey === "true" && x.publicKey.toLowerCase() === thresholdPublicKey.X.toLowerCase()) {
          isNewKey = true;
        }
      });

      // Convert each string timestamp to a number
      const serverOffsetTimes = serverTimeOffsetResponses.map((timestamp) => Number.parseInt(timestamp, 10));

      return {
        privateKey,
        sessionTokenData,
        thresholdNonceData,
        nodeIndexes,
        thresholdPubKey: thresholdPublicKey,
        isNewKey,
        serverTimeOffsetResponse: serverTimeOffset || calculateMedian(serverOffsetTimes),
      };
    }
    if (completedRequests.length < thresholdReqCount) {
      throw new Error(`Waiting for results from more nodes, pending: ${thresholdReqCount - completedRequests.length}`);
    }
    throw new Error(
      `Invalid results, threshold pub key: ${thresholdPublicKey}, nonce data found: ${!!thresholdNonceData}, extended verifierId: ${verifierParams.extended_verifier_id}`
    );
  }).then(async (res) => {
    const { privateKey, thresholdPubKey, sessionTokenData, nodeIndexes, thresholdNonceData, isNewKey, serverTimeOffsetResponse } = res;
    let nonceResult = thresholdNonceData;
    if (!privateKey) throw new Error("Invalid private key returned");

    const oAuthKey = privateKey;
    const oAuthPubKey = derivePubKey(ecCurve, oAuthKey);
    const oAuthPubkeyX = bigintToHex(oAuthPubKey.x);
    const oAuthPubkeyY = bigintToHex(oAuthPubKey.y);

    // if both thresholdNonceData and extended_verifier_id are not available
    // then we need to throw other wise address would be incorrect.
    if (!nonceResult && !verifierParams.extended_verifier_id && !LEGACY_NETWORKS_ROUTE_MAP[network as TORUS_LEGACY_NETWORK_TYPE]) {
      // NOTE: dont use padded pub key anywhere in metadata apis, send pub keys as is received from nodes.
      const metadataNonceResult = await getOrSetSapphireMetadataNonce(network, thresholdPubKey.X, thresholdPubKey.Y, serverTimeOffset, oAuthKey);
      // rechecking nonceResult to avoid promise race condition.
      if (metadataNonceResult && !thresholdNonceData) {
        nonceResult = metadataNonceResult;
      } else {
        throw new Error(
          `invalid metadata result from nodes, nonce metadata is empty for verifier: ${verifier} and verifierId: ${verifierParams.verifier_id}`
        );
      }
    }
    let metadataNonce = nonceResult?.nonce ? toBigIntBE(nonceResult.nonce) : 0n;
    let finalPubKey: Point2D;
    let pubNonce: { X: string; Y: string } | undefined;
    let typeOfUser: UserType = "v1";
    const N = ecCurve.Point.CURVE().n;
    // extended_verifier_id is only exception for torus-test-health verifier
    // otherwise extended verifier id should not even return shares.
    if (verifierParams.extended_verifier_id) {
      typeOfUser = "v2";
      // for tss key no need to add pub nonce
      finalPubKey = oAuthPubKey;
    } else if (LEGACY_NETWORKS_ROUTE_MAP[network as TORUS_LEGACY_NETWORK_TYPE]) {
      if (enableOneKey) {
        nonceResult = await getOrSetNonce(legacyMetadataHost, ecCurve, serverTimeOffsetResponse, oAuthPubkeyX, oAuthPubkeyY, oAuthKey, !isNewKey);
        metadataNonce = nonceResult.nonce ? toBigIntBE(nonceResult.nonce) : 0n;
        typeOfUser = nonceResult.typeOfUser;
        if (typeOfUser === "v2" && isV2NonceResult(nonceResult)) {
          pubNonce = { X: nonceResult.pubNonce.x, Y: nonceResult.pubNonce.y };
          const noncePubKey = {
            x: toBigIntBE(nonceResult.pubNonce.x),
            y: toBigIntBE(nonceResult.pubNonce.y),
          };
          finalPubKey = ecCurve.Point.fromAffine(oAuthPubKey).add(ecCurve.Point.fromAffine(noncePubKey)).toAffine();
        } else {
          typeOfUser = "v1";
          // for imported keys in legacy networks
          metadataNonce = await getMetadata(legacyMetadataHost, { pub_key_X: oAuthPubkeyX, pub_key_Y: oAuthPubkeyY });
          const privateKeyWithNonce = mod(oAuthKey + metadataNonce, N);
          finalPubKey = derivePubKey(ecCurve, privateKeyWithNonce);
        }
      } else {
        typeOfUser = "v1";
        // for imported keys in legacy networks
        metadataNonce = await getMetadata(legacyMetadataHost, { pub_key_X: oAuthPubkeyX, pub_key_Y: oAuthPubkeyY });
        const privateKeyWithNonce = mod(oAuthKey + metadataNonce, N);
        finalPubKey = derivePubKey(ecCurve, privateKeyWithNonce);
      }
    } else if (isV2NonceResult(nonceResult)) {
      typeOfUser = "v2";
      const noncePubKey = {
        x: toBigIntBE(nonceResult.pubNonce.x),
        y: toBigIntBE(nonceResult.pubNonce.y),
      };
      finalPubKey = ecCurve.Point.fromAffine(oAuthPubKey).add(ecCurve.Point.fromAffine(noncePubKey)).toAffine();
      pubNonce = { X: nonceResult.pubNonce.x, Y: nonceResult.pubNonce.y };
    }

    if (!finalPubKey) {
      throw new Error("Invalid public key, this might be a bug, please report this to web3auth team");
    }

    let finalPrivKey = ""; // it is empty for v2 user upgraded to 2/n
    let isUpgraded: boolean | null = false;
    const oAuthKeyAddress = generateAddressFromPrivKey(keyType, oAuthKey);
    // deriving address from pub key coz pubkey is always available
    // but finalPrivKey won't be available for  v2 user upgraded to 2/n
    const finalWalletAddress = generateAddressFromPubKey(keyType, finalPubKey.x, finalPubKey.y);
    let keyWithNonce = "";
    if (typeOfUser === "v1") {
      isUpgraded = null;
    } else if (typeOfUser === "v2") {
      isUpgraded = metadataNonce === 0n;
    }

    if (typeOfUser === "v1" || (typeOfUser === "v2" && metadataNonce > 0n)) {
      const privateKeyWithNonce = mod(oAuthKey + metadataNonce, N);
      keyWithNonce = bigintToHex(privateKeyWithNonce);
    }
    if (keyType === KEY_TYPE.SECP256K1) {
      finalPrivKey = keyWithNonce;
    } else if (keyType === KEY_TYPE.ED25519) {
      if (keyWithNonce && !nonceResult.seed) {
        throw new Error("Invalid data, seed data is missing for ed25519 key, Please report this bug");
      } else if (keyWithNonce && nonceResult.seed) {
        // console.log("nonceResult.seed", nonceResult.seed, keyWithNonce);
        const decryptedSeed = await decryptSeedData(nonceResult.seed, toBigIntBE(keyWithNonce));
        finalPrivKey = bytesToHex(decryptedSeed);
      }
    } else {
      throw new Error(`Invalid keyType: ${keyType}`);
    }

    let postboxKey = oAuthKey;
    let postboxPubX = oAuthPubkeyX;
    let postboxPubY = oAuthPubkeyY;
    if (keyType === KEY_TYPE.ED25519) {
      const { scalar, point } = getSecpKeyFromEd25519(privateKey);
      postboxKey = scalar;
      postboxPubX = bigintToHex(point.x);
      postboxPubY = bigintToHex(point.y);
      if (thresholdPubKey.SignerX.padStart(64, "0") !== postboxPubX || thresholdPubKey.SignerY.padStart(64, "0") !== postboxPubY) {
        throw new Error("Invalid postbox key");
      }
    }
    // return reconstructed private key and ethereum address
    return {
      finalKeyData: {
        walletAddress: finalWalletAddress,
        X: bigintToHex(finalPubKey.x), // this is final pub x user before and after updating to 2/n
        Y: bigintToHex(finalPubKey.y), // this is final pub y user before and after updating to 2/n
        privKey: finalPrivKey,
      },
      oAuthKeyData: {
        walletAddress: oAuthKeyAddress,
        X: oAuthPubkeyX,
        Y: oAuthPubkeyY,
        privKey: bigintToHex(oAuthKey),
      },
      postboxKeyData: {
        privKey: bigintToHex(postboxKey),
        X: postboxPubX,
        Y: postboxPubY,
      },
      sessionData: {
        sessionTokenData,
        sessionAuthKey: bytesToHex(sessionAuthKey),
      },
      metadata: {
        pubNonce,
        nonce: metadataNonce,
        typeOfUser,
        upgraded: isUpgraded,
        serverTimeOffset: serverTimeOffsetResponse,
      },
      nodesData: {
        nodeIndexes: nodeIndexes.map((x) => Number(x)),
      },
    } as TorusKey;
  });
}
