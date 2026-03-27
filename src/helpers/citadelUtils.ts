import { BUILD_ENV_TYPE, CITADEL_SERVER_MAP, TORUS_NETWORK_TYPE } from "@toruslabs/constants";
import { get, put } from "@toruslabs/http-helpers";

import { RetrieveSharesParams } from "../interfaces";

export interface CitadelAllowParams {
  buildEnv: BUILD_ENV_TYPE;
  verifier: string;
  verifierId: string;
  network: string;
  clientId: string;
  recordId: string;
  source?: string;
}

export interface CitadelAuthFlowAuditParams {
  oauthInitiated?: boolean;
  oauthVerified?: boolean;
  oauthCompleted?: boolean;
  oauthVerificationFailed?: boolean;
  oauthFailed?: boolean;
}

export interface CitadelAuditParams extends CitadelAuthFlowAuditParams {
  recordId: string;
  authConnection: string;
  authConnectionId: string;
  groupedAuthConnectionId: string;
  oAuthUserId: string;
  web3AuthNetwork: string;
  web3AuthClientId: string;
}

export function buildAllowUrl(params: CitadelAllowParams): string {
  const url = new URL(`${CITADEL_SERVER_MAP[params.buildEnv]}/v1/signer/allow`);
  url.searchParams.set("recordid", params.recordId);
  url.searchParams.set("verifier", params.verifier);
  url.searchParams.set("verifierid", params.verifierId);
  url.searchParams.set("network", params.network);
  url.searchParams.set("clientid", params.clientId);
  if (params.source) {
    url.searchParams.set("source", params.source);
  }
  return url.toString();
}

export function buildAuditPayload(
  network: TORUS_NETWORK_TYPE,
  clientId: string,
  params: RetrieveSharesParams,
  authFlowAuditParams: CitadelAuthFlowAuditParams
): CitadelAuditParams {
  return {
    ...authFlowAuditParams,
    recordId: params.recordId,
    authConnection: params.authConnection || "",
    authConnectionId: params.verifierParams.sub_verifier_ids?.[0] || "",
    groupedAuthConnectionId: params.verifier || "",
    oAuthUserId: params.verifierParams.verifier_id || "",
    web3AuthNetwork: network,
    web3AuthClientId: clientId,
  };
}

export async function callAllowApi(params: CitadelAllowParams): Promise<void> {
  await get<void>(buildAllowUrl(params));
}

export async function callAuditApi(buildEnv: BUILD_ENV_TYPE, params: CitadelAuditParams): Promise<void> {
  const url = new URL(`${CITADEL_SERVER_MAP[buildEnv]}/v1/user/audit`);
  await put<void>(url.toString(), params);
}

export function generateRecordId(): string {
  const cr = typeof globalThis === "object" ? globalThis.crypto : null;
  if (typeof cr?.randomUUID !== "function") throw new Error("crypto.randomUUID must be defined");
  return cr.randomUUID();
}
