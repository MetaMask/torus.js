import { BUILD_ENV_TYPE, CITADEL_SERVER_MAP } from "@toruslabs/constants";
import { get } from "@toruslabs/http-helpers";

import { TorusLoginStatus } from "../interfaces";

export interface CitadelAllowParams {
  buildEnv: BUILD_ENV_TYPE;
  verifier: string;
  verifierId: string;
  network: string;
  clientId: string;
  recordId: string;
  source?: string;
  torusLoginStatus?: TorusLoginStatus;
  torusLoginInitiated?: boolean;
  torusLoginSuccess?: boolean;
  torusLoginFailed?: boolean;
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
  if (params.torusLoginStatus) {
    url.searchParams.set("torusloginstatus", params.torusLoginStatus);
  }
  if (typeof params.torusLoginInitiated !== "undefined") {
    url.searchParams.set("toruslogininitiated", params.torusLoginInitiated.toString());
  }
  if (typeof params.torusLoginSuccess !== "undefined") {
    url.searchParams.set("torusloginsuccess", params.torusLoginSuccess.toString());
  }
  if (typeof params.torusLoginFailed !== "undefined") {
    url.searchParams.set("torusloginfailed", params.torusLoginFailed.toString());
  }
  return url.toString();
}

export async function callAllowApi(params: CitadelAllowParams): Promise<void> {
  await get<void>(buildAllowUrl(params));
}

export function generateRecordId(): string {
  const cr = typeof globalThis === "object" ? globalThis.crypto : null;
  if (typeof cr?.randomUUID !== "function") throw new Error("crypto.randomUUID must be defined");
  return cr.randomUUID();
}
