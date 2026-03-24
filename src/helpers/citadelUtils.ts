import { BUILD_ENV_TYPE, CITADEL_SERVER_MAP } from "@toruslabs/constants";
import { get } from "@toruslabs/http-helpers";

import { LoginStatus } from "../interfaces";

export interface CitadelAllowParams {
  buildEnv: BUILD_ENV_TYPE;
  verifier: string;
  verifierId: string;
  network: string;
  clientId: string;
  source?: string;
  loginStatus?: LoginStatus;
}

export function buildAllowUrl(params: CitadelAllowParams): string {
  const url = new URL(`${CITADEL_SERVER_MAP[params.buildEnv]}/v1/signer/allow`);
  url.searchParams.set("verifier", params.verifier);
  url.searchParams.set("verifierid", params.verifierId);
  url.searchParams.set("network", params.network);
  url.searchParams.set("clientid", params.clientId);
  if (params.source) {
    url.searchParams.set("source", params.source);
  }
  if (params.loginStatus) {
    url.searchParams.set("loginstatus", params.loginStatus);
  }
  return url.toString();
}

export async function callAllowApi(params: CitadelAllowParams): Promise<void> {
  try {
    await get<void>(buildAllowUrl(params));
  } catch {
    return;
  }
}
