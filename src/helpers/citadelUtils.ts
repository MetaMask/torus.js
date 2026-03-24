import { BUILD_ENV_TYPE, CITADEL_SERVER_MAP } from "@toruslabs/constants";
import { get } from "@toruslabs/http-helpers";

import { TorusLoginStatus } from "../interfaces";

export interface CitadelAllowParams {
  buildEnv: BUILD_ENV_TYPE;
  verifier: string;
  verifierId: string;
  network: string;
  clientId: string;
  source?: string;
  torusLoginStatus?: TorusLoginStatus;
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
  if (params.torusLoginStatus) {
    url.searchParams.set("torusloginstatus", params.torusLoginStatus);
  }
  return url.toString();
}

export async function callAllowApi(params: CitadelAllowParams): Promise<void> {
  await get<void>(buildAllowUrl(params));
}
