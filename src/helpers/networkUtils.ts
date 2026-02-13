import { LEGACY_NETWORKS_ROUTE_MAP, TORUS_LEGACY_NETWORK_TYPE, TORUS_NETWORK_TYPE } from "@toruslabs/constants";

/** Type guard: narrows network to legacy network type for LEGACY_NETWORKS_ROUTE_MAP / METADATA_MAP lookups. */
export function isLegacyNetwork(network: TORUS_NETWORK_TYPE): network is TORUS_LEGACY_NETWORK_TYPE {
  return Object.prototype.hasOwnProperty.call(LEGACY_NETWORKS_ROUTE_MAP, network);
}
