import type { AffinePoint as AffinePointCurve } from "@noble/curves/abstract/curve.js";
import type { INodePub, TORUS_NETWORK_TYPE } from "@toruslabs/constants";
import { Ecies } from "@toruslabs/eccrypto";

import { TorusUtilsExtraParams } from "./TorusUtilsExtraParams";

export type AffinePoint = AffinePointCurve<bigint>;

export interface KeyIndex {
  index: string;
  service_group_id: string;
  tag: "imported" | "generated"; // we tag keys so that we can identify if generated using dkg or externally imported by user
}

export type UserType = "v1" | "v2";
export type v2NonceResultType = {
  typeOfUser: "v2";
  nonce?: string;
  seed?: string;
  pubNonce: { x: string; y: string };
  ipfs?: string;
  upgraded: boolean;
};

export type v1NonceResultType = { typeOfUser: "v1"; nonce?: string; seed?: string };
export type GetOrSetNonceResult = v2NonceResultType | v1NonceResultType;
export type KeyType = "secp256k1" | "ed25519";

export interface SetNonceData {
  operation: string;
  data: string;
  seed?: string;
  timestamp: string;
}

export interface NonceMetadataParams {
  namespace?: string;
  pub_key_X: string;
  pub_key_Y: string;
  set_data: Partial<SetNonceData>;
  signature: string;
  key_type?: KeyType;
  seed?: string;
}

export interface TorusCtorOptions {
  clientId: string;
  network: TORUS_NETWORK_TYPE;
  keyType?: KeyType;
  enableOneKey?: boolean;
  serverTimeOffset?: number;
  legacyMetadataHost?: string;
  source?: string;
  authorizationServerUrl?: string;
}

export interface LegacyVerifierLookupResponse {
  keys: { pub_key_X: string; pub_key_Y: string; address: string }[];
  server_time_offset?: string;
}

export interface GetORSetKeyResponse {
  keys: {
    pub_key_X: string;
    pub_key_Y: string;
    address: string;
    nonce_data?: GetOrSetNonceResult;
    created_at?: number;
  }[];
  is_new_key: boolean;
  node_index: string;
  server_time_offset?: string;
}

export interface VerifierLookupResponse {
  keys: {
    pub_key_X: string;
    pub_key_Y: string;
    signing_pub_key_X?: string;
    signing_pub_key_Y?: string;
    address: string;
  }[];
  server_time_offset?: string;
}

export interface CommitmentRequestResult {
  signature: string;
  data: string;
  nodepubx: string;
  nodepuby: string;
  nodeindex: string;
  pub_key_x: string;
}
export interface JRPCResponse<T> {
  id: number;
  jsonrpc: "2.0";
  result?: T;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface KeyLookupResult {
  keyResult: Pick<GetORSetKeyResponse, "keys" | "is_new_key">;
  nodeIndexes: number[];
  serverTimeOffset: number;
  errorResult: JRPCResponse<GetORSetKeyResponse>["error"];
  nonceResult?: GetOrSetNonceResult;
}
export interface VerifierLookupResult {
  keyResult: Pick<VerifierLookupResponse, "keys">;
  serverTimeOffset: number;
  errorResult: JRPCResponse<VerifierLookupResponse>["error"];
}

export type EciesHex = {
  [key in keyof Ecies]: string;
} & { mode?: string };

export interface ExtendedPublicKey {
  X: string;
  Y: string;
  SignerX: string;
  SignerY: string;
}
export interface KeyAssignment {
  index: KeyIndex;
  public_key: ExtendedPublicKey;
  threshold: string;
  node_index: string;
  // this is encrypted ciphertext
  share: string;
  share_metadata: EciesHex;
  nonce_data?: GetOrSetNonceResult;
}

export interface ShareRequestResult {
  keys: KeyAssignment[];
  // these are encrypted ciphertexts
  session_tokens: string[];
  session_token_metadata: EciesHex[];
  // these are encrypted ciphertexts
  session_token_sigs: string[];
  session_token_sig_metadata: EciesHex[];
  node_pubx: string;
  node_puby: string;
  is_new_key: string;
  server_time_offset?: string;
}

export interface ImportedShare {
  oauth_pub_key_x: string;
  oauth_pub_key_y: string;
  final_user_point: AffinePoint;
  signing_pub_key_x: string;
  signing_pub_key_y: string;
  encrypted_share: string;
  encrypted_share_metadata: EciesHex;
  encrypted_seed?: string;
  node_index: number;
  key_type: string;
  nonce_data: string;
  nonce_signature: string;
}
export type ImportShareRequestResult = ShareRequestResult;

export interface SessionToken {
  token: string;
  signature: string;
  node_pubx: string;
  node_puby: string;
}
export interface TorusPublicKey {
  // based on curve type
  finalKeyData: {
    walletAddress: string; // format depends on key type
    X: string; // this is final pub x user before and after updating to 2/n
    Y: string; // this is final pub y user before and after updating to 2/n
  };
  // based on curve type
  oAuthKeyData: {
    walletAddress: string; // format depends on key type
    X: string;
    Y: string;
  };
  metadata: {
    pubNonce?: { X: string; Y: string };
    nonce?: bigint;
    typeOfUser: UserType;
    upgraded: boolean | null;
    serverTimeOffset: number;
  };
  nodesData: {
    nodeIndexes: number[];
  };
}

export interface TorusKey {
  finalKeyData: TorusPublicKey["finalKeyData"] & {
    privKey?: string;
  };
  oAuthKeyData: TorusPublicKey["oAuthKeyData"] & {
    privKey: string;
  };
  // always secp key
  postboxKeyData: {
    X: string;
    Y: string;
    privKey: string;
  };
  sessionData: {
    sessionTokenData: SessionToken[];
    sessionAuthKey: string;
  };
  metadata: TorusPublicKey["metadata"] & Required<Pick<TorusPublicKey["metadata"], "nonce">>;
  nodesData: TorusPublicKey["nodesData"];
}

export interface VerifierParams {
  [key: string]: unknown;
  verifier_id: string;
  extended_verifier_id?: string;
}

export type StringifiedType = Record<string, unknown>;

/** JSON shape returned by Share.toJSON() */
export type ShareJSON = { share: string; shareIndex: string };

export interface MetadataResponse {
  message: string;
}

export interface MetadataParams {
  namespace?: string;
  pub_key_X: string;
  pub_key_Y: string;
  key_type?: KeyType;
  set_data: {
    data: "getNonce" | "getOrSetNonce" | string;
    timestamp: string;
  };
  signature: string;
}

export interface PrivateKeyData {
  oAuthKeyScalar: bigint;
  oAuthPubX: bigint;
  oAuthPubY: bigint;
  SigningPubX: bigint;
  SigningPubY: bigint;
  metadataNonce: bigint;
  metadataSigningKey: bigint;
  finalUserPubKeyPoint: AffinePoint;
  encryptedSeed?: string;
}

export interface EncryptedSeed {
  enc_text: string;
  public_key?: string;
  metadata: EciesHex;
}
export interface SapphireMetadataParams {
  namespace?: string;
  pub_key_X: string;
  pub_key_Y: string;
  key_type: "secp256k1" | "ed25519";
  set_data: {
    operation: "getNonce" | "getOrSetNonce" | string;
    timestamp?: string;
  };
  signature?: string;
}

export interface ImportKeyParams {
  endpoints: string[];
  nodeIndexes: number[];
  nodePubkeys: INodePub[];
  verifier: string;
  verifierParams: VerifierParams;
  idToken: string;
  newPrivateKey: string;
  extraParams?: TorusUtilsExtraParams;
  checkCommitment?: boolean;
}

export interface RetrieveSharesParams {
  endpoints: string[];
  indexes: number[];
  verifier: string;
  verifierParams: VerifierParams;
  idToken: string;
  nodePubkeys: INodePub[];
  extraParams?: TorusUtilsExtraParams;
  useDkg?: boolean;
  checkCommitment?: boolean;
}
