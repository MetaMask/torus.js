import { faker } from "@faker-js/faker";
import { TORUS_LEGACY_NETWORK } from "@toruslabs/constants";
import { NodeDetailManager } from "@toruslabs/fetch-node-details";
import { beforeEach, describe, expect, it } from "vitest";

import { keccak256, TorusPublicKey, utf8ToBytes } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken, getRetrieveSharesParams } from "./helpers";

const TORUS_NODE_MANAGER = new NodeDetailManager({
  network: TORUS_LEGACY_NETWORK.TESTNET,
});
const TORUS_TEST_EMAIL = "hello@tor.us";
const TORUS_TEST_VERIFIER = "torus-test-health";
const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

describe("torus onekey", () => {
  let torus: TorusUtils;

  beforeEach(() => {
    torus = new TorusUtils({
      enableOneKey: true,
      network: TORUS_LEGACY_NETWORK.TESTNET,
      clientId: "YOUR_CLIENT_ID",
    });
  });

  it("should still fetch v1 public address correctly", async () => {
    const verifier = "google-lrc";
    const verifierDetails = { verifier, verifierId: "himanshu@tor.us" };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const publicAddress = (await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails)) as TorusPublicKey;
    expect(publicAddress.finalKeyData.walletAddress).toBe("0x930abEDDCa6F9807EaE77A3aCc5c78f20B168Fd1");
    expect(publicAddress.metadata.serverTimeOffset).toBeLessThan(20);

    delete publicAddress.metadata.serverTimeOffset;

    expect(publicAddress).toEqual({
      oAuthKeyData: {
        walletAddress: "0xf1e76fcDD28b5AA06De01de508fF21589aB9017E",
        X: "b3f2b4d8b746353fe670e0c39ac9adb58056d4d7b718d06b623612d4ec49268b",
        Y: "ac9f79dff78add39cdba380dbbf517c20cf2c1e06b32842a90a84a31f6eb9a9a",
      },
      finalKeyData: {
        walletAddress: "0x930abEDDCa6F9807EaE77A3aCc5c78f20B168Fd1",
        X: "12f6b90d66bda29807cf9ff14b2e537c25080154fc4fafed446306e8356ff425",
        Y: "e7c92e164b83e1b53e41e5d87d478bb07d7b19d105143e426e1ef08f7b37f224",
      },
      metadata: {
        pubNonce: undefined,
        nonce: BigInt("0x186a20d9b00315855ff5622a083aca6b2d34ef66ef6e0a4de670f5b2fde37e0d"),
        upgraded: false,
        typeOfUser: "v1",
      },
      nodesData: publicAddress.nodesData,
    });
  });

  it("should still login v1 account correctly", async () => {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const retrieveSharesResponse = await torus.retrieveShares(
      getRetrieveSharesParams(torusNodeEndpoints, torusIndexes, TORUS_TEST_VERIFIER, { verifier_id: TORUS_TEST_EMAIL }, token, torusNodePub)
    );
    expect(retrieveSharesResponse.metadata.serverTimeOffset).toBeLessThan(20);
    delete retrieveSharesResponse.metadata.serverTimeOffset;

    expect(retrieveSharesResponse.finalKeyData.privKey).toBe("296045a5599afefda7afbdd1bf236358baff580a0fe2db62ae5c1bbe817fbae4");
    expect(retrieveSharesResponse).toEqual({
      finalKeyData: {
        walletAddress: "0x53010055542cCc0f2b6715a5c53838eC4aC96EF7",
        X: "3fa78a0bfb9ec48810bf1ee332360def2600c4aef528ff8b1e49a0d304722c91",
        Y: "46aaca39fc00c0f88f63a79989697c70eeeeec6489300c493dd07a5608ded0d4",
        privKey: "296045a5599afefda7afbdd1bf236358baff580a0fe2db62ae5c1bbe817fbae4",
      },
      oAuthKeyData: {
        walletAddress: "0xEfd7eDAebD0D99D1B7C8424b54835457dD005Dc4",
        X: "18409385c38e9729eb6b7837dc8f234256233ffab1ed7eeb1c23b230333396b4",
        Y: "17d35ffc722d7a8dd88353815e9553cacf567c5f3b8d082adac9d653367ce47a",
        privKey: "068ee4f97468ef1ae95d18554458d372e31968190ae38e377be59d8b3c9f7a25",
      },
      postboxKeyData: {
        X: "18409385c38e9729eb6b7837dc8f234256233ffab1ed7eeb1c23b230333396b4",
        Y: "17d35ffc722d7a8dd88353815e9553cacf567c5f3b8d082adac9d653367ce47a",
        privKey: "068ee4f97468ef1ae95d18554458d372e31968190ae38e377be59d8b3c9f7a25",
      },
      sessionData: {
        sessionTokenData: retrieveSharesResponse.sessionData.sessionTokenData,
        sessionAuthKey: retrieveSharesResponse.sessionData.sessionAuthKey,
      },
      metadata: {
        pubNonce: {
          X: "8e8c399d8ba00ff88e6c42eb40c10661f822868ba2ad8fe12a8830e996b1e25d",
          Y: "554b12253694bf9eb98485441bba7ba220b78cb78ee21664e96f934d10b1494d",
        },
        nonce: BigInt("0x22d160abe5320fe2be52a57c7aca8fe5d7e5eff104ff4d2b32767e3344e040bf"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: retrieveSharesResponse.nodesData,
    });
  });

  it("should still aggregate account v1 user correctly", async () => {
    const idToken = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const hashedIdToken = keccak256(utf8ToBytes(idToken));
    const verifierDetails = { verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const retrieveSharesResponse = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        torusIndexes,
        TORUS_TEST_AGGREGATE_VERIFIER,
        {
          verify_params: [{ verifier_id: TORUS_TEST_EMAIL, idtoken: idToken }],
          sub_verifier_ids: [TORUS_TEST_VERIFIER],
          verifier_id: TORUS_TEST_EMAIL,
        },
        hashedIdToken.substring(2),
        torusNodePub
      )
    );
    expect(retrieveSharesResponse.metadata.serverTimeOffset).toBeLessThan(20);
    delete retrieveSharesResponse.metadata.serverTimeOffset;

    expect(retrieveSharesResponse.finalKeyData.walletAddress).toBe("0xE1155dB406dAD89DdeE9FB9EfC29C8EedC2A0C8B");
    expect(retrieveSharesResponse).toEqual({
      finalKeyData: {
        walletAddress: "0xE1155dB406dAD89DdeE9FB9EfC29C8EedC2A0C8B",
        X: "78658b2671f1bd6a488baf2afb8ce6f8d8b9a1a70842130b3c8756a9d51d9723",
        Y: "2e5840f47d645afa4bfe93c3715e65974051080d7a1e474eef8d68752924f4fb",
        privKey: "ad47959db4cb2e63e641bac285df1b944f54d1a1cecdaeea40042b60d53c35d2",
      },
      oAuthKeyData: {
        walletAddress: "0x5a165d2Ed4976BD104caDE1b2948a93B72FA91D2",
        X: "aba2b085ae6390b3eb26802c3239bb7e3b9ed8ea6e1dcc28aeb67432571f20fc",
        Y: "f1a2163cba5620b7b40241a6112e7918e9445b0b9cfbbb9d77b2de6f61ed5c27",
        privKey: "d9733fc1098151f3e3289673e7c69c4ed46cbbdbc13416560e14741524d2d51a",
      },
      postboxKeyData: {
        X: "aba2b085ae6390b3eb26802c3239bb7e3b9ed8ea6e1dcc28aeb67432571f20fc",
        Y: "f1a2163cba5620b7b40241a6112e7918e9445b0b9cfbbb9d77b2de6f61ed5c27",
        privKey: "d9733fc1098151f3e3289673e7c69c4ed46cbbdbc13416560e14741524d2d51a",
      },
      sessionData: {
        sessionTokenData: retrieveSharesResponse.sessionData.sessionTokenData,
        sessionAuthKey: retrieveSharesResponse.sessionData.sessionAuthKey,
      },
      metadata: {
        pubNonce: {
          X: "376c0ac5e15686633061cf5833dd040365f91377686d7ab5338c5202bd963a2f",
          Y: "794d7edb6a5ec0307dd40789274b377f37f293b0410a6cbd303db309536099b7",
        },
        nonce: BigInt("0xd3d455dcab49dc700319244e9e187f443596f2acbce238cff1c215d8809fa1f9"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: retrieveSharesResponse.nodesData,
    });
  });

  it("should be able to key assign", async () => {
    const verifier = TORUS_TEST_VERIFIER;
    const email = faker.internet.email();
    const verifierDetails = { verifier, verifierId: email };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const publicAddress = (await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails)) as TorusPublicKey;
    expect(publicAddress.metadata.typeOfUser).toBe("v2");
    expect(publicAddress.metadata.upgraded).toBe(false);
    expect(publicAddress.finalKeyData.walletAddress).not.toBe("");
    expect(publicAddress.finalKeyData.walletAddress).not.toBeNull();
    expect(publicAddress.oAuthKeyData.walletAddress).not.toBe("");
    expect(publicAddress.oAuthKeyData.walletAddress).not.toBeNull();
  });

  it("should be able to key assign via login", async () => {
    const email = faker.internet.email();
    const token = generateIdToken(email, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(torusNodeEndpoints, torusIndexes, TORUS_TEST_VERIFIER, { verifier_id: email }, token, torusNodePub)
    );
    expect(result.metadata.nonce !== 0n).toBe(true);
    expect(result.metadata.typeOfUser).toBe("v2");
    expect(result.metadata.upgraded).toBe(false);
    expect(result.finalKeyData.walletAddress).not.toBe("");
    expect(result.finalKeyData.walletAddress).not.toBeNull();
    expect(result.oAuthKeyData.walletAddress).not.toBe("");
    expect(result.oAuthKeyData.walletAddress).not.toBeNull();
  });

  it("should still login v2 account correctly", async () => {
    const token = generateIdToken("Jonathan.Nolan@hotmail.com", "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: "Jonathan.Nolan@hotmail.com" };
    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const retrieveSharesResponse = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: "Jonathan.Nolan@hotmail.com" },
        token,
        torusNodePub
      )
    );
    expect(retrieveSharesResponse.metadata.serverTimeOffset).toBeLessThan(20);
    delete retrieveSharesResponse.metadata.serverTimeOffset;

    expect(retrieveSharesResponse.finalKeyData.privKey).toBe("9ec5b0504e252e35218c7ce1e4660eac190a1505abfbec7102946f92ed750075");
    expect(retrieveSharesResponse.finalKeyData.walletAddress).toBe("0x2876820fd9536BD5dd874189A85d71eE8bDf64c2");
    expect(retrieveSharesResponse).toEqual({
      finalKeyData: {
        walletAddress: "0x2876820fd9536BD5dd874189A85d71eE8bDf64c2",
        X: "ad4c223520aac9bc3ec72399869601fd59f29363471131914e2ed2bc4ba46e54",
        Y: "802c6e40b22b49b5ef73fa49b194c2037267215fa01683aa86746907aab37ae1",
        privKey: "9ec5b0504e252e35218c7ce1e4660eac190a1505abfbec7102946f92ed750075",
      },
      oAuthKeyData: {
        walletAddress: "0x54de3Df0CA76AAe3e171FB410F0626Ab759f3c24",
        X: "49d69b8550bb0eba77595c73bf57f0463ff96adf6b50d44f9e1bcf2b3fb7976e",
        Y: "d63bac65bdfc7484a28d4362347bbd098095db190c14a4ce9dbaafe74803eccc",
        privKey: "f4b7e0fb1e6f6fbac539c55e22aff2900947de652d2d6254a9cd8709f505f83a",
      },
      postboxKeyData: {
        X: "49d69b8550bb0eba77595c73bf57f0463ff96adf6b50d44f9e1bcf2b3fb7976e",
        Y: "d63bac65bdfc7484a28d4362347bbd098095db190c14a4ce9dbaafe74803eccc",
        privKey: "f4b7e0fb1e6f6fbac539c55e22aff2900947de652d2d6254a9cd8709f505f83a",
      },
      sessionData: {
        sessionTokenData: retrieveSharesResponse.sessionData.sessionTokenData,
        sessionAuthKey: retrieveSharesResponse.sessionData.sessionAuthKey,
      },
      metadata: {
        pubNonce: {
          X: "f494a5bf06a2f0550aafb6aabeb495bd6ea3ef92eaa736819b5b0ad6bfbf1aab",
          Y: "35df3d3a14f88cbba0cfd092a1e5a0e4e725ba52a8d45719614555542d701f18",
        },
        nonce: BigInt("0xaa0dcf552fb5be7a5c52b783c1b61c1aca7113872e172a5818994715c8a5497c"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: retrieveSharesResponse.nodesData,
    });
  });
});
