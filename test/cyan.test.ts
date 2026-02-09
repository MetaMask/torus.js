import { faker } from "@faker-js/faker";
import { TORUS_LEGACY_NETWORK } from "@toruslabs/constants";
import { NodeDetailManager } from "@toruslabs/fetch-node-details";
import { beforeEach, describe, expect, it } from "vitest";

import { keccak256, utf8ToBytes } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken, getRetrieveSharesParams } from "./helpers";

const TORUS_TEST_EMAIL = "hello@tor.us";
const TORUS_TEST_VERIFIER = "torus-test-health";
const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

describe("torus utils cyan", () => {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeDetailManager;

  beforeEach(() => {
    torus = new TorusUtils({
      network: "cyan",
      clientId: "YOUR_CLIENT_ID",
    });
    TORUS_NODE_MANAGER = new NodeDetailManager({ network: TORUS_LEGACY_NETWORK.CYAN });
  });

  it("should fetch public address", async () => {
    const verifier = "tkey-google-cyan";
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).toBe("0xA3767911A84bE6907f26C572bc89426dDdDB2825");
    expect(result.metadata.serverTimeOffset).toBeLessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).toEqual({
      oAuthKeyData: {
        walletAddress: "0xA3767911A84bE6907f26C572bc89426dDdDB2825",
        X: "2853f323437da98ce021d06854f4b292db433c0ad03b204ef223ac2583609a6a",
        Y: "f026b4788e23523e0c8fcbf0bdcf1c1a62c9cde8f56170309607a7a52a19f7c1",
      },
      finalKeyData: {
        walletAddress: "0xA3767911A84bE6907f26C572bc89426dDdDB2825",
        X: "2853f323437da98ce021d06854f4b292db433c0ad03b204ef223ac2583609a6a",
        Y: "f026b4788e23523e0c8fcbf0bdcf1c1a62c9cde8f56170309607a7a52a19f7c1",
      },
      metadata: {
        pubNonce: undefined,
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v1",
      },
      nodesData: result.nodesData,
    });
  });

  it("should fetch user type and public address", async () => {
    const verifier = "tkey-google-cyan";
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result1 = await torus.getUserTypeAndAddress(torusNodeEndpoints, verifierDetails);
    expect(result1.finalKeyData.walletAddress).toBe("0x3507F0d192a44E436B8a6C32a37d57D022861b1a");
    expect(result1.metadata.typeOfUser).toBe("v2");
    expect(result1.metadata.serverTimeOffset).toBeLessThan(20);
    delete result1.metadata.serverTimeOffset;

    expect(result1).toEqual({
      oAuthKeyData: {
        walletAddress: "0xA3767911A84bE6907f26C572bc89426dDdDB2825",
        X: "2853f323437da98ce021d06854f4b292db433c0ad03b204ef223ac2583609a6a",
        Y: "f026b4788e23523e0c8fcbf0bdcf1c1a62c9cde8f56170309607a7a52a19f7c1",
      },
      finalKeyData: {
        walletAddress: "0x3507F0d192a44E436B8a6C32a37d57D022861b1a",
        X: "8aaadab9530cb157d0b0dfb7b27d1a3aaca45274563c22c92c77ee2191779051",
        Y: "d57b89d9f62bb6609d8542c3057943805c8c72f6f27d39781b820f27d7210f12",
      },
      metadata: {
        pubNonce: {
          X: "5f2505155e2c1119ee8a76d0f3b22fccee45871d4aab3cb6209bdbc302b5abc2",
          Y: "a20f30868759a6095697d5631483faa650f489b33c0e2958ad8dc29e707c0a99",
        },
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result1.nodesData,
    });

    const v2Verifier = "tkey-google-cyan";
    const v2TestEmail = "somev2user@gmail.com";
    const result2 = await torus.getUserTypeAndAddress(torusNodeEndpoints, {
      verifier: v2Verifier,
      verifierId: v2TestEmail,
    });
    expect(result2.metadata.serverTimeOffset).toBeLessThan(20);
    delete result2.metadata.serverTimeOffset;

    expect(result2.finalKeyData.walletAddress).toBe("0x8EA83Ace86EB414747F2b23f03C38A34E0217814");
    expect(result2.metadata.typeOfUser).toBe("v2");
    expect(result2).toEqual({
      oAuthKeyData: {
        walletAddress: "0x29446f428293a4E6470AEaEDa6EAfA0F842EF54e",
        X: "8b6f2048aba8c7833e3b02c5b6522bb18c484ad0025156e428f17fb8d8c34021",
        Y: "cd9ba153ff89d665f655d1be4c6912f3ff93996e6fe580d89e78bf1476fef2aa",
      },
      finalKeyData: {
        walletAddress: "0x8EA83Ace86EB414747F2b23f03C38A34E0217814",
        X: "cbe7b0f0332e5583c410fcacb6d4ff685bec053cfd943ac75f5e4aa3278a6fbb",
        Y: "b525c463f438c7a3c4b018c8c5d16c9ef33b9ac6f319140a22b48b17bdf532dd",
      },
      metadata: {
        pubNonce: {
          X: "da0039dd481e140090bed9e777ce16c0c4a16f30f47e8b08b73ac77737dd2d4",
          Y: "7fecffd2910fa47dbdbc989f5c119a668fc922937175974953cbb51c49268265",
        },
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result2.nodesData,
    });

    const v2nTestEmail = "caspertorus@gmail.com";
    const result3 = await torus.getUserTypeAndAddress(torusNodeEndpoints, {
      verifier: v2Verifier,
      verifierId: v2nTestEmail,
    });
    delete result3.metadata.serverTimeOffset;

    expect(result3.finalKeyData.walletAddress).toBe("0xCC1f953f6972a9e3d685d260399D6B85E2117561");
    expect(result3.metadata.typeOfUser).toBe("v2");
    expect(result3).toEqual({
      oAuthKeyData: {
        walletAddress: "0xe8a19482cbe5FaC896A5860Ca4156fb999DDc73b",
        X: "c491ba39155594896b27cf71a804ccf493289d918f40e6ba4d590f1c76139e9e",
        Y: "d4649ed9e46461e1af00399a4c65fabb1dc219b3f4af501a7d635c17f57ab553",
      },
      finalKeyData: {
        walletAddress: "0xCC1f953f6972a9e3d685d260399D6B85E2117561",
        X: "8d784434becaad9b23d9293d1f29c4429447315c4cac824cbf2eb21d3f7d79c8",
        Y: "fe46a0ef5efe33d16f6cfa678a597be930fbec5432cbb7f3580189c18bd7e157",
      },
      metadata: {
        pubNonce: {
          X: "50e250cc6ac1d50d32d2b0f85f11c6625a917a115ced4ef24f4eac183e1525c7",
          Y: "8067a52d02b8214bf82e91b66ce5009f674f4c3998b103059c46c386d0c17f90",
        },
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result3.nodesData,
    });
  });

  it("should be able to key assign", async () => {
    const verifier = "tkey-google-cyan";
    const email = faker.internet.email();
    const verifierDetails = { verifier, verifierId: email };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalKeyData, oAuthKeyData, metadata } = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);

    expect(finalKeyData.walletAddress).not.toBe("");
    expect(finalKeyData.walletAddress).not.toBeNull();
    expect(oAuthKeyData.walletAddress).not.toBe("");
    expect(oAuthKeyData.walletAddress).not.toBeNull();
    expect(metadata.typeOfUser).toBe("v1");
    expect(metadata.upgraded).toBe(false);
  });

  it("should be able to login", async () => {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(torusNodeEndpoints, torusIndexes, TORUS_TEST_VERIFIER, { verifier_id: TORUS_TEST_EMAIL }, token, torusNodePub)
    );
    delete result.sessionData;
    expect(result.metadata.serverTimeOffset).toBeLessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result.finalKeyData.privKey).toBe("5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8");
    expect(result).toEqual({
      finalKeyData: {
        X: "e2ed6033951af2851d1bea98799e62fb1ff24b952c1faea17922684678ba42d1",
        Y: "beef0efad88e81385952c0068ca48e8b9c2121be87cb0ddf18a68806db202359",
        walletAddress: "0xC615aA03Dd8C9b2dc6F7c43cBDfF2c34bBa47Ec9",
        privKey: "5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8",
      },
      oAuthKeyData: {
        X: "e2ed6033951af2851d1bea98799e62fb1ff24b952c1faea17922684678ba42d1",
        Y: "beef0efad88e81385952c0068ca48e8b9c2121be87cb0ddf18a68806db202359",
        walletAddress: "0xC615aA03Dd8C9b2dc6F7c43cBDfF2c34bBa47Ec9",
        privKey: "5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8",
      },
      postboxKeyData: {
        X: "e2ed6033951af2851d1bea98799e62fb1ff24b952c1faea17922684678ba42d1",
        Y: "beef0efad88e81385952c0068ca48e8b9c2121be87cb0ddf18a68806db202359",
        privKey: "5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8",
      },
      metadata: { pubNonce: undefined, nonce: 0n, typeOfUser: "v1", upgraded: null },
      nodesData: result.nodesData,
    });
  });

  it("should be able to login without commitments", async () => {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: TORUS_TEST_EMAIL },
        token,
        torusNodePub,
        {},
        true,
        false
      )
    );
    delete result.sessionData;
    expect(result.metadata.serverTimeOffset).toBeLessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result.finalKeyData.privKey).toBe("5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8");
    expect(result).toEqual({
      finalKeyData: {
        X: "e2ed6033951af2851d1bea98799e62fb1ff24b952c1faea17922684678ba42d1",
        Y: "beef0efad88e81385952c0068ca48e8b9c2121be87cb0ddf18a68806db202359",
        walletAddress: "0xC615aA03Dd8C9b2dc6F7c43cBDfF2c34bBa47Ec9",
        privKey: "5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8",
      },
      oAuthKeyData: {
        X: "e2ed6033951af2851d1bea98799e62fb1ff24b952c1faea17922684678ba42d1",
        Y: "beef0efad88e81385952c0068ca48e8b9c2121be87cb0ddf18a68806db202359",
        walletAddress: "0xC615aA03Dd8C9b2dc6F7c43cBDfF2c34bBa47Ec9",
        privKey: "5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8",
      },
      postboxKeyData: {
        X: "e2ed6033951af2851d1bea98799e62fb1ff24b952c1faea17922684678ba42d1",
        Y: "beef0efad88e81385952c0068ca48e8b9c2121be87cb0ddf18a68806db202359",
        privKey: "5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8",
      },
      metadata: { pubNonce: undefined, nonce: 0n, typeOfUser: "v1", upgraded: null },
      nodesData: result.nodesData,
    });
  });

  it("should be able to aggregate login", async () => {
    const idToken = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const hashedIdToken = keccak256(utf8ToBytes(idToken));
    const verifierDetails = { verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.retrieveShares(
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
    delete result.sessionData;
    expect(result.metadata.serverTimeOffset).toBeLessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result.oAuthKeyData.walletAddress).toBe("0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04");
    expect(result.finalKeyData.walletAddress).toBe("0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04");
    expect(result).toEqual({
      finalKeyData: {
        walletAddress: "0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04",
        X: "afd12f2476006ef6aa8778190b29676a70039df8688f9dee69c779bdc8ff0223",
        Y: "e557a5ee879632727f5979d6b9cea69d87e3dab54a8c1b6685d86dfbfcd785dd",
        privKey: "45a5b62c4ff5490baa75d33bf4f03ba6c5b0095678b0f4055312eef7b780b7bf",
      },
      oAuthKeyData: {
        walletAddress: "0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04",
        X: "afd12f2476006ef6aa8778190b29676a70039df8688f9dee69c779bdc8ff0223",
        Y: "e557a5ee879632727f5979d6b9cea69d87e3dab54a8c1b6685d86dfbfcd785dd",
        privKey: "45a5b62c4ff5490baa75d33bf4f03ba6c5b0095678b0f4055312eef7b780b7bf",
      },
      postboxKeyData: {
        X: "afd12f2476006ef6aa8778190b29676a70039df8688f9dee69c779bdc8ff0223",
        Y: "e557a5ee879632727f5979d6b9cea69d87e3dab54a8c1b6685d86dfbfcd785dd",
        privKey: "45a5b62c4ff5490baa75d33bf4f03ba6c5b0095678b0f4055312eef7b780b7bf",
      },
      metadata: { pubNonce: undefined, nonce: 0n, typeOfUser: "v1", upgraded: null },
      nodesData: result.nodesData,
    });
  });
});
