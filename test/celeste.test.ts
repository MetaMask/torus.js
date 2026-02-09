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

describe("torus utils celeste", () => {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeDetailManager;

  beforeEach(() => {
    torus = new TorusUtils({
      network: "celeste",
      clientId: "YOUR_CLIENT_ID",
    });
    TORUS_NODE_MANAGER = new NodeDetailManager({ network: TORUS_LEGACY_NETWORK.CELESTE });
  });

  it("should fetch public address", async () => {
    const verifier = "tkey-google-celeste";
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).toBe("0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113");
    expect(result.metadata.serverTimeOffset).toBeLessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).toEqual({
      oAuthKeyData: {
        X: "b89b9d66b247d7294a98616b95b7bfa1675aa85a1df4d89f2780283864f1b6e9",
        Y: "65422a8ccd66e638899fc53497e468a9a0bf50d45c9cb85ae0ffcfc13f433ffb",
        walletAddress: "0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113",
      },
      finalKeyData: {
        X: "b89b9d66b247d7294a98616b95b7bfa1675aa85a1df4d89f2780283864f1b6e9",
        Y: "65422a8ccd66e638899fc53497e468a9a0bf50d45c9cb85ae0ffcfc13f433ffb",
        walletAddress: "0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113",
      },
      metadata: {
        pubNonce: undefined,
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v1",
      },
      nodesData: { nodeIndexes: [] },
    });
  });

  it("should fetch user type and public address", async () => {
    const verifier = "tkey-google-celeste";
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result1 = await torus.getUserTypeAndAddress(torusNodeEndpoints, verifierDetails);
    expect(result1.finalKeyData.walletAddress).toBe("0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113");
    expect(result1.metadata.typeOfUser).toBe("v1");
    expect(result1.metadata.serverTimeOffset).toBeLessThan(20);
    delete result1.metadata.serverTimeOffset;

    expect(result1).toEqual({
      oAuthKeyData: {
        X: "b89b9d66b247d7294a98616b95b7bfa1675aa85a1df4d89f2780283864f1b6e9",
        Y: "65422a8ccd66e638899fc53497e468a9a0bf50d45c9cb85ae0ffcfc13f433ffb",
        walletAddress: "0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113",
      },
      finalKeyData: {
        X: "b89b9d66b247d7294a98616b95b7bfa1675aa85a1df4d89f2780283864f1b6e9",
        Y: "65422a8ccd66e638899fc53497e468a9a0bf50d45c9cb85ae0ffcfc13f433ffb",
        walletAddress: "0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113",
      },
      metadata: {
        pubNonce: undefined,
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v1",
      },
      nodesData: { nodeIndexes: [] },
    });

    const v2Verifier = "tkey-google-celeste";
    const v2TestEmail = "somev2user@gmail.com";
    const result2 = await torus.getUserTypeAndAddress(torusNodeEndpoints, {
      verifier: v2Verifier,
      verifierId: v2TestEmail,
    });
    expect(result2.finalKeyData.walletAddress).toBe("0x8d69CE354DA39413f205FdC8680dE1F3FBBb36e2");
    expect(result2.metadata.typeOfUser).toBe("v2");
    delete result2.metadata.serverTimeOffset;

    expect(result2).toEqual({
      oAuthKeyData: {
        X: "cfa646a2949ebe559205c5c407d734d1b6927f2ea5fbeabfcbc31ab9a985a336",
        Y: "8f988eb8b59515293820aa38af172b153e8d25307db8d5f410407c20e062b6e6",
        walletAddress: "0xda4afB35493094Dd2C05b186Ca0FABAD96491B21",
      },
      finalKeyData: {
        X: "5962144e03b993b0e503eb4e6e0196427f9fc9472f0dfd1be2ca5d4939f91680",
        Y: "f6e81f01f483110badab18371237d15834f9ecf31c3588c165dae32ec446ac38",
        walletAddress: "0x8d69CE354DA39413f205FdC8680dE1F3FBBb36e2",
      },
      metadata: {
        pubNonce: {
          X: "2f630074151394ba1f715986a9215f4e36c9f22fc264ff880ef6d162c1300aa8",
          Y: "704cb63e5f7a291735c54e22242ef53673642ec1660da00f1abc2e7909da03d7",
        },
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: { nodeIndexes: [] },
    });

    const v2nTestEmail = "caspertorus@gmail.com";
    const result3 = await torus.getUserTypeAndAddress(torusNodeEndpoints, {
      verifier: v2Verifier,
      verifierId: v2nTestEmail,
    });
    delete result3.metadata.serverTimeOffset;

    expect(result3.finalKeyData.walletAddress).toBe("0x8108c29976C458e76f797AD55A3715Ce80a3fe78");
    expect(result3.metadata.typeOfUser).toBe("v2");
    expect(result3).toEqual({
      oAuthKeyData: {
        X: "0cc857201e6c304dd893b243e323fe95982e5a99c0994cf902efa2432a672eb4",
        Y: "37a2f53c250b3e1186e38ece3dfcbcb23e325913038703531831b96d3e7b54cc",
        walletAddress: "0xc8c4748ec135196fb482C761da273C31Ec48B099",
      },
      finalKeyData: {
        X: "e95fe2d595ade03f56d9c9a147fbb67705041704f147576fa4a8afbe7dc69470",
        Y: "3e20e4b331466769c4dd78f4561bfb2849010b4005b09c2ed082380326724ebe",
        walletAddress: "0x8108c29976C458e76f797AD55A3715Ce80a3fe78",
      },
      metadata: {
        pubNonce: {
          X: "f8ff2c44cc0abf512d35b35c3c5cbc0eda700d49bc13b72c5492b0cdb2ca3619",
          Y: "88fb3087cec269c8c39d25b04f15298d33712f13b0f9665821328dfc7a567afb",
        },
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: { nodeIndexes: [] },
    });
  });

  it("should be able to key assign", async () => {
    const verifier = "tkey-google-celeste";
    const email = faker.internet.email();
    const verifierDetails = { verifier, verifierId: email };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalKeyData, metadata, oAuthKeyData } = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);

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
    expect(result.finalKeyData.privKey).toBe("0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914");
    expect(result.metadata.serverTimeOffset).toBeLessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).toEqual({
      finalKeyData: {
        walletAddress: "0x58420FB83971C4490D8c9B091f8bfC890D716617",
        X: "73b82ce0f8201a962636d404fe7a683f37c2267a9528576e1dac9964940add74",
        Y: "6d28c46c5385b90322bde74d6c5096e154eae2838399f4d6e8d752f7b0c449c1",
        privKey: "0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914",
      },
      oAuthKeyData: {
        walletAddress: "0x58420FB83971C4490D8c9B091f8bfC890D716617",
        X: "73b82ce0f8201a962636d404fe7a683f37c2267a9528576e1dac9964940add74",
        Y: "6d28c46c5385b90322bde74d6c5096e154eae2838399f4d6e8d752f7b0c449c1",
        privKey: "0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914",
      },
      postboxKeyData: {
        X: "73b82ce0f8201a962636d404fe7a683f37c2267a9528576e1dac9964940add74",
        Y: "6d28c46c5385b90322bde74d6c5096e154eae2838399f4d6e8d752f7b0c449c1",
        privKey: "0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914",
      },
      sessionData: result.sessionData,
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
    expect(result.metadata.serverTimeOffset).toBeLessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result.oAuthKeyData.walletAddress).toBe("0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564");
    expect(result.finalKeyData.walletAddress).toBe("0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564");
    expect(result).toEqual({
      finalKeyData: {
        walletAddress: "0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564",
        X: "df6eb11d52e76b388a44896e9442eda17096c2b67b0be957a4ba0b68a70111ca",
        Y: "bfd29ab1e97b3f7c444bb3e7ad0acb39d72589371387436c7d623d1e83f3d6eb",
        privKey: "356305761eca57f27b09700d76456ad627b084152725dbfdfcfa0abcd9d4f17e",
      },
      oAuthKeyData: {
        walletAddress: "0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564",
        X: "df6eb11d52e76b388a44896e9442eda17096c2b67b0be957a4ba0b68a70111ca",
        Y: "bfd29ab1e97b3f7c444bb3e7ad0acb39d72589371387436c7d623d1e83f3d6eb",
        privKey: "356305761eca57f27b09700d76456ad627b084152725dbfdfcfa0abcd9d4f17e",
      },
      postboxKeyData: {
        X: "df6eb11d52e76b388a44896e9442eda17096c2b67b0be957a4ba0b68a70111ca",
        Y: "bfd29ab1e97b3f7c444bb3e7ad0acb39d72589371387436c7d623d1e83f3d6eb",
        privKey: "356305761eca57f27b09700d76456ad627b084152725dbfdfcfa0abcd9d4f17e",
      },
      sessionData: result.sessionData,
      metadata: { pubNonce: undefined, nonce: 0n, typeOfUser: "v1", upgraded: null },
      nodesData: result.nodesData,
    });
  });
});
