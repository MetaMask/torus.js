import { faker } from "@faker-js/faker";
import { TORUS_LEGACY_NETWORK } from "@toruslabs/constants";
import { NodeDetailManager } from "@toruslabs/fetch-node-details";
import { fail } from "assert";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { keccak256, TorusPublicKey, utf8ToBytes } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken, getRetrieveSharesParams } from "./helpers";

const TORUS_TEST_EMAIL = "archit1@tor.us";
const TORUS_TEST_VERIFIER = "torus-test-health";
const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

describe("torus utils migrated testnet on sapphire", () => {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeDetailManager;

  beforeEach(() => {
    torus = new TorusUtils({ network: "testnet", clientId: "YOUR_CLIENT_ID" });
    TORUS_NODE_MANAGER = new NodeDetailManager({
      network: TORUS_LEGACY_NETWORK.TESTNET,
    });
  });

  it("should fetch public address", async () => {
    const verifier = "google-lrc";
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).toBe("0x9bcBAde70546c0796c00323CD1b97fa0a425A506");
    expect(result.metadata.serverTimeOffset).toBeLessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).toEqual({
      oAuthKeyData: {
        walletAddress: "0x9bcBAde70546c0796c00323CD1b97fa0a425A506",
        X: "894f633b3734ddbf08867816bc55da60803c1e7c2a38b148b7fb2a84160a1bb5",
        Y: "1cf2ea7ac63ee1a34da2330413692ba8538bf7cd6512327343d918e0102a1438",
      },
      finalKeyData: {
        walletAddress: "0x9bcBAde70546c0796c00323CD1b97fa0a425A506",
        X: "894f633b3734ddbf08867816bc55da60803c1e7c2a38b148b7fb2a84160a1bb5",
        Y: "1cf2ea7ac63ee1a34da2330413692ba8538bf7cd6512327343d918e0102a1438",
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
    const verifier = "google-lrc";
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result1 = await torus.getUserTypeAndAddress(torusNodeEndpoints, verifierDetails);
    expect(result1.finalKeyData.walletAddress).toBe("0xf5804f608C233b9cdA5952E46EB86C9037fd6842");
    expect(result1.metadata.typeOfUser).toBe("v2");
    expect(result1.metadata.serverTimeOffset).toBeLessThan(20);

    delete result1.metadata.serverTimeOffset;

    expect(result1).toEqual({
      oAuthKeyData: {
        walletAddress: "0x9bcBAde70546c0796c00323CD1b97fa0a425A506",
        X: "894f633b3734ddbf08867816bc55da60803c1e7c2a38b148b7fb2a84160a1bb5",
        Y: "1cf2ea7ac63ee1a34da2330413692ba8538bf7cd6512327343d918e0102a1438",
      },
      finalKeyData: {
        walletAddress: "0xf5804f608C233b9cdA5952E46EB86C9037fd6842",
        X: "ed737569a557b50722a8b5c0e4e5ca30cef1ede2f5674a0616b78246bb93dfd0",
        Y: "d9e8e6c54c12c4da38c2f0d1047fcf6089036127738f4ef72a83431339586ca9",
      },
      metadata: {
        pubNonce: {
          X: "f3f7caefd6540d923c9993113f34226371bd6714a5be6882dedc95a6a929a8",
          Y: "f28620603601ce54fa0d70fd691fb72ff52f5bf164bf1a91617922eaad8cc7a5",
        },
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result1.nodesData,
    });

    const v2Verifier = "tkey-google-lrc";
    const v2TestEmail = "somev2user@gmail.com";
    const result2 = (await torus.getUserTypeAndAddress(torusNodeEndpoints, {
      verifier: v2Verifier,
      verifierId: v2TestEmail,
    })) as TorusPublicKey;
    expect(result2.finalKeyData.walletAddress).toBe("0xE91200d82029603d73d6E307DbCbd9A7D0129d8D");
    expect(result2.metadata.typeOfUser).toBe("v2");
    expect(result2.metadata.serverTimeOffset).toBeLessThan(20);

    delete result2.metadata.serverTimeOffset;

    expect(result2).toEqual({
      oAuthKeyData: {
        walletAddress: "0x376597141d8d219553378313d18590F373B09795",
        X: "86cd2db15b7a9937fa8ab7d0bf8e7f4113b64d1f4b2397aad35d6d4749d2fb6c",
        Y: "86ef47a3724144331c31a3a322d85b6fc1a5d113b41eaa0052053b6e3c74a3e2",
      },
      finalKeyData: {
        walletAddress: "0xE91200d82029603d73d6E307DbCbd9A7D0129d8D",
        X: "c350e338dde24df986915992fea6e0aef3560c245ca144ee7fe1498784c4ef4e",
        Y: "a605e52b65d3635f89654519dfa7e31f7b45f206ef4189866ad0c2240d40f97f",
      },
      metadata: {
        pubNonce: {
          X: "ad121b67fa550da814bbbd54ec7070705d058c941e04c03e07967b07b2f90345",
          Y: "bfe2395b177a72ebb836aaf24cedff2f14cd9ed49047990f5cdb99e4981b5753",
        },
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result2.nodesData,
    });

    const v2nTestEmail = "caspertorus@gmail.com";
    const result3 = (await torus.getUserTypeAndAddress(torusNodeEndpoints, {
      verifier: v2Verifier,
      verifierId: v2nTestEmail,
    })) as TorusPublicKey;
    expect(result3.finalKeyData.walletAddress).toBe("0x1016DA7c47A04C76036637Ea02AcF1d29c64a456");
    expect(result3.metadata.typeOfUser).toBe("v2");
    delete result3.metadata.serverTimeOffset;

    expect(result3).toEqual({
      oAuthKeyData: {
        walletAddress: "0xd45383fbF04BccFa0450d7d8ee453ca86b7C6544",
        X: "d25cc473fbb448d20b5551f3c9aa121e1924b3d197353347187c47ad13ecd5d8",
        Y: "3394000f43160a925e6c3017dde1354ecb2b61739571c6584f58edd6b923b0f5",
      },
      finalKeyData: {
        walletAddress: "0x1016DA7c47A04C76036637Ea02AcF1d29c64a456",
        X: "d3e222f6b23f0436b7c86e9cc4164eb5ea8448e4c0e7539c8b4f7fd00e8ec5c7",
        Y: "1c47f5faccec6cf57c36919f6f0941fe3d8d65033cf2cc78f209304386044222",
      },
      metadata: {
        pubNonce: {
          X: "4f86b0e69992d1551f1b16ceb0909453dbe17b9422b030ee6c5471c2e16b65d0",
          Y: "640384f3d39debb04c4e9fe5a5ec6a1b494b0ad66d00ac9be6f166f21d116ca4",
        },
        nonce: 0n,
        upgraded: true,
        typeOfUser: "v2",
      },
      nodesData: result3.nodesData,
    });
  });

  it("should be able to key assign", async () => {
    const verifier = "google-lrc";
    const email = faker.internet.email();
    const verifierDetails = { verifier, verifierId: email };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const { finalKeyData, oAuthKeyData, metadata } = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(finalKeyData.walletAddress).not.toBe("");
    expect(finalKeyData.walletAddress).not.toBe(null);
    expect(oAuthKeyData.walletAddress).not.toBe("");
    expect(oAuthKeyData.walletAddress).not.toBe(null);
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
    expect(result.metadata.serverTimeOffset).toBeLessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result.finalKeyData.privKey).toBe("9b0fb017db14a0a25ed51f78a258713c8ae88b5e58a43acb70b22f9e2ee138e3");
    expect(result).toEqual({
      finalKeyData: {
        walletAddress: "0xF8d2d3cFC30949C1cb1499C9aAC8F9300535a8d6",
        X: "6de2e34d488dd6a6b596524075b032a5d5eb945bcc33923ab5b88fd4fd04b5fd",
        Y: "d5fb7b51b846e05362461357ec6e8ca075ea62507e2d5d7253b72b0b960927e9",
        privKey: "9b0fb017db14a0a25ed51f78a258713c8ae88b5e58a43acb70b22f9e2ee138e3",
      },
      oAuthKeyData: {
        walletAddress: "0xF8d2d3cFC30949C1cb1499C9aAC8F9300535a8d6",
        X: "6de2e34d488dd6a6b596524075b032a5d5eb945bcc33923ab5b88fd4fd04b5fd",
        Y: "d5fb7b51b846e05362461357ec6e8ca075ea62507e2d5d7253b72b0b960927e9",
        privKey: "9b0fb017db14a0a25ed51f78a258713c8ae88b5e58a43acb70b22f9e2ee138e3",
      },
      postboxKeyData: {
        X: "6de2e34d488dd6a6b596524075b032a5d5eb945bcc33923ab5b88fd4fd04b5fd",
        Y: "d5fb7b51b846e05362461357ec6e8ca075ea62507e2d5d7253b72b0b960927e9",
        privKey: "9b0fb017db14a0a25ed51f78a258713c8ae88b5e58a43acb70b22f9e2ee138e3",
      },
      sessionData: {
        sessionTokenData: result.sessionData.sessionTokenData,
        sessionAuthKey: result.sessionData.sessionAuthKey,
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
    expect(result.metadata.serverTimeOffset).toBeLessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result.metadata.typeOfUser).toBe("v1");
    expect(result.oAuthKeyData.walletAddress).toBe("0x938a40E155d118BD31E439A9d92D67bd55317965");
    expect(result.finalKeyData.walletAddress).toBe("0x938a40E155d118BD31E439A9d92D67bd55317965");
    expect(result).toEqual({
      finalKeyData: {
        walletAddress: "0x938a40E155d118BD31E439A9d92D67bd55317965",
        X: "1c50e34ef5b7afcf5b0c6501a6ae00ec3a09a321dd885c5073dd122e2a251b95",
        Y: "2cc74beb28f2c4a7c4034f80836d51b2781b36fefbeafb4eb1cd055bdf73b1e6",
        privKey: "3cbfa57d702327ec1af505adc88ad577804a1a7780bc013ed9e714c547fb5cb1",
      },
      oAuthKeyData: {
        walletAddress: "0x938a40E155d118BD31E439A9d92D67bd55317965",
        X: "1c50e34ef5b7afcf5b0c6501a6ae00ec3a09a321dd885c5073dd122e2a251b95",
        Y: "2cc74beb28f2c4a7c4034f80836d51b2781b36fefbeafb4eb1cd055bdf73b1e6",
        privKey: "3cbfa57d702327ec1af505adc88ad577804a1a7780bc013ed9e714c547fb5cb1",
      },
      postboxKeyData: {
        X: "1c50e34ef5b7afcf5b0c6501a6ae00ec3a09a321dd885c5073dd122e2a251b95",
        Y: "2cc74beb28f2c4a7c4034f80836d51b2781b36fefbeafb4eb1cd055bdf73b1e6",
        privKey: "3cbfa57d702327ec1af505adc88ad577804a1a7780bc013ed9e714c547fb5cb1",
      },
      sessionData: {
        sessionTokenData: result.sessionData.sessionTokenData,
        sessionAuthKey: result.sessionData.sessionAuthKey,
      },
      metadata: { pubNonce: undefined, nonce: 0n, typeOfUser: "v1", upgraded: null },
      nodesData: result.nodesData,
    });
  });

  it("should fail at get or set nonce when server time offset is expired", async () => {
    const email = "himanshu@tor.us";
    const verifier = "google-lrc";
    const token = generateIdToken(email, "ES256");

    const verifierDetails = { verifier, verifierId: email };
    const legacyTorus = new TorusUtils({
      network: TORUS_LEGACY_NETWORK.TESTNET,
      clientId: "YOUR_CLIENT_ID",
      enableOneKey: true,
      serverTimeOffset: -700,
    });
    const { torusNodeSSSEndpoints: torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    try {
      await legacyTorus.retrieveShares(
        getRetrieveSharesParams(torusNodeEndpoints, torusIndexes, TORUS_TEST_VERIFIER, { verifier_id: email }, token, torusNodePub)
      );
      fail("should not reach here");
    } catch (err) {
      // eslint-disable-next-line vitest/no-conditional-expect
      expect((err as { status: number }).status).toBe(403);
    }
  });

  it("should pass at get pub nonce when system time is incorrect", async () => {
    const fakeTime = new Date("2023-05-05T12:00:00").getTime();
    vi.useFakeTimers({ now: fakeTime });

    // Now, getCurrentTime should return the mocked time
    const currentTime = new Date().getTime();

    // Assert that the current time matches the mocked time
    expect(currentTime).toBe(fakeTime);
    const email = "himanshu@tor.us";
    const verifier = "google-lrc";
    const verifierDetails = { verifier, verifierId: email };
    const { torusNodeSSSEndpoints: torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const response = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(response.metadata.typeOfUser).toBe("v1");
    vi.useRealTimers();
  });
});
