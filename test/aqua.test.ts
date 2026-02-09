import { faker } from "@faker-js/faker";
import { TORUS_LEGACY_NETWORK } from "@toruslabs/constants";
import { NodeDetailManager } from "@toruslabs/fetch-node-details";
import { beforeEach, describe, expect, it } from "vitest";

import { keccak256, TorusPublicKey, utf8ToBytes } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken, getRetrieveSharesParams } from "./helpers";

const TORUS_TEST_EMAIL = "hello@tor.us";
const TORUS_TEST_VERIFIER = "torus-test-health";
const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

describe("torus utils aqua", () => {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeDetailManager;

  beforeEach(() => {
    torus = new TorusUtils({
      network: "aqua",
      clientId: "YOUR_CLIENT_ID",
    });
    TORUS_NODE_MANAGER = new NodeDetailManager({ network: TORUS_LEGACY_NETWORK.AQUA });
  });

  it("should fetch public address", async () => {
    const verifier = "tkey-google-aqua"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints, torusNodePub } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result = await torus.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).toBe("0xDfA967285AC699A70DA340F60d00DB19A272639d");
    expect(result.metadata.serverTimeOffset).toBeLessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).toEqual({
      oAuthKeyData: {
        walletAddress: "0xDfA967285AC699A70DA340F60d00DB19A272639d",
        X: "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d",
        Y: "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c",
      },
      finalKeyData: {
        walletAddress: "0xDfA967285AC699A70DA340F60d00DB19A272639d",
        X: "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d",
        Y: "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c",
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
    const verifier = "tkey-google-aqua"; // any verifier
    const verifierDetails = { verifier, verifierId: TORUS_TEST_EMAIL };
    const { torusNodeEndpoints } = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const result1 = (await torus.getUserTypeAndAddress(torusNodeEndpoints, verifierDetails)) as TorusPublicKey;
    expect(result1.metadata.typeOfUser).toBe("v2");
    expect(result1.metadata.serverTimeOffset).toBeLessThan(20);
    delete result1.metadata.serverTimeOffset;

    expect(result1).toEqual({
      oAuthKeyData: {
        walletAddress: "0xDfA967285AC699A70DA340F60d00DB19A272639d",
        X: "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d",
        Y: "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c",
      },
      finalKeyData: {
        walletAddress: "0x79F06350eF34Aeed4BE68e26954D405D573f1438",
        X: "99df45abc8e6ee03d2f94df33be79e939eadfbed20c6b88492782fdc3ef1dfd3",
        Y: "12bf3e54599a177fdb88f8b22419df7ddf1622e1d2344301edbe090890a72b16",
      },
      metadata: {
        pubNonce: {
          X: "dc5a031fd2e0b55dbaece314ea125bac9da5f0a916bf156ff36b5ad71380ea32",
          Y: "affd749b98c209d2f9cf4dacb145d7897f82f1e2924a47b07874302ecc0b8ef1",
        },
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result1.nodesData,
    });

    // Test v2 verifier
    const v2Verifier = "tkey-google-aqua";
    const v2TestEmail = "somev2user@gmail.com";
    const result2 = (await torus.getUserTypeAndAddress(torusNodeEndpoints, {
      verifier: v2Verifier,
      verifierId: v2TestEmail,
    })) as TorusPublicKey;
    expect(result2.metadata.typeOfUser).toBe("v2");
    expect(result2.metadata.serverTimeOffset).toBeLessThan(20);
    delete result2.metadata.serverTimeOffset;

    expect(result2).toEqual({
      oAuthKeyData: {
        walletAddress: "0x4ea5260fF85678A2a326D08DF9C44d1f559a5828",
        X: "0e6febe33a9d4eeb680cc6b63ff6237ad1971f27adcd7f104a3b1de18eda9337",
        Y: "a5a915561f3543688e71281a850b9ee10b9690f305d9e79028dfc8359192b82d",
      },
      finalKeyData: {
        walletAddress: "0xBc32f315515AdE7010cabC5Fd68c966657A570BD",
        X: "4897f120584ee18a72b9a6bb92c3ef6e45fc5fdff70beae7dc9325bd01332022",
        Y: "2066dbef2fcdded4573e3c04d1c04edd5d44662168e636ed9d0b0cbe2e67c968",
      },
      metadata: {
        pubNonce: {
          X: "1601cf4dc4362b219260663d5ec5119699fbca185d08b7acb2e36cad914340d5",
          Y: "c2f7871f61ee71b4486ac9fb40ec759099800e737139dc5dfaaaed8c9d77c3c1",
        },
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result2.nodesData,
    });

    // Test 2/n user
    const v2nTestEmail = "caspertorus@gmail.com";
    const result3 = (await torus.getUserTypeAndAddress(torusNodeEndpoints, {
      verifier: v2Verifier,
      verifierId: v2nTestEmail,
    })) as TorusPublicKey;
    expect(result3.metadata.serverTimeOffset).toBeLessThan(20);
    delete result3.metadata.serverTimeOffset;

    expect(result3.metadata.typeOfUser).toBe("v2");
    expect(result3).toEqual({
      oAuthKeyData: {
        walletAddress: "0x4ce0D09C3989eb3cC9372cC27fa022D721D737dD",
        X: "e76d2f7fa2c0df324b4ab74629c3af47aa4609c35f1d2b6b90b77a47ab9a1281",
        Y: "b33b35148d72d357070f66372e07fec436001bdb15c098276b120b9ed64c1e5f",
      },
      finalKeyData: {
        walletAddress: "0x5469C5aCB0F30929226AfF4622918DA8E1424a8D",
        X: "c20fac685bb67169e92f1d5d8894d4eea18753c0ef3b7b1b2224233b2dfa3539",
        Y: "c4f080b5c8d5c55c8eaba4bec70f668f36db4126f358b491d631fefea7c19d21",
      },
      metadata: {
        pubNonce: {
          X: "17b1ebce1fa874452a96d0c6d74c1445b78f16957c7decc5d2a202b0ce4662f5",
          Y: "b5432cb593753e1b3ecf98b05dc03e57bc02c415e1b80a1ffc5a401ec1f0abd6",
        },
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result3.nodesData,
    });
  });

  it("should be able to key assign", async () => {
    const verifier = "tkey-google-aqua";
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
    expect(result.finalKeyData.privKey).toBe("f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d");
    expect(result.metadata.serverTimeOffset).toBeLessThan(20);
    delete result.metadata.serverTimeOffset;

    expect(result).toEqual({
      finalKeyData: {
        walletAddress: "0x9EBE51e49d8e201b40cAA4405f5E0B86d9D27195",
        X: "c7bcc239f0957bb05bda94757eb4a5f648339424b22435da5cf7a0f2b2323664",
        Y: "63795690a33e575ee12d832935d563c2b5f2e1b1ffac63c32a4674152f68cb3f",
        privKey: "f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d",
      },
      oAuthKeyData: {
        walletAddress: "0x9EBE51e49d8e201b40cAA4405f5E0B86d9D27195",
        X: "c7bcc239f0957bb05bda94757eb4a5f648339424b22435da5cf7a0f2b2323664",
        Y: "63795690a33e575ee12d832935d563c2b5f2e1b1ffac63c32a4674152f68cb3f",
        privKey: "f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d",
      },
      postboxKeyData: {
        X: "c7bcc239f0957bb05bda94757eb4a5f648339424b22435da5cf7a0f2b2323664",
        Y: "63795690a33e575ee12d832935d563c2b5f2e1b1ffac63c32a4674152f68cb3f",
        privKey: "f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d",
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

    expect(result.oAuthKeyData.walletAddress).toBe("0x5b58d8a16fDA79172cd42Dc3068d5CEf26a5C81D");
    expect(result.finalKeyData.walletAddress).toBe("0x5b58d8a16fDA79172cd42Dc3068d5CEf26a5C81D");
    expect(result).toEqual({
      finalKeyData: {
        walletAddress: "0x5b58d8a16fDA79172cd42Dc3068d5CEf26a5C81D",
        X: "37a4ac8cbef68e88bcec5909d9b6fffb539187365bb723f3d7bffe56ae80e31d",
        Y: "f963f2d08ed4dd0da9b8a8d74c6fdaeef7bdcde31f84fcce19fa2173d40b2c10",
        privKey: "488d39ac548e15cfb0eaf161d86496e1645b09437df21311e24a56c4efd76355",
      },
      oAuthKeyData: {
        walletAddress: "0x5b58d8a16fDA79172cd42Dc3068d5CEf26a5C81D",
        X: "37a4ac8cbef68e88bcec5909d9b6fffb539187365bb723f3d7bffe56ae80e31d",
        Y: "f963f2d08ed4dd0da9b8a8d74c6fdaeef7bdcde31f84fcce19fa2173d40b2c10",
        privKey: "488d39ac548e15cfb0eaf161d86496e1645b09437df21311e24a56c4efd76355",
      },
      postboxKeyData: {
        X: "37a4ac8cbef68e88bcec5909d9b6fffb539187365bb723f3d7bffe56ae80e31d",
        Y: "f963f2d08ed4dd0da9b8a8d74c6fdaeef7bdcde31f84fcce19fa2173d40b2c10",
        privKey: "488d39ac548e15cfb0eaf161d86496e1645b09437df21311e24a56c4efd76355",
      },
      sessionData: result.sessionData,
      metadata: { pubNonce: undefined, nonce: 0n, typeOfUser: "v1", upgraded: null },
      nodesData: result.nodesData,
    });
  });
});
