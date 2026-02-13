import { faker } from "@faker-js/faker";
import { bs58 as base58 } from "@toruslabs/bs58";
import { TORUS_SAPPHIRE_NETWORK } from "@toruslabs/constants";
import { NodeDetailManager } from "@toruslabs/fetch-node-details";
import { beforeEach, describe, expect, it } from "vitest";

import { bytesToHex, keccak256, utf8ToBytes } from "../src";
import TorusUtils from "../src/torus";
import { generateIdToken, getImportKeyParams, getRetrieveSharesParams, lookupVerifier } from "./helpers";

const TORUS_TEST_EMAIL = "ed25519testuser@tor.us";
const TORUS_TEST_EMAIL_HASHED = "ed25519testuserhashed19@tor.us";

const TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierided25519@example.com";

const TORUS_TEST_VERIFIER = "torus-test-health";

const TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";
const HashEnabledVerifier = "torus-test-verifierid-hash";

describe("torus utils ed25519 sapphire devnet", () => {
  let torus: TorusUtils;
  let TORUS_NODE_MANAGER: NodeDetailManager;

  beforeEach(() => {
    TORUS_NODE_MANAGER = new NodeDetailManager({ network: TORUS_SAPPHIRE_NETWORK.SAPPHIRE_DEVNET });
    torus = new TorusUtils({
      network: TORUS_SAPPHIRE_NETWORK.SAPPHIRE_DEVNET,
      clientId: "YOUR_CLIENT_ID",
      enableOneKey: true,
      keyType: "ed25519",
    });
    TorusUtils.enableLogging(false);
  });

  it("should should fetch public address", async () => {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: "Willa_Funk11@gmail.com" };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).toBe("HHmiJMCAwhyf9ZWNtj7FEKGXeeC2NjUjPobpDKm43yKs");
    delete result.metadata.serverTimeOffset;
    expect(result).toEqual({
      oAuthKeyData: {
        walletAddress: "49yLu8yLqpuCXchzjQSt1tpBz8AP2E9EzzP7a8QtxmTE",
        X: "5d39eba90fafbce150b33b9a60b41e1cfdf9e2640b55bf96b787173d74f8e415",
        Y: "099639b7da35c1f31a44da7399a29d7db8eaa9639582cf7ed80aa4f7216adf2e",
      },
      finalKeyData: {
        walletAddress: "HHmiJMCAwhyf9ZWNtj7FEKGXeeC2NjUjPobpDKm43yKs",
        X: "575203523b34bcfa2c25c428871c421afd69dbcb7375833b52ef264aaa466a81",
        Y: "26f0b1f5740088c2ecf676081b8e2fe5254f1cbb693947ae391af13500d706f2",
      },
      metadata: {
        pubNonce: {
          X: "71bf997547c1ac3f0babee87ebac055e8542863ebb1ba66e8092499eacbffd22",
          Y: "71a0a70c5ae06d7eeb45673d4081fdfc9f29c4acfbbb57bf52a33dd7630599b1",
        },
        nonce: 0n,
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: result.nodesData,
    });
  });

  it("should should fetch public address with keyType", async function () {
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: "Willa_Funk11@gmail.com" };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, { ...verifierDetails, keyType: "secp256k1" });
    expect(result.finalKeyData.walletAddress).toBe("0xc53Df7C3Eb4990CfB8f903e4240dBB3BBa715A96");
    delete result.metadata.serverTimeOffset;
    expect(result).toEqual({
      oAuthKeyData: {
        walletAddress: "0x27890B4B87E5a39CA0510B32B2b2621d7D1eF7c0",
        X: "d594a7c8368d37b2ca31b55be7db1b6a6bce9a3ddbcc573d5460bc7d630024e3",
        Y: "09416f76bdbb88307900f748f0edc1cc345a9ba78c98508c8e29236d98b1d043",
      },
      finalKeyData: {
        walletAddress: "0xc53Df7C3Eb4990CfB8f903e4240dBB3BBa715A96",
        X: "c60e9fbdb820c2ea430769fce86e2fd56ac4a4e5137346d54a914d57c56cab22",
        Y: "02df3331a556d429baea94b0da05ec9438ea2ba9912af0fc4b76925531fc4629",
      },
      metadata: {
        pubNonce: {
          X: "d3edb1a89af7db7a078e73cfdb59f9be82512e8121751934122f104b28b92074",
          Y: "2a2700c2934c0a0b5cdfaeeca5a4e279fc9d46c6b6837de6f2e2f15ad39c51a3",
        },
        nonce: 0n,
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: result.nodesData,
    });
  });

  it("should be able to import a key for a new user", async function () {
    const email = faker.internet.email();
    const token = generateIdToken(email, "ES256");
    // const privKeyBuffer = new BN(generatePrivateKey(ec, Buffer));
    // key exported from phantom wallet
    const privB58 = "BjremmcjdFWexYJWcNSsT3U8ekuq6KnenBCSvxVfx2fQuvWbZQzDtQuAuXtQzcgxNY9CRyVNXJu2W5Rgt7ufQDh";
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: email });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;

    const decodedKey = base58.decode(privB58);
    const seedKey = bytesToHex(decodedKey.subarray(0, 32));
    const result = await torus.importPrivateKey(
      getImportKeyParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        nodeDetails.torusNodePub,
        TORUS_TEST_VERIFIER,
        { verifier_id: email },
        token,
        seedKey
      )
    );
    expect(result.finalKeyData.walletAddress).toBe("3TTBP4g4UZNH1Tga1D4D6tBGrXUpVXcWt1PX2W19CRqM");
    expect(result.finalKeyData.privKey).toBe(seedKey);

    const token1 = generateIdToken(email, "ES256");
    const result1 = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: email },
        token1,
        nodeDetails.torusNodePub
      )
    );
    expect(result1.finalKeyData.walletAddress).toBe("3TTBP4g4UZNH1Tga1D4D6tBGrXUpVXcWt1PX2W19CRqM");
    expect(result.finalKeyData.privKey).toBe(seedKey);

    const result2 = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, {
      verifier: TORUS_TEST_VERIFIER,
      verifierId: email,
    });
    expect(result2.finalKeyData.walletAddress).toBe("3TTBP4g4UZNH1Tga1D4D6tBGrXUpVXcWt1PX2W19CRqM");
  });

  it("should be able to login", async () => {
    const testEmail = "edd2519TestUser951@example.com";
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: testEmail });

    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;

    const token = generateIdToken(`${testEmail}`, "ES256");
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: testEmail },
        token,
        nodeDetails.torusNodePub
      )
    );

    delete result.metadata.serverTimeOffset;
    delete result.sessionData;
    expect(result).toEqual({
      oAuthKeyData: {
        X: "10249abbadc55312ce60f8a6ef522f3c1f076f5df33f0017f9d30116a5793b98",
        Y: "6e613d07eaaaec03430ff89498044a53e18317a9ab5b897d8122b51d5f86ddae",
        privKey: "08fcf6cc843ea4ad9d7b314ca57b3fdc8bccf9293d7a3fb70dd3f7ea8c506fec",
        walletAddress: "CmbriSJicm3fga5cTtwWEmZxC2eMzXbntZRt7CMNoo1w",
      },
      postboxKeyData: {
        X: "ae706aa0becae4b1d6435a42010bdc616254e136d5054bdf431a04e36068fa1c",
        Y: "c54dc56e25661c227ad5bfab26368da7fce8629f22c127b24b2c2db93a3c45f1",
        privKey: "4a0629fffdec0303b76e5e8dfabf21edd4e1957e234e180b7767453a0b301bd0",
      },
      finalKeyData: {
        X: "3c244876ef8205fdc66d4a2f6d460945a9dbdbcb149519a5fbd33a4f4b1f99ae",
        Y: "5c4c708d2b09c114f0b5c4d3a002b0c26b3d6ba49eb1e57c8e67b1ba2f3a2555",
        privKey: "7cfc7bfbf35aaf17ecf1a7fed0688eba887993dcc987a03c69ee26e2d70e5c90",
        walletAddress: "6jNaYT5c1EgYaASeBte79hSQ1m1FKq6fsAzMo8SgxpiF",
      },
      metadata: {
        pubNonce: {
          X: "6afdf51271677bc31c38ee8e540e74f2f77252814bcaf547f1038a6df620dc0f",
          Y: "1a58d067a52bd15447cbfd31cc2e8c67231e5883d245dbf03d83bb0c91d4fe68",
        },
        nonce: BigInt("0x02d19eb6bd599c6dd1473e821b1de1982f10ee7b53e9b303067e1edc42538c19"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: result.nodesData,
    });
    const result2 = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, {
      verifier: TORUS_TEST_VERIFIER,
      verifierId: testEmail,
    });
    expect(result2.finalKeyData.walletAddress).toBe(result.finalKeyData.walletAddress);
  });

  it("should be able to key assign", async () => {
    const email = faker.internet.email();
    const token = generateIdToken(email, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).not.toBe("");
    expect(result.finalKeyData.walletAddress).not.toBe(null);
    const result2 = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: email },
        token,
        nodeDetails.torusNodePub
      )
    );
    expect(result.finalKeyData.walletAddress).toBe(result2.finalKeyData.walletAddress);
  });

  it("should be able to login a new user with non dkg keys", async () => {
    const email = `${faker.internet.email()}`;
    const token = generateIdToken(email, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: email },
        token,
        nodeDetails.torusNodePub,
        {},
        false
      )
    );

    const publicResult = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);

    expect(result.finalKeyData.X).toBe(publicResult.finalKeyData.X);
  });

  it("should be able to login a new user with use dkg flag is true", async () => {
    const email = `${faker.internet.email()}`;
    const token = generateIdToken(email, "ES256");
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: email },
        token,
        nodeDetails.torusNodePub,
        {},
        true
      )
    );

    const publicResult = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);

    expect(result.finalKeyData.X).toBe(publicResult.finalKeyData.X);
  });

  it("should be able to login even when node is down", async () => {
    const token = generateIdToken(TORUS_TEST_EMAIL, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: TORUS_TEST_VERIFIER, verifierId: TORUS_TEST_EMAIL });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    torusNodeEndpoints[1] = "https://example.com";
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { verifier_id: TORUS_TEST_EMAIL },
        token,
        nodeDetails.torusNodePub
      )
    );
    expect(result.finalKeyData.privKey).toBe("ea39cc89d2d8b8403858d1c518fe82e2500cc83e472ba86d006323b57835a519");
  });

  it("should fetch pub address of tss verifier id", async () => {
    const email = TORUS_EXTENDED_VERIFIER_EMAIL;
    const nonce = 0;
    const tssTag = "default";
    const tssVerifierId = `${email}\u0015${tssTag}\u0016${nonce}`;
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email, extendedVerifierId: tssVerifierId };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    delete result.metadata.serverTimeOffset;
    expect(result).toEqual({
      oAuthKeyData: {
        walletAddress: "8YXTwFuGWc15bYSw7npC9nJpZzg3yoQpYPDe81DuKjGZ",
        X: "0a89d65e3ba433f52aa86c6b1b832501dea6200a178ec1d1f2a17d556b551cba",
        Y: "7ed3af68be167f590faec6a951c920730b760dd8f11af6a708dde3cc80421570",
      },
      finalKeyData: {
        walletAddress: "8YXTwFuGWc15bYSw7npC9nJpZzg3yoQpYPDe81DuKjGZ",
        X: "0a89d65e3ba433f52aa86c6b1b832501dea6200a178ec1d1f2a17d556b551cba",
        Y: "7ed3af68be167f590faec6a951c920730b760dd8f11af6a708dde3cc80421570",
      },
      metadata: {
        pubNonce: undefined,
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });
  });

  it("should assign key to tss verifier id", async () => {
    const email = faker.internet.email();
    const nonce = 0;
    const tssTag = "default";
    const tssVerifierId = `${email}\u0015${tssTag}\u0016${nonce}`;
    const verifierDetails = { verifier: TORUS_TEST_VERIFIER, verifierId: email, extendedVerifierId: tssVerifierId };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    expect(result.finalKeyData.walletAddress).not.toBeNull();
    expect(result.oAuthKeyData.walletAddress).not.toBeNull();
    expect(result.metadata.typeOfUser).toBe("v2");
    expect(result.metadata.nonce).toEqual(0n);
    expect(result.metadata.upgraded).toBe(false);
  });

  it("should allow test tss verifier id to fetch shares", async () => {
    const email = faker.internet.email();
    const nonce = 0;
    const tssTag = "default";
    const tssVerifierId = `${email}\u0015${tssTag}\u0016${nonce}`;
    const token = generateIdToken(email, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifierId: email, verifier: TORUS_TEST_VERIFIER });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { extended_verifier_id: tssVerifierId, verifier_id: email },
        token,
        nodeDetails.torusNodePub
      )
    );
    expect(result.finalKeyData.privKey).not.toBeNull();
    expect(result.oAuthKeyData.walletAddress).not.toBeNull();
    expect(result.metadata.typeOfUser).toBe("v2");
    expect(result.metadata.nonce).toEqual(0n);
    expect(result.metadata.upgraded).toBe(true);
    const token2 = generateIdToken(email, "ES256");

    const result2 = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_VERIFIER,
        { extended_verifier_id: tssVerifierId, verifier_id: email },
        token2,
        nodeDetails.torusNodePub
      )
    );
    expect(result.finalKeyData.privKey).toBe(result2.finalKeyData.privKey);
    expect(result.oAuthKeyData.walletAddress).toBe(result2.finalKeyData.walletAddress);
    expect(result2.metadata.typeOfUser).toBe(result.metadata.typeOfUser);
    expect(result2.metadata.upgraded).toBe(result.metadata.upgraded);

    const result3 = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, {
      verifier: TORUS_TEST_VERIFIER,
      verifierId: email,
      extendedVerifierId: tssVerifierId,
    });
    expect(result3.oAuthKeyData.walletAddress).toBe(result2.finalKeyData.walletAddress);
  });

  it("should fetch public address when verifierID hash enabled", async () => {
    const verifierDetails = { verifier: HashEnabledVerifier, verifierId: TORUS_TEST_EMAIL_HASHED };
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.getPublicAddress(torusNodeEndpoints, nodeDetails.torusNodePub, verifierDetails);
    delete result.metadata.serverTimeOffset;

    expect(result).toEqual({
      oAuthKeyData: {
        walletAddress: "DybMLmBwiPqt8GXpDW2MwHi5ZqEtrbgxgwcf7shPdTWg",
        X: "45c531429896ab89078789018b21639dab308b7d3952d9df243177e60fc0eb1f",
        Y: "6155cf9bb00f8eedf398361c2140a5ed3fe2b3c51b883e757addcb06e09bcbc0",
      },
      finalKeyData: {
        walletAddress: "HK9Xo2UgjuMNxBi6WxX76hfQm9oTtJdDUSGKFhzGQiSo",
        X: "6002549f42c1f3504652ce4b3fb1cbff4f1eaa1b66551313dd9c44d48b31a63d",
        Y: "44af643f9200d11c5f60212de9470f92806df18eeea730a8736e4570611761f2",
      },
      metadata: {
        pubNonce: {
          X: "4cc875975c4ed6fed34758eab0be8954c50decbe736f85b3c5011f5035dd9e27",
          Y: "233fe212cf0d6033be989f9dd5ffd5dfe77f0c3340984fcc5b0dd745bdfded12",
        },
        nonce: 0n,
        upgraded: false,
        typeOfUser: "v2",
      },
      nodesData: result.nodesData,
    });
  });

  it("should be able to login when verifierID hash enabled", async () => {
    const testEmail = TORUS_TEST_EMAIL_HASHED;
    const token = generateIdToken(testEmail, "ES256");
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: HashEnabledVerifier, verifierId: TORUS_TEST_EMAIL_HASHED });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        HashEnabledVerifier,
        { verifier_id: TORUS_TEST_EMAIL_HASHED },
        token,
        nodeDetails.torusNodePub
      )
    );
    delete result.metadata.serverTimeOffset;
    expect(result).toEqual({
      finalKeyData: {
        walletAddress: "HK9Xo2UgjuMNxBi6WxX76hfQm9oTtJdDUSGKFhzGQiSo",
        X: "6002549f42c1f3504652ce4b3fb1cbff4f1eaa1b66551313dd9c44d48b31a63d",
        Y: "44af643f9200d11c5f60212de9470f92806df18eeea730a8736e4570611761f2",
        privKey: "47c471c6c3b53f751e39feae967359b9258a790a30f2db394625f76b0c84ada0",
      },
      postboxKeyData: {
        X: "8a25dd3b35a77927e5f094b333ccd69a77acec89868db646e2afbf363f191b11",
        Y: "aa9282b02c5af9d06d206631ac503c218f807f0365c0a8677f6347fd01f8ffb0",
        privKey: "239c7b52e39074d8c580e3fcd2950dbd2562e8b54340d2628bac055546b6a97e",
      },
      oAuthKeyData: {
        walletAddress: "DybMLmBwiPqt8GXpDW2MwHi5ZqEtrbgxgwcf7shPdTWg",
        X: "45c531429896ab89078789018b21639dab308b7d3952d9df243177e60fc0eb1f",
        Y: "6155cf9bb00f8eedf398361c2140a5ed3fe2b3c51b883e757addcb06e09bcbc0",
        privKey: "0423cd18b36b862054489ad706d9be0226204af69b0407907dc1f3ee9ca72b7a",
      },
      sessionData: {
        sessionTokenData: result.sessionData.sessionTokenData,
        sessionAuthKey: result.sessionData.sessionAuthKey,
      },
      metadata: {
        pubNonce: {
          X: "4cc875975c4ed6fed34758eab0be8954c50decbe736f85b3c5011f5035dd9e27",
          Y: "233fe212cf0d6033be989f9dd5ffd5dfe77f0c3340984fcc5b0dd745bdfded12",
        },
        nonce: BigInt("0x8ff7137ce3f5648b8722779e0d3c153bf76042800783bd6793f38672d8c129d"),
        typeOfUser: "v2",
        upgraded: false,
      },
      nodesData: result.nodesData,
    });
  });

  // to do: update pub keys
  it.skip("should lookup return hash when verifierID hash enabled", async () => {
    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails({ verifier: HashEnabledVerifier, verifierId: TORUS_TEST_VERIFIER });
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    for (const endpoint of torusNodeEndpoints) {
      const pubKeyX = "21cd0ae3168d60402edb8bd65c58ff4b3e0217127d5bb5214f03f84a76f24d8a";
      const pubKeyY = "575b7a4d0ef9921b3b1b84f30d412e87bc69b4eab83f6706e247cceb9e985a1e";
      const response = await lookupVerifier(endpoint, pubKeyX, pubKeyY);
      const verifierID = response.result.verifiers[HashEnabledVerifier][0];
      expect(verifierID).toBe("086c23ab78578f2fce9a1da11c0071ec7c2225adb1bf499ffaee98675bee29b7");
    }
  });

  it("should be able to aggregate login", async () => {
    const email = faker.internet.email();
    const idToken = generateIdToken(email, "ES256");
    const hashedIdToken = keccak256(utf8ToBytes(idToken));
    const verifierDetails = { verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierId: email };

    const nodeDetails = await TORUS_NODE_MANAGER.getNodeDetails(verifierDetails);
    const torusNodeEndpoints = nodeDetails.torusNodeSSSEndpoints;
    const result = await torus.retrieveShares(
      getRetrieveSharesParams(
        torusNodeEndpoints,
        nodeDetails.torusIndexes,
        TORUS_TEST_AGGREGATE_VERIFIER,
        {
          verify_params: [{ verifier_id: email, idtoken: idToken }],
          sub_verifier_ids: [TORUS_TEST_VERIFIER],
          verifier_id: email,
        },
        hashedIdToken.substring(2),
        nodeDetails.torusNodePub
      )
    );
    expect(result.finalKeyData.walletAddress).not.toBeNull();
    expect(result.finalKeyData.walletAddress).not.toBe("");
    expect(result.oAuthKeyData.walletAddress).not.toBeNull();
    expect(result.metadata.typeOfUser).toBe("v2");
    expect(result.metadata.nonce).not.toBeNull();
    expect(result.metadata.upgraded).toBe(false);
  });
});
