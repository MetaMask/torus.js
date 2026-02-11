import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { concatBytes, hexToBytes, numberToBytesBE } from "@noble/curves/utils.js";

import { toBigIntBE } from "./helpers/common";
import { BigIntString, KeyType } from "./interfaces";

class Point {
  x: bigint;

  y: bigint;

  keyType: KeyType;

  constructor(x: BigIntString, y: BigIntString, keyType: KeyType) {
    this.x = toBigIntBE(x);
    this.y = toBigIntBE(y);
    this.keyType = keyType;
  }

  encode(enc: string): Uint8Array {
    switch (enc) {
      case "arr":
        return concatBytes(hexToBytes("04"), numberToBytesBE(this.x, 32), numberToBytesBE(this.y, 32));
      case "elliptic-compressed": {
        if (this.keyType === "secp256k1") {
          const point = secp256k1.Point.fromAffine({ x: this.x, y: this.y });
          return point.toBytes();
        }
        // ed25519: standard compressed encoding (y in LE + x sign bit)
        const point = ed25519.Point.fromAffine({ x: this.x, y: this.y });
        return point.toBytes();
      }
      default:
        throw new Error("encoding doesn't exist in Point");
    }
  }
}

export default Point;
