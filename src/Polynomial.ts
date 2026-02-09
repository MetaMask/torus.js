import { mod } from "@noble/curves/abstract/modular.js";

import { bigintToHex, Curve, toBigIntBE } from "./helpers/common";
import { BigIntString } from "./interfaces";
import Share from "./Share";

export type ShareMap = {
  [x: string]: Share;
};

class Polynomial {
  polynomial: bigint[];

  ecCurve: Curve;

  constructor(polynomial: bigint[], ecCurve: Curve) {
    this.polynomial = polynomial;
    this.ecCurve = ecCurve;
  }

  getThreshold(): number {
    return this.polynomial.length;
  }

  polyEval(x: BigIntString): bigint {
    const n = this.ecCurve.Point.CURVE().n;
    const tmpX = toBigIntBE(x);
    let xi = tmpX;
    let sum = this.polynomial[0];
    for (let i = 1; i < this.polynomial.length; i += 1) {
      const tmp = xi * this.polynomial[i];
      sum = mod(sum + tmp, n);
      xi = mod(xi * tmpX, n);
    }
    return sum;
  }

  generateShares(shareIndexes: BigIntString[]): ShareMap {
    const newShareIndexes = shareIndexes.map((index) => {
      if (typeof index === "number") {
        return BigInt(index);
      }
      if (typeof index === "bigint") {
        return index;
      }
      if (typeof index === "string") {
        return toBigIntBE(index);
      }
      return index;
    });

    const shares: ShareMap = {};
    for (let x = 0; x < newShareIndexes.length; x += 1) {
      shares[bigintToHex(newShareIndexes[x])] = new Share(newShareIndexes[x], this.polyEval(newShareIndexes[x]));
    }
    return shares;
  }
}

export default Polynomial;
