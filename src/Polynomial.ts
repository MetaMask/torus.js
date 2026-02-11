import { mod } from "@noble/curves/abstract/modular.js";

import { bigintToHex, Curve } from "./helpers/common";
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

  polyEval(x: bigint): bigint {
    const n = this.ecCurve.Point.CURVE().n;
    let xi = x;
    let sum = this.polynomial[0];
    for (let i = 1; i < this.polynomial.length; i += 1) {
      const tmp = xi * this.polynomial[i];
      sum = mod(sum + tmp, n);
      xi = mod(xi * x, n);
    }
    return sum;
  }

  generateShares(shareIndexes: bigint[]): ShareMap {
    const shares: ShareMap = {};
    for (let x = 0; x < shareIndexes.length; x += 1) {
      const idx = shareIndexes[x];
      shares[bigintToHex(idx)] = new Share(idx, this.polyEval(idx));
    }
    return shares;
  }
}

export default Polynomial;
