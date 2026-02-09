import { invert, mod } from "@noble/curves/abstract/modular.js";

import { KeyType } from "../interfaces";
import Point from "../Point";
import Polynomial from "../Polynomial";
import Share from "../Share";
import { bigintToHex, bytesToNumberBE, Curve, generatePrivateKey } from "./common";

function generatePrivateExcludingIndexes(shareIndexes: bigint[], keyType: KeyType): bigint {
  const key = bytesToNumberBE(generatePrivateKey(keyType));
  if (shareIndexes.find((el) => el === key)) {
    return generatePrivateExcludingIndexes(shareIndexes, keyType);
  }
  return key;
}

const generateEmptyBigIntArray = (length: number): bigint[] => Array.from({ length }, () => 0n);

const denominator = (ecCurve: Curve, i: number, innerPoints: Point[]) => {
  const n = ecCurve.Point.CURVE().n;
  let result = 1n;
  const xi = innerPoints[i].x;
  for (let j = innerPoints.length - 1; j >= 0; j -= 1) {
    if (i !== j) {
      let tmp = xi - innerPoints[j].x;
      tmp = mod(tmp, n);
      result = mod(result * tmp, n);
    }
  }
  return result;
};

const interpolationPoly = (ecCurve: Curve, i: number, innerPoints: Point[]): bigint[] => {
  const n = ecCurve.Point.CURVE().n;
  let coefficients = generateEmptyBigIntArray(innerPoints.length);
  const d = denominator(ecCurve, i, innerPoints);
  if (d === 0n) {
    throw new Error("Denominator for interpolationPoly is 0");
  }
  coefficients[0] = invert(d, n);
  for (let k = 0; k < innerPoints.length; k += 1) {
    const newCoefficients = generateEmptyBigIntArray(innerPoints.length);
    if (k !== i) {
      let j: number;
      if (k < i) {
        j = k + 1;
      } else {
        j = k;
      }
      j -= 1;
      for (; j >= 0; j -= 1) {
        newCoefficients[j + 1] = mod(newCoefficients[j + 1] + coefficients[j], n);
        const tmp = mod(innerPoints[k].x * coefficients[j], n);
        newCoefficients[j] = mod(newCoefficients[j] - tmp, n);
      }
      coefficients = newCoefficients;
    }
  }
  return coefficients;
};

const pointSort = (innerPoints: Point[]): Point[] => {
  const pointArrClone = [...innerPoints];
  pointArrClone.sort((a, b) => (a.x < b.x ? -1 : a.x > b.x ? 1 : 0));
  return pointArrClone;
};

const lagrange = (ecCurve: Curve, unsortedPoints: Point[]) => {
  const n = ecCurve.Point.CURVE().n;
  const sortedPoints = pointSort(unsortedPoints);
  const polynomial = generateEmptyBigIntArray(sortedPoints.length);
  for (let i = 0; i < sortedPoints.length; i += 1) {
    const coefficients = interpolationPoly(ecCurve, i, sortedPoints);
    for (let k = 0; k < sortedPoints.length; k += 1) {
      const tmp = sortedPoints[i].y * coefficients[k];
      polynomial[k] = mod(polynomial[k] + tmp, n);
    }
  }
  return new Polynomial(polynomial, n);
};

export function lagrangeInterpolatePolynomial(ecCurve: Curve, points: Point[]): Polynomial {
  return lagrange(ecCurve, points);
}

export function lagrangeInterpolation(ecCurve: Curve, shares: bigint[], nodeIndex: bigint[]): bigint {
  if (shares.length !== nodeIndex.length) {
    throw new Error("shares not equal to nodeIndex length in lagrangeInterpolation");
  }
  const n = ecCurve.Point.CURVE().n;
  let secret = 0n;
  for (let i = 0; i < shares.length; i += 1) {
    let upper = 1n;
    let lower = 1n;
    for (let j = 0; j < shares.length; j += 1) {
      if (i !== j) {
        upper = mod(upper * -nodeIndex[j], n);
        let temp = nodeIndex[i] - nodeIndex[j];
        temp = mod(temp, n);
        lower = mod(lower * temp, n);
      }
    }
    let delta = mod(upper * invert(lower, n), n);
    delta = mod(delta * shares[i], n);
    secret = secret + delta;
  }
  return mod(secret, n);
}

// generateRandomPolynomial - determinisiticShares are assumed random
export function generateRandomPolynomial(
  ecCurve: Curve,
  keyType: KeyType,
  degree: number,
  secret?: bigint,
  deterministicShares?: Share[]
): Polynomial {
  const n = ecCurve.Point.CURVE().n;
  const actualS = secret !== undefined ? secret : generatePrivateExcludingIndexes([0n], keyType);
  if (!deterministicShares) {
    const poly: bigint[] = [actualS];
    for (let i = 0; i < degree; i += 1) {
      const share = generatePrivateExcludingIndexes(poly, keyType);
      poly.push(share);
    }
    return new Polynomial(poly, n);
  }
  if (!Array.isArray(deterministicShares)) {
    throw new Error("deterministic shares in generateRandomPolynomial should be an array");
  }

  if (deterministicShares.length > degree) {
    throw new Error("deterministicShares in generateRandomPolynomial should be less or equal than degree to ensure an element of randomness");
  }
  const points: Record<string, Point> = {};
  deterministicShares.forEach((share) => {
    points[bigintToHex(share.shareIndex)] = new Point(share.shareIndex, share.share, keyType);
  });
  for (let i = 0; i < degree - deterministicShares.length; i += 1) {
    let shareIndex = generatePrivateExcludingIndexes([0n], keyType);
    while (points[bigintToHex(shareIndex)] !== undefined) {
      shareIndex = generatePrivateExcludingIndexes([0n], keyType);
    }
    points[bigintToHex(shareIndex)] = new Point(shareIndex, bytesToNumberBE(generatePrivateKey(keyType)), keyType);
  }
  points["0"] = new Point(0n, actualS, keyType);
  return lagrangeInterpolatePolynomial(ecCurve, Object.values(points));
}
