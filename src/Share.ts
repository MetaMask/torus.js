import { bigintToHex, toBigIntBE } from "./helpers/common";
import { BigIntString, ShareJSON, StringifiedType } from "./interfaces";

class Share {
  share: bigint;

  shareIndex: bigint;

  constructor(shareIndex: BigIntString, share: BigIntString) {
    this.share = toBigIntBE(share);
    this.shareIndex = toBigIntBE(shareIndex);
  }

  static fromJSON(value: StringifiedType): Share {
    const { share, shareIndex } = value as ShareJSON;
    return new Share(shareIndex, share);
  }

  toJSON(): ShareJSON {
    return {
      share: bigintToHex(this.share),
      shareIndex: bigintToHex(this.shareIndex),
    };
  }
}

export default Share;
