import { bigintToHex, toBigIntBE } from "./helpers/common";
import { ShareJSON, StringifiedType } from "./interfaces";

class Share {
  share: bigint;

  shareIndex: bigint;

  constructor(shareIndex: bigint, share: bigint) {
    this.share = share;
    this.shareIndex = shareIndex;
  }

  static fromJSON(value: StringifiedType): Share {
    const { share, shareIndex } = value as ShareJSON;
    return new Share(toBigIntBE(shareIndex), toBigIntBE(share));
  }

  toJSON(): ShareJSON {
    return {
      share: bigintToHex(this.share),
      shareIndex: bigintToHex(this.shareIndex),
    };
  }
}

export default Share;
