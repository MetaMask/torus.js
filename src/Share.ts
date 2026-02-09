import { bigintToHex, toBigIntBE } from "./helpers/common";
import { BigIntString, StringifiedType } from "./interfaces";

class Share {
  share: bigint;

  shareIndex: bigint;

  constructor(shareIndex: BigIntString, share: BigIntString) {
    this.share = toBigIntBE(share);
    this.shareIndex = toBigIntBE(shareIndex);
  }

  static fromJSON(value: StringifiedType): Share {
    const { share, shareIndex } = value;
    return new Share(shareIndex as BigIntString, share as BigIntString);
  }

  toJSON(): StringifiedType {
    return {
      share: bigintToHex(this.share),
      shareIndex: bigintToHex(this.shareIndex),
    };
  }
}

export default Share;
