/* eslint-disable no-underscore-dangle */

import { base64FromBytes } from '../../android/resources/proto/Resources';
import { BufferWrapper } from '../BufferWrapper';

const EOCD_MINIMUM_SIZE = 22;
const EOCD_MAGIC = 0x06054b50;

const SIGNING_BLOCK_MAGIC = 'APK Sig Block 42';
const SIGNING_BLOCK_SUFFIX_SIZE = 16 + 8;

const V2_BLOCK_ID = 0x7109871a;
const V3_BLOCK_ID = 0xf05368c0;

interface SignatureInfo {
  hasSignature: boolean;
  firstDigest?: string;
}

function noSignature(): SignatureInfo {
  return {
    hasSignature: false,
  };
}

// See:
// - https://raw.githubusercontent.com/WerWolv/ImHex-Patterns/refs/heads/master/patterns/zip.hexpat
// - https://source.android.com/docs/security/features/apksigning

export class AndroidSignatureParser {
  private _info: undefined | SignatureInfo;

  private bufferWrapper: BufferWrapper;

  constructor(buffer: Buffer, debug: boolean = false) {
    this.bufferWrapper = new BufferWrapper(buffer, debug);
  }

  private parse(): SignatureInfo {
    const end = this.bufferWrapper.buffer.length;
    const canRead = (bytes: number): boolean => {
      return this.bufferWrapper.cursor >= 0 && this.bufferWrapper.cursor + bytes <= end;
    };

    // EoCD is a minimum of 22 bytes (and will normally be eactly 22
    // bytes) but can be longer if there is a zip comment.
    let foundEndOfCentralDirectory = false;
    for (let i = EOCD_MINIMUM_SIZE; i < 2 ** 16 && end - i >= 0; ++i) {
      this.bufferWrapper.cursor = end - i;
      const endOfCentralDirectoryMagic = this.bufferWrapper.readU32();
      if (endOfCentralDirectoryMagic === EOCD_MAGIC) {
        foundEndOfCentralDirectory = true;
        break;
      }
    }

    if (!foundEndOfCentralDirectory) {
      return noSignature();
    }

    // Cursor should now be at the 'diskNum' field. Read forwards 12
    // bytes to get to CDOffset.
    this.bufferWrapper.cursor += 12;
    if (!canRead(4)) {
      return noSignature();
    }
    const cdOffset = this.bufferWrapper.readU32();

    // Move cursor to start of CentralDirectory:
    this.bufferWrapper.cursor = cdOffset;
    // Move cursor back to the signing block suffix.
    this.bufferWrapper.cursor -= SIGNING_BLOCK_SUFFIX_SIZE;
    if (!canRead(SIGNING_BLOCK_SUFFIX_SIZE)) {
      return noSignature();
    }
    const endOfPairs = this.bufferWrapper.cursor;
    const signatureBlockSize = this.bufferWrapper.readU64();
    const signatureBlockMagic = this.bufferWrapper.readStringWithLength(16);
    if (signatureBlockMagic !== SIGNING_BLOCK_MAGIC) {
      return noSignature();
    }

    this.bufferWrapper.cursor -= Number(signatureBlockSize);

    let firstDigest: string | undefined;

    while (canRead(8) && this.bufferWrapper.cursor < endOfPairs) {
      const id = this.bufferWrapper.readU32();
      const size = this.bufferWrapper.readU32();
      const endOfPair = this.bufferWrapper.cursor + size;

      if (id === V2_BLOCK_ID || id === V3_BLOCK_ID) {
        while (canRead(8) && this.bufferWrapper.cursor < endOfPair) {
          const signerSize = this.bufferWrapper.readU32();
          const signerEnd = signerSize + this.bufferWrapper.cursor;

          const signedDataSize = this.bufferWrapper.readU32();
          const signedDataEnd = signedDataSize + this.bufferWrapper.cursor;

          const digestsSize = this.bufferWrapper.readU32();
          const digestsEnd = digestsSize + this.bufferWrapper.cursor;

          while (this.bufferWrapper.cursor < digestsEnd) {
            const digestSize = this.bufferWrapper.readU32();
            const digestEnd = digestSize + this.bufferWrapper.cursor;

            // signatureAlgorithmId
            this.bufferWrapper.readU32();
            const digestLength = this.bufferWrapper.readU32();
            if (digestLength === 32 || digestLength === 64) {
              const digest = this.bufferWrapper.slice(digestLength);
              if (firstDigest === undefined) {
                firstDigest = base64FromBytes(digest);
              }
            }

            this.bufferWrapper.cursor = digestEnd;
          }

          this.bufferWrapper.cursor = digestsEnd;
          this.bufferWrapper.cursor = signedDataEnd;
          this.bufferWrapper.cursor = signerEnd;
        }
      }

      this.bufferWrapper.cursor = endOfPair;
    }

    return {
      hasSignature: true,
      firstDigest,
    };
  }

  private getInfo(): SignatureInfo {
    if (this._info !== undefined) {
      return this._info;
    }
    const info = this.parse();
    this._info = info;
    return info;
  }

  hasSignature(): boolean {
    return this.getInfo().hasSignature;
  }

  firstDigest(): string | undefined {
    return this.getInfo().firstDigest;
  }
}
