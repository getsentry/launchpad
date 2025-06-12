import { fromBER } from 'asn1js';
import { createHash } from 'crypto';
import { Certificate, ContentInfo, SignedData } from 'pkijs';
import { stringify } from '../../utils/stringify';
import { BufferWrapper } from '../BufferWrapper';
import {
  BoundSymbol,
  CMSSigning,
  CSAlgorithm,
  CSCodeDirectory,
  CSSlot,
  CSSuperBlob,
  CodeDirectory,
  CodesignInformation,
  DEREntitlements,
  Entitlements,
  LoadCommand,
  LoadCommands,
  MachO64Header,
  MachOSection64,
  ProtocolConformanceDescriptor,
  Requirements,
  SegmentCommand64,
} from './MachOParserTypes';

/* eslint-disable no-bitwise */

const LoadCommandsReverseLookup: { [key: number]: string } = Object.entries(LoadCommands).reduce(
  (acc, [key, value]) => {
    if (typeof value === 'number') {
      const unsignedValue = value >>> 0; // Force unsigned 32-bit interpretation
      acc[unsignedValue] = key;
    }
    return acc;
  },
  {} as { [key: number]: string },
);

const BIND_IMMEDIATE_MASK = 0x0f;
const BIND_OPCODE_MASK = 0xf0;
const BIND_OPCODE_DONE = 0x00;
const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10;
const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20;
const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30;
const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40;
const BIND_OPCODE_SET_TYPE_IMM = 0x50;
const BIND_OPCODE_SET_ADDEND_SLEB = 0x60;
const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70;
const BIND_OPCODE_ADD_ADDR_ULEB = 0x80;
const BIND_OPCODE_DO_BIND = 0x90;
const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xa0;
const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xb0;
const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xc0;

export class MachOParser {
  bufferWrapper: BufferWrapper;

  private loadCommands: LoadCommand[] = [];

  private importedSymbols: string[] | null = null;

  private boundSymbols: { name: string; address: bigint }[] | null = null;

  usesChainedFixups: boolean = false;

  isFatFile: boolean = false;

  private encryptionResult: boolean | undefined = undefined;

  private fileStart: number = 0;

  constructor(buffer: Buffer) {
    this.bufferWrapper = new BufferWrapper(buffer);
  }

  fatCursor(): number {
    return this.bufferWrapper.cursor - this.fileStart;
  }

  setFatCursor(offset: number) {
    this.bufferWrapper.seek(this.fileStart + offset);
  }

  swap32(val: number): number {
    return ((val & 0xff) << 24) | ((val & 0xff00) << 8) | ((val >> 8) & 0xff00) | ((val >> 24) & 0xff);
  }

  parseHeader() {
    this.bufferWrapper.seek(0);
    this.fileStart = 0;
    const magic = this.bufferWrapper.readU32();
    if (magic === 0xcafebabe || magic === 0xbebafeca) {
      this.isFatFile = true;
      let nFatArch = this.bufferWrapper.readU32();
      const requiresReverse = magic === 0xbebafeca;
      if (requiresReverse) {
        nFatArch = this.swap32(nFatArch);
      }
      for (let i = 0; i < nFatArch; i++) {
        let cpuType = this.bufferWrapper.readS32();
        if (requiresReverse) {
          cpuType = this.swap32(cpuType);
        }
        // subtype
        this.bufferWrapper.readS32();
        const offset = this.bufferWrapper.readU32();
        // size
        this.bufferWrapper.readU32();
        // align
        this.bufferWrapper.readU32();
        if (cpuType === (12 | 0x01000000)) {
          if (requiresReverse) {
            this.fileStart = this.swap32(offset);
          } else {
            this.fileStart = offset;
          }
        }
      }
    }
    this.setFatCursor(0);
    const header: MachO64Header = {
      magic: this.bufferWrapper.readU32(),
      cputype: this.bufferWrapper.readS32(),
      cpusubtype: this.bufferWrapper.readS32(),
      filetype: this.bufferWrapper.readU32(),
      ncmds: this.bufferWrapper.readU32(),
      sizeofcmds: this.bufferWrapper.readU32(),
      flags: this.bufferWrapper.readU32(),
      reserved: this.bufferWrapper.readU32(),
    };
    return header;
  }

  parseLoadCommands(): LoadCommand[] {
    if (this.loadCommands.length) {
      return this.loadCommands;
    }

    const loadCommands: Array<LoadCommand> = [];
    const header = this.parseHeader();
    const magic = header.magic;
    const is64Bit = magic === 0xfeedfacf || magic === 0xcffaedfe;

    // TODO(telkins): use the actual header size
    this.setFatCursor(is64Bit ? 32 : 28);

    for (let i = 0; i < header.ncmds; i++) {
      this.bufferWrapper.logDebug(`Parsing load command at offset ${this.bufferWrapper.cursor}`);

      const currentOffset = this.fatCursor();
      const cmd = this.bufferWrapper.readU32();
      const cmdSize = this.bufferWrapper.readU32();

      let loadCommand: LoadCommand;
      switch (cmd) {
        case LoadCommands.LC_SEGMENT_64: {
          loadCommand = this.parseSegmentCommand64({ cmd, cmdSize, currentOffset });
          break;
        }
        case LoadCommands.LC_UUID: {
          loadCommand = this.parseUUID({ cmd, cmdSize, currentOffset });
          break;
        }
        default: {
          loadCommand = {
            cmd,
            name: LoadCommandsReverseLookup[cmd],
            cmdSize,
            offset: currentOffset,
          };
          break;
        }
      }

      this.bufferWrapper.logDebug(`Parsed load command: ${stringify(loadCommand)}`);
      loadCommands.push(loadCommand);

      this.setFatCursor(currentOffset + cmdSize);
    }

    this.loadCommands = loadCommands;
    return loadCommands;
  }

  parseImportedSymbols() {
    if (this.importedSymbols) {
      return this.importedSymbols;
    }

    this.parseLoadCommands();
    this.importedSymbols = [];
    this.boundSymbols = [];
    this.parseChainedFixups();
    this.parseDyldInfoOnly();
  }

  parseDyldInfoOnly() {
    const dyldInfo = this.loadCommands.find((lc) => {
      return lc.cmd === LoadCommands.LC_DYLD_INFO_ONLY >>> 0;
    });
    if (!dyldInfo) {
      return;
    }

    this.setFatCursor(dyldInfo.offset);
    // cmd
    this.bufferWrapper.readU32();
    // cmdSize
    this.bufferWrapper.readU32();
    // Rebase off
    this.bufferWrapper.readU32();
    // Rebase size
    this.bufferWrapper.readU32();
    const bindOff = this.bufferWrapper.readU32();
    const bindSize = this.bufferWrapper.readU32();
    const current = { segmentOffset: 0, library: 0, offset: 0, symbol: '' };
    this.setFatCursor(bindOff);
    while (this.fatCursor() < bindOff + bindSize) {
      const symbols = this.readBoundSymbol(current, bindOff + bindSize);
      for (const s of symbols) {
        const vmStart = (this.loadCommands[s.segmentOffset] as SegmentCommand64).vmaddr;
        const address = vmStart + BigInt(s.offset);
        this.boundSymbols?.push({
          name: s.symbol,
          address: address,
        });
      }
    }
  }

  readNullTerminated(offset: number): string {
    let str = '';
    const buf = this.bufferWrapper.buffer;
    let pos = offset;
    while (pos < buf.length && buf[pos] !== 0) {
      str += String.fromCharCode(buf[pos]);
      pos++;
    }
    return str;
  }

  readBoundSymbol(current: BoundSymbol, endPointer: number): BoundSymbol[] {
    while (this.fatCursor() < endPointer) {
      const firstByte = this.bufferWrapper.readU8();
      const immediate = firstByte & BIND_IMMEDIATE_MASK;
      const opcode = firstByte & BIND_OPCODE_MASK;
      switch (opcode) {
        case BIND_OPCODE_DONE: {
          const ret = { ...current };
          current.segmentOffset = 0;
          current.library = 0;
          current.offset = 0;
          current.symbol = '';
          return [ret];
        }
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
          current.library = immediate;
          break;
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
          current.symbol = this.bufferWrapper.readStringNullTerminated();
          break;
        }
        case BIND_OPCODE_ADD_ADDR_ULEB: {
          const off = this.bufferWrapper.readUleb128Bigint();
          current.offset = Number((BigInt(current.offset) + off) & BigInt(Number.MAX_SAFE_INTEGER));
          break;
        }
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
          const o = this.bufferWrapper.readUleb128Bigint();
          const r = { ...current };
          current.offset = Number((BigInt(current.offset) + (o + BigInt(8))) & BigInt(Number.MAX_SAFE_INTEGER));
          return [r];
        }
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
          const offset = this.bufferWrapper.readUleb128Bigint();
          current.segmentOffset = immediate;
          current.offset = Number(offset);
          break;
        }
        case BIND_OPCODE_SET_ADDEND_SLEB: {
          this.bufferWrapper.readUleb128Bigint();
          break;
        }
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: {
          const re = { ...current };
          current.offset = current.offset + immediate * 8 + 8;
          return [re];
        }
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
          const c = this.bufferWrapper.readUleb128Bigint();
          const skipping = this.bufferWrapper.readUleb128Bigint();
          const results: BoundSymbol[] = [];
          for (let i = 0; i < c; i++) {
            results.push({ ...current });
            current.offset += Number((skipping + BigInt(8)) & BigInt(Number.MAX_SAFE_INTEGER));
          }
          return results;
        }
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: {
          current.library = Number(this.bufferWrapper.readUleb128Bigint());
          break;
        }
        case BIND_OPCODE_DO_BIND: {
          const result = { ...current };
          current.offset += 8;
          return [result];
        }
        case BIND_OPCODE_SET_TYPE_IMM:
          break;
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
          break;
        default:
          break;
      }
    }
    return [];
  }

  parseChainedFixups() {
    const chainedFixups = this.loadCommands.find((lc) => {
      return lc.cmd === LoadCommands.LC_DYLD_CHAINED_FIXUPS >>> 0;
    });
    if (!chainedFixups) {
      return;
    }

    this.usesChainedFixups = true;

    this.setFatCursor(chainedFixups.offset);

    this.bufferWrapper.readU32();
    this.bufferWrapper.readU32();
    const headerStart = this.bufferWrapper.readU32();
    this.setFatCursor(headerStart);

    // fixupsVersion
    this.bufferWrapper.readU32();
    // startsOffset
    this.bufferWrapper.readU32();
    const importsOffset = this.bufferWrapper.readU32();
    const symbolsOffset = this.bufferWrapper.readU32();
    const importsCount = this.bufferWrapper.readU32();
    const importsFormat = this.bufferWrapper.readU32();
    // symbolsFormat
    this.bufferWrapper.readU32();

    const importsStart = headerStart + importsOffset;
    const symbolsStart = headerStart + symbolsOffset;
    this.setFatCursor(symbolsStart);

    let importsSize = 4;
    // TODO: More steps to handling these formats
    switch (importsFormat) {
      case 2:
        importsSize = 4 * 2;
        break;
      case 3:
        importsSize = 4 * 2;
        break;
      default:
        break;
    }
    this.setFatCursor(symbolsStart);
    for (let i = 0; i < importsCount; i++) {
      this.setFatCursor(importsStart + i * importsSize);
      const nameOffset = this.bufferWrapper.readU32();
      this.setFatCursor(symbolsStart + (nameOffset >> 9));
      this.importedSymbols?.push(this.bufferWrapper.readStringNullTerminated());
    }
  }

  parseSwiftProtocolConformances(): string[] {
    const swiftProtocols: string[] = [];
    const loadCommands = this.parseLoadCommands();
    if (this.isEncrypted()) {
      return swiftProtocols;
    }

    this.parseImportedSymbols();
    const segments = loadCommands
      .filter((lc) => lc.name === 'LC_SEGMENT_64' && 'sections' in lc)
      .flatMap((lc) => (lc as SegmentCommand64).sections ?? []);
    const swiftProtoSection = segments.find((lc) => lc.sectname === '__swift5_proto');
    if (!swiftProtoSection) {
      console.log('No swift protocol section found');
      return swiftProtocols;
    }

    this.setFatCursor(swiftProtoSection.offset);

    // The Swift proto section contains a list of offsets to protocol conformance descriptors
    const offsetsList = this.parseIntsFromSection('Int32', swiftProtoSection.offset, swiftProtoSection.size);

    for (const { value: relativePointer, offset } of offsetsList) {
      const typeFileAddress = relativePointer + offset;
      if (typeFileAddress < 0 || typeFileAddress >= this.bufferWrapper.buffer.length) {
        console.log('Invalid protocol conformance offset');
        continue;
      }
      const proto = this.loadProtocolConformance(typeFileAddress);
      if (proto) {
        swiftProtocols.push(proto);
      }
    }
    return swiftProtocols;
  }

  // Returns the VM address
  readIndirectPointer() {
    const vm = this.vmAddress(BigInt(this.fatCursor())) ?? 0;
    const offset = this.bufferWrapper.readS32();
    this.bufferWrapper.skip(4);
    if (offset % 2 === 1) {
      const file = this.fileOffset(BigInt(vm + (offset & ~0x1)));
      return this.bufferWrapper.buffer.readBigUint64LE(this.fileStart + (file ?? 0));
    } else {
      return BigInt(vm + offset);
    }
  }

  loadProtocolConformance(typeFileAddress: number) {
    this.setFatCursor(typeFileAddress);
    const conformanceDescriptor: ProtocolConformanceDescriptor = {
      protocolDescriptor: this.readIndirectPointer(),
      nominalTypeDescriptor: this.bufferWrapper.readS32(),
      protocolWitnessTable: this.bufferWrapper.readS32(),
      conformanceFlags: this.bufferWrapper.readU32(),
    };
    const protocolFileOffset = this.fileOffset(BigInt(conformanceDescriptor.protocolDescriptor));
    if (!protocolFileOffset && this.importedSymbols && this.usesChainedFixups) {
      const ordinal = conformanceDescriptor.protocolDescriptor & BigInt(0xffffff);
      if (
        conformanceDescriptor.protocolDescriptor >> BigInt(63) === BigInt(1) &&
        ordinal < this.importedSymbols?.length
      ) {
        return this.importedSymbols[Number(ordinal)];
      }
    } else if (!protocolFileOffset && this.importedSymbols) {
      const offset = this.bufferWrapper.buffer.readInt32LE(this.fileStart + typeFileAddress);
      const vm = this.vmAddress(BigInt(typeFileAddress)) ?? 0;
      this.bufferWrapper.skip(4);
      if (offset % 2 === 1) {
        const indirectVM = BigInt(vm + (offset & ~0x1));
        for (const s of this.boundSymbols ?? []) {
          if (s.address === indirectVM) {
            return s.name;
          }
        }
        console.log('Could not find bound symbol');
      }
    }
    return null;
  }

  vmAddress(fileOffset: bigint): number | null {
    for (const loadCommand of this.loadCommands) {
      if (fileOffset >= BigInt(loadCommand.offset) && fileOffset < BigInt(loadCommand.offset + loadCommand.cmdSize)) {
        return null;
      }
      for (const section of (loadCommand as SegmentCommand64).sections ?? []) {
        if (fileOffset >= BigInt(section.offset) && fileOffset < BigInt(section.offset) + section.size) {
          return Number(section.addr) + Number(fileOffset - BigInt(section.offset));
        }
      }
    }
    return null;
  }

  fileOffset(vmAddress: bigint): number | null {
    for (const loadCommand of this.loadCommands) {
      if (vmAddress >= BigInt(loadCommand.offset) && vmAddress < BigInt(loadCommand.offset + loadCommand.cmdSize)) {
        return null;
      }
      for (const section of (loadCommand as SegmentCommand64).sections ?? []) {
        if (vmAddress >= BigInt(section.addr) && vmAddress < BigInt(section.addr) + section.size) {
          return Number(section.offset) + Number(vmAddress - BigInt(section.addr));
        }
      }
    }
    return null;
  }

  relativeOffset(value: number, from: number, canBeIndirect: boolean = true): number | null {
    if (canBeIndirect && value % 2 === 1) {
      const offset = value & ~1;
      // TODO: Use the result of this offset to mark the Uint64 in the binary which is the vm address of the pointee
      const result = from + offset;
      // TODO: mark the indirect pointer as used
      // The result would be outside this binary
      return result;
    } else {
      const result = from + value;
      if (result > 0) {
        return result;
      } else {
        return null;
      }
    }
  }

  parseIntsFromSection(
    type: 'UInt8' | 'UInt16' | 'UInt32' | 'Int32',
    start: number,
    size: bigint,
  ): Array<{ value: number; offset: number }> {
    this.setFatCursor(start);

    const result: Array<{ value: number; offset: number }> = [];
    while (this.fatCursor() < BigInt(start) + size) {
      let value: number;
      const currentOffset = this.fatCursor();

      switch (type) {
        case 'UInt8':
          value = this.bufferWrapper.readU8();
          break;
        case 'UInt16':
          value = this.bufferWrapper.readU16();
          break;
        case 'UInt32':
          value = this.bufferWrapper.readU32();
          break;
        case 'Int32':
          value = this.bufferWrapper.readS32();
          break;
        default:
          throw new Error(`Unsupported type: ${type}`);
      }

      result.push({ value, offset: currentOffset });
    }

    return result;
  }

  isEncrypted(): boolean {
    if (this.encryptionResult !== undefined) {
      return this.encryptionResult;
    }

    // Ensure the load commands are parsed already
    this.parseLoadCommands();
    const encryptionInfo = this.loadCommands.find((lc) => lc.cmd === LoadCommands.LC_ENCRYPTION_INFO_64);
    if (!encryptionInfo) {
      return false;
    }

    this.setFatCursor(encryptionInfo.offset);
    // cmd
    this.bufferWrapper.readU32();
    // cmdSize
    this.bufferWrapper.readU32();
    // cryptOff
    this.bufferWrapper.readU32();
    // cryptSize
    this.bufferWrapper.readU32();
    const cryptId = this.bufferWrapper.readU32();
    this.encryptionResult = cryptId !== 0;

    return this.encryptionResult;
  }

  parseCodeSignature(): CodesignInformation | null {
    this.parseLoadCommands();

    // Find the code signature load command
    const parsedData = this.parseCodeSignatureCommand();
    if (!parsedData) {
      return null;
    }
    const { superBlob, baseOffset } = parsedData;

    const codeDirectory = this.parseCodeDirectory(superBlob, baseOffset);
    const entitlements = this.parseEntitlements(superBlob, baseOffset, codeDirectory?.hashType ?? CSAlgorithm.SHA256);
    const requirements = this.parseRequirements(superBlob, baseOffset, codeDirectory?.hashType ?? CSAlgorithm.SHA256);
    const derEntitlements = this.parseDEREntitlements(
      superBlob,
      baseOffset,
      codeDirectory?.hashType ?? CSAlgorithm.SHA256,
    );
    const cmsSigning = this.parseSignature(superBlob, baseOffset);

    return {
      codeDirectory,
      entitlements,
      requirements,
      derEntitlements,
      cmsSigning,
    };
  }

  private parseSegmentCommand64(params: { cmd: number; cmdSize: number; currentOffset: number }): SegmentCommand64 {
    const segname = this.bufferWrapper.readStringWithLength(16);
    const vmaddr = this.bufferWrapper.readU64();
    const vmsize = this.bufferWrapper.readU64();
    const fileoff = this.bufferWrapper.readU64();
    const filesize = this.bufferWrapper.readU64();
    const maxprot = this.bufferWrapper.readU32();
    const initprot = this.bufferWrapper.readU32();
    const nsects = this.bufferWrapper.readU32();
    const flags = this.bufferWrapper.readU32();
    const sections: MachOSection64[] = [];
    for (let i = 0; i < nsects; i++) {
      sections.push(this.parseSection());
    }
    return {
      cmd: params.cmd,
      name: LoadCommandsReverseLookup[params.cmd],
      cmdSize: params.cmdSize,
      offset: params.currentOffset,
      segname,
      vmaddr,
      vmsize,
      fileoff,
      filesize,
      maxprot,
      initprot,
      nsects,
      flags,
      sections,
    };
  }

  private parseSection(): MachOSection64 {
    const sectname = this.bufferWrapper.readStringWithLength(16);
    const segname = this.bufferWrapper.readStringWithLength(16);
    const addr = this.bufferWrapper.readU64();
    const size = this.bufferWrapper.readU64();
    const offset = this.bufferWrapper.readU32();
    const align = this.bufferWrapper.readU32();
    const reloff = this.bufferWrapper.readU32();
    const nreloc = this.bufferWrapper.readU32();
    const flags = this.bufferWrapper.readU32();
    const reserved1 = this.bufferWrapper.readU32();
    const reserved2 = this.bufferWrapper.readU32();
    const reserved3 = this.bufferWrapper.readU32();
    return {
      sectname,
      segname,
      addr,
      size,
      offset,
      align,
      reloff,
      nreloc,
      flags,
      reserved1,
      reserved2,
      reserved3,
    };
  }

  private parseUUID(params: { cmd: number; cmdSize: number; currentOffset: number }): LoadCommand {
    const { cmd, cmdSize, currentOffset } = params;

    let uuid = '';
    for (let i = 0; i < 16; i++) {
      const val = this.bufferWrapper.readU8();
      uuid += val.toString(16).padStart(2, '0');
    }

    // Format UUID
    uuid = uuid.toUpperCase();
    uuid = `${uuid.slice(0, 8)}-${uuid.slice(8, 12)}-${uuid.slice(12, 16)}-${uuid.slice(16, 20)}-${uuid.slice(20)}`;

    return {
      cmd: cmd,
      name: LoadCommandsReverseLookup[cmd],
      cmdSize: cmdSize,
      offset: currentOffset,
      uuid: uuid,
    };
  }

  private parseCodeSignatureCommand(): { superBlob: CSSuperBlob; baseOffset: number } | null {
    const codeSignatureCmd = this.loadCommands.find((lc) => lc.cmd === LoadCommands.LC_CODE_SIGNATURE);
    if (!codeSignatureCmd) {
      this.bufferWrapper.logDebug('No code signature load command found');
      return null;
    }

    this.setFatCursor(codeSignatureCmd.offset);
    // cmd
    this.bufferWrapper.readU32();
    // cmdSize
    this.bufferWrapper.readU32();
    const dataOffset = this.bufferWrapper.readU32();
    const dataSize = this.bufferWrapper.readU32();
    this.bufferWrapper.logDebug(`Data offset: ${dataOffset}, Data size: ${dataSize}`);

    this.setFatCursor(dataOffset);

    // Read the SuperBlob header
    const superBlob: CSSuperBlob = {
      magic: this.bufferWrapper.readU32BE(),
      length: this.bufferWrapper.readU32BE(),
      count: this.bufferWrapper.readU32BE(),
      index: [],
    };
    this.bufferWrapper.logDebug(
      `Superblob magic: ${superBlob.magic}, Superblob length: ${superBlob.length}, Superblob count: ${superBlob.count}`,
    );

    // Read the blob indices
    for (let i = 0; i < superBlob.count; i++) {
      superBlob.index.push({
        type: this.bufferWrapper.readU32BE(),
        offset: this.bufferWrapper.readU32BE(),
      });
    }

    return { superBlob, baseOffset: dataOffset };
  }

  private parseCodeDirectory(superBlob: CSSuperBlob, baseOffset: number): CodeDirectory | null {
    let codeDirectoryIndex = superBlob.index.find((index) => index.type === CSSlot.CSSLOT_ALTERNATE_CODEDIRECTORIES);
    if (!codeDirectoryIndex) {
      codeDirectoryIndex = superBlob.index.find((index) => index.type === CSSlot.CSSLOT_CODEDIRECTORY);
    }
    if (!codeDirectoryIndex) {
      return null;
    }

    this.bufferWrapper.logDebug(
      `Code directory index type: ${codeDirectoryIndex.type}, Code directory index offset: ${codeDirectoryIndex.offset}`,
    );

    // Read the CodeDirectory
    this.setFatCursor(baseOffset + codeDirectoryIndex.offset);
    const codeDirectory: CSCodeDirectory = {
      magic: this.bufferWrapper.readU32BE(),
      length: this.bufferWrapper.readU32BE(),
      version: this.bufferWrapper.readU32BE(),
      flags: this.bufferWrapper.readU32BE(),
      hashOffset: this.bufferWrapper.readU32BE(),
      identOffset: this.bufferWrapper.readU32BE(),
      nSpecialSlots: this.bufferWrapper.readU32BE(),
      nCodeSlots: this.bufferWrapper.readU32BE(),
      codeLimit: this.bufferWrapper.readU32BE(),
      hashSize: this.bufferWrapper.readU8(),
      hashType: this.bufferWrapper.readU8(),
      platform: this.bufferWrapper.readU8(),
      pageSize: this.bufferWrapper.readU8(),
      spare2: this.bufferWrapper.readU32BE(),
      scatterOffset: 0,
      teamOffset: 0,
      spare3: 0,
      codeLimit64: BigInt(0),
      execSegBase: BigInt(0),
      execSegLimit: BigInt(0),
      execSegFlags: BigInt(0),
    };

    // Handle version-specific fields
    if (codeDirectory.version >= 0x20100) {
      codeDirectory.scatterOffset = this.bufferWrapper.readU32BE();
    }
    if (codeDirectory.version >= 0x20200) {
      codeDirectory.teamOffset = this.bufferWrapper.readU32BE();
    }
    if (codeDirectory.version >= 0x20300) {
      codeDirectory.spare3 = this.bufferWrapper.readU32();
      codeDirectory.codeLimit64 = this.bufferWrapper.readU64();
    }
    if (codeDirectory.version >= 0x20400) {
      codeDirectory.execSegBase = this.bufferWrapper.readU64();
      codeDirectory.execSegLimit = this.bufferWrapper.readU64();
      codeDirectory.execSegFlags = this.bufferWrapper.readU64();
    }

    const hashTableOffset = baseOffset + codeDirectoryIndex.offset + codeDirectory.hashOffset;

    // Read special slots (negative indices)
    const specialHashes: string[] = [];
    this.setFatCursor(hashTableOffset - codeDirectory.hashSize * codeDirectory.nSpecialSlots);
    for (let i = -codeDirectory.nSpecialSlots; i < 0; i++) {
      const hash = this.bufferWrapper.buffer.slice(this.fatCursor(), this.fatCursor() + codeDirectory.hashSize);
      this.bufferWrapper.logDebug(`[Slot ${i}]: ${hash.toString('hex')}`);
      specialHashes.push(hash.toString('hex'));
      this.setFatCursor(this.fatCursor() + codeDirectory.hashSize);
    }

    const hashes: string[] = [];
    for (let i = 0; i < codeDirectory.nCodeSlots; i++) {
      const hash = this.bufferWrapper.buffer.slice(this.fatCursor(), this.fatCursor() + codeDirectory.hashSize);
      hashes.push(hash.toString('hex'));
      this.setFatCursor(this.fatCursor() + codeDirectory.hashSize);
    }

    const identityOffset = baseOffset + codeDirectoryIndex.offset + codeDirectory.identOffset;
    this.setFatCursor(identityOffset);
    const identity = this.bufferWrapper.readStringNullTerminated();

    let teamId: string | null = null;
    if (codeDirectory.version >= 0x20200) {
      const teamIdOffset = baseOffset + codeDirectoryIndex.offset + codeDirectory.teamOffset;
      this.setFatCursor(teamIdOffset);
      teamId = this.bufferWrapper.readStringNullTerminated();
    }

    const blobData = this.bufferWrapper.buffer.slice(
      baseOffset + codeDirectoryIndex.offset,
      baseOffset + codeDirectoryIndex.offset + codeDirectory.length,
    );
    const cdHash = createHash(codeDirectory.hashType === CSAlgorithm.SHA1 ? 'sha1' : 'sha256')
      .update(blobData as Uint8Array)
      .digest('hex');

    return {
      bundleId: identity,
      teamId,
      hashSize: codeDirectory.hashSize,
      hashType: codeDirectory.hashType,
      pageSize: codeDirectory.pageSize,
      specialHashes,
      hashes,
      cdHash,
      codeDirectory: codeDirectory,
    };
  }

  private parseEntitlements(superBlob: CSSuperBlob, baseOffset: number, hashType: CSAlgorithm): Entitlements | null {
    const entitlementsIndex = superBlob.index.find((index) => index.type === CSSlot.CSSLOT_ENTITLEMENTS);
    if (!entitlementsIndex) {
      return null;
    }

    this.setFatCursor(baseOffset + entitlementsIndex.offset);

    this.bufferWrapper.readU32BE(); // magic, we don't need it
    const entitlementsLength = this.bufferWrapper.readU32BE();

    const entitlementsPlist = this.bufferWrapper.buffer
      .slice(
        this.fatCursor(),
        this.fatCursor() + entitlementsLength - 8, // subtract 8 for the header we already read
      )
      .toString('utf8');

    const blobData = this.bufferWrapper.buffer.slice(
      baseOffset + entitlementsIndex.offset,
      baseOffset + entitlementsIndex.offset + entitlementsLength,
    );
    const cdHash = createHash(hashType === CSAlgorithm.SHA1 ? 'sha1' : 'sha256')
      .update(blobData as Uint8Array)
      .digest('hex');

    return {
      entitlementsPlist,
      cdHash,
    };
  }

  private parseRequirements(superBlob: CSSuperBlob, baseOffset: number, hashType: CSAlgorithm): Requirements | null {
    const requirementsIndex = superBlob.index.find((index) => index.type === CSSlot.CSSLOT_REQUIREMENTS);
    if (!requirementsIndex) {
      return null;
    }

    this.setFatCursor(baseOffset + requirementsIndex.offset);

    this.bufferWrapper.readU32BE(); // magic
    const reqLength = this.bufferWrapper.readU32BE();

    // TODO: Parse the requirements blob
    const requirements = this.bufferWrapper.buffer.slice(
      this.fatCursor() - 8,
      this.fatCursor() + reqLength - 8, // subtract 8 for the magic and length we already read
    );

    const cdHash = createHash(hashType === CSAlgorithm.SHA1 ? 'sha1' : 'sha256')
      .update(requirements! as Uint8Array)
      .digest()
      .toString('hex');

    return {
      requirements,
      cdHash,
    };
  }

  private parseDEREntitlements(
    superBlob: CSSuperBlob,
    baseOffset: number,
    hashType: CSAlgorithm,
  ): DEREntitlements | null {
    const derIndex = superBlob.index.find((index) => index.type === CSSlot.CSSLOT_DER_ENTITLEMENTS);
    if (!derIndex) {
      return null;
    }

    this.setFatCursor(baseOffset + derIndex.offset);

    this.bufferWrapper.readU32BE(); // magic, we don't need it
    const derLength = this.bufferWrapper.readU32BE();

    const derData = this.bufferWrapper.buffer.slice(
      this.fatCursor(),
      this.fatCursor() + derLength - 8, // subtract 8 for the header we already read
    );

    const blobData = this.bufferWrapper.buffer.slice(
      baseOffset + derIndex.offset,
      baseOffset + derIndex.offset + derLength,
    );
    const cdHash = createHash(hashType === CSAlgorithm.SHA1 ? 'sha1' : 'sha256')
      .update(blobData as Uint8Array)
      .digest()
      .toString('hex');

    return {
      derData,
      cdHash,
    };
  }

  private parseSignature(superBlob: CSSuperBlob, baseOffset: number): CMSSigning | null {
    const signatureIndex = superBlob.index.find((index) => index.type === CSSlot.CSSLOT_SIGNATURESLOT);
    if (!signatureIndex) {
      return null;
    }

    this.setFatCursor(baseOffset + signatureIndex.offset);

    this.bufferWrapper.readU32BE(); // magic
    const signatureLength = this.bufferWrapper.readU32BE();

    const content = this.bufferWrapper.buffer.slice(
      this.fatCursor(),
      this.fatCursor() + signatureLength - 8, // subtract 8 for the header we already read
    );

    const signature = fromBER(content);

    const cms = new ContentInfo({ schema: signature.result });
    const certificates: Certificate[] = [];

    // CMS SignedData
    const cdHashes: { type: CSAlgorithm; value: string }[] = [];
    if (cms.contentType === '1.2.840.113549.1.7.2') {
      const signedData = new SignedData({ schema: cms.content });

      signedData.signerInfos.forEach((signerInfo) => {
        signerInfo.signedAttrs?.attributes.forEach((attr) => {
          const type = attr.type;
          // CDHash
          if (type === '1.2.840.113635.100.9.2') {
            attr.values.forEach((value) => {
              const hashBlock = value.valueBlock.value;
              const hashType =
                hashBlock[0].valueBlock.value.toString() === '2.16,840,1,101,3,4,2,1'
                  ? CSAlgorithm.SHA256
                  : CSAlgorithm.SHA1;
              const hashValue = Buffer.from(hashBlock[1].valueBlock.valueHexView).toString('hex');

              cdHashes.push({ type: hashType, value: hashValue });
            });
          }
        });
      });

      certificates.push(...(signedData.certificates as Certificate[]));
    }

    return {
      cdHashes,
      certificates,
    };
  }
}
