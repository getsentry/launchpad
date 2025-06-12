/* eslint-disable no-bitwise */
import { BufferWrapper } from '../BufferWrapper';
import {
  ChunkHeader,
  ChunkType,
  Dimension,
  EntryFlags,
  Fraction,
  NodeType,
  ResourceTableEntry,
  ResourceTablePackage,
  ResourceTableType,
  ResourceTypeConfig,
  StringFlags,
  StringPool,
  TypeFlags,
  TypedValue,
  TypedValueRawType,
  XmlAttribute,
  XmlCData,
  XmlNode,
} from './AndroidBinaryParserTypes';

export class AndroidBinaryParser {
  bufferWrapper: BufferWrapper;

  strings: string[];

  resources: number[];

  document: XmlNode | null | undefined;

  parent: any;

  stack: any[];

  stringPool: StringPool | null | undefined;

  packages: ResourceTablePackage[];

  constructor(buffer: Buffer, debug: boolean = false) {
    this.bufferWrapper = new BufferWrapper(buffer, debug);
    this.strings = [];
    this.resources = [];
    this.document = null;
    this.parent = null;
    this.stack = [];
    this.stringPool = null;
    this.packages = [];
  }

  readDimension(): Dimension {
    this.bufferWrapper.logGroup('readDimension');

    const value = this.bufferWrapper.readU32();
    const rawUnit = value & 0xff;

    const dimensionValue = value >> 8;
    const dimensionRawUnit = rawUnit;

    let dimensionUnit;
    switch (rawUnit) {
      case TypedValueRawType.COMPLEX_UNIT_MM:
        dimensionUnit = 'mm';
        break;
      case TypedValueRawType.COMPLEX_UNIT_PX:
        dimensionUnit = 'px';
        break;
      case TypedValueRawType.COMPLEX_UNIT_DIP:
        dimensionUnit = 'dp';
        break;
      case TypedValueRawType.COMPLEX_UNIT_SP:
        dimensionUnit = 'sp';
        break;
      case TypedValueRawType.COMPLEX_UNIT_PT:
        dimensionUnit = 'pt';
        break;
      case TypedValueRawType.COMPLEX_UNIT_IN:
        dimensionUnit = 'in';
        break;
      default:
        dimensionUnit = `unknown (${rawUnit})`;
        break;
    }

    this.bufferWrapper.logGroupEnd();

    return {
      value: dimensionValue,
      unit: dimensionUnit,
      rawUnit: dimensionRawUnit,
    };
  }

  readFraction(): Fraction {
    this.bufferWrapper.logGroup('readFraction');

    const value = this.bufferWrapper.readU32();
    const type = value & 0xf;

    const fractionValue = this.convertIntToFloat(value >> 4);
    const fractionRawType = type;

    let fractionType;
    switch (type) {
      case TypedValueRawType.COMPLEX_UNIT_FRACTION:
        fractionType = '%';
        break;
      case TypedValueRawType.COMPLEX_UNIT_FRACTION_PARENT:
        fractionType = '%p';
        break;
      default:
        fractionType = `unknown (${type})`;
        break;
    }

    this.bufferWrapper.logGroupEnd();

    return {
      value: fractionValue,
      type: fractionType,
      rawType: fractionRawType,
    };
  }

  readHex24() {
    this.bufferWrapper.logGroup('readHex24');
    const val = (this.bufferWrapper.readU32() & 0xffffff).toString(16);
    this.bufferWrapper.logGroupEnd();
    return val;
  }

  readHex32() {
    this.bufferWrapper.logGroup('readHex32');
    const val = this.bufferWrapper.readU32().toString(16);
    this.bufferWrapper.logGroupEnd();
    return val;
  }

  typedValueNameFromId(id: number): string {
    switch (id) {
      case TypedValueRawType.TYPE_INT_DEC:
        return 'int_dec';
      case TypedValueRawType.TYPE_INT_HEX:
        return 'int_hex';
      case TypedValueRawType.TYPE_STRING:
        return 'string';
      case TypedValueRawType.TYPE_REFERENCE:
        return 'reference';
      case TypedValueRawType.TYPE_INT_BOOLEAN:
        return 'boolean';
      case TypedValueRawType.TYPE_NULL:
        return 'null';
      case TypedValueRawType.TYPE_INT_COLOR_RGB8:
        return 'rgb8';
      case TypedValueRawType.TYPE_INT_COLOR_RGB4:
        return 'rgb4';
      case TypedValueRawType.TYPE_INT_COLOR_ARGB8:
        return 'argb8';
      case TypedValueRawType.TYPE_INT_COLOR_ARGB4:
        return 'argb4';
      case TypedValueRawType.TYPE_DIMENSION:
        return 'dimension';
      case TypedValueRawType.TYPE_FRACTION:
        return 'fraction';
      default: {
        const type = id.toString(16);
        this.bufferWrapper.logDebug(`Unrecognized typed value of type 0x${type}`);
        return 'unknown';
      }
    }
  }

  readTypedValue(): TypedValue {
    this.bufferWrapper.logGroup('readTypedValue');

    const start = this.bufferWrapper.cursor;

    let size = this.bufferWrapper.readU16();
    /* const zero = */
    const reserved = this.bufferWrapper.readU8();
    if (reserved !== 0) {
      throw new Error(`Reserved field is not 0: ${reserved}`);
    }
    const rawType = this.bufferWrapper.readU8();

    // Yes, there has been a real world APK where the size is malformed.
    if (size === 0) {
      size = 8;
    }

    const typedValueRawType = rawType;

    let typedValue;
    switch (rawType) {
      case TypedValueRawType.TYPE_INT_DEC:
        typedValue = this.bufferWrapper.readS32();
        break;
      case TypedValueRawType.TYPE_INT_HEX:
        typedValue = this.bufferWrapper.readS32();
        break;
      case TypedValueRawType.TYPE_STRING: {
        const ref = this.bufferWrapper.readU32();
        typedValue = ref >= 0 ? this.strings[ref] : '';
        break;
      }
      case TypedValueRawType.TYPE_REFERENCE: {
        const id = this.bufferWrapper.readU32();
        typedValue = `resourceId:0x${id.toString(16)}`;
        break;
      }
      case TypedValueRawType.TYPE_INT_BOOLEAN:
        typedValue = this.bufferWrapper.readS32() !== 0;
        break;
      case TypedValueRawType.TYPE_NULL:
        this.bufferWrapper.readU32();
        typedValue = null;
        break;
      case TypedValueRawType.TYPE_INT_COLOR_RGB8:
        typedValue = this.readHex24();
        break;
      case TypedValueRawType.TYPE_INT_COLOR_RGB4:
        typedValue = this.readHex24();
        break;
      case TypedValueRawType.TYPE_INT_COLOR_ARGB8:
        typedValue = this.readHex32();
        break;
      case TypedValueRawType.TYPE_INT_COLOR_ARGB4:
        typedValue = this.readHex32();
        break;
      case TypedValueRawType.TYPE_DIMENSION:
        typedValue = this.readDimension();
        break;
      case TypedValueRawType.TYPE_FRACTION:
        typedValue = this.readFraction();
        break;
      default: {
        const type = rawType.toString(16);
        this.bufferWrapper.logDebug(`Not sure what to do with typed value of type 0x${type}, falling \
back to reading an uint32.`);
        typedValue = this.bufferWrapper.readU32();
      }
    }

    // Ensure we consume the whole value
    const end = start + size;
    if (this.bufferWrapper.cursor !== end) {
      const type = rawType.toString(16);
      const diff = end - this.bufferWrapper.cursor;
      this.bufferWrapper.logDebug(`Cursor is off by ${diff} bytes at ${this.bufferWrapper.cursor} at supposed end \
of typed value of type 0x${type}. The typed value started at offset ${start} \
and is supposed to end at offset ${end}. Ignoring the rest of the value.`);
      this.bufferWrapper.cursor = end;
    }

    this.bufferWrapper.logGroupEnd();

    return {
      value: typedValue,
      type: this.typedValueNameFromId(rawType),
      rawType: typedValueRawType,
    };
  }

  // https://twitter.com/kawasima/status/427730289201139712
  convertIntToFloat(int: number): number {
    const buf = new ArrayBuffer(4);
    new Int32Array(buf)[0] = int;
    return new Float32Array(buf)[0];
  }

  readString(encoding: string): string {
    this.bufferWrapper.logGroup(`readString ${encoding}`);
    switch (encoding) {
      case 'utf-8': {
        const stringLength = this.bufferWrapper.readLength8();
        this.bufferWrapper.logDebug(`stringLength: ${stringLength}`);

        const byteLength = this.bufferWrapper.readLength8();
        this.bufferWrapper.logDebug(`byteLength: ${byteLength}`);

        const value = this.bufferWrapper.readStringWithLength(byteLength);
        this.bufferWrapper.logDebug(`value: ${value}`);

        if (this.bufferWrapper.readU8() !== 0) {
          throw new Error('String must end with trailing zero');
        }
        this.bufferWrapper.logGroupEnd();
        return value;
      }
      case 'ucs2': {
        const stringLength = this.bufferWrapper.readLength16();
        this.bufferWrapper.logDebug(`stringLength: ${stringLength}`);

        const byteLength = stringLength * 2;
        this.bufferWrapper.logDebug(`byteLength: ${byteLength}`);

        const value = this.bufferWrapper.readStringWithLength(byteLength);
        this.bufferWrapper.logDebug(`value: ${value}`);

        if (this.bufferWrapper.readU16() !== 0) {
          throw new Error('String must end with trailing zero');
        }
        this.bufferWrapper.logGroupEnd();
        return value;
      }
      default:
        throw new Error(`Unsupported encoding '${encoding}'`);
    }
  }

  readChunkHeader(): ChunkHeader {
    this.bufferWrapper.logGroup('readChunkHeader');
    const header = {
      startOffset: this.bufferWrapper.cursor,
      chunkType: this.bufferWrapper.readU16(),
      headerSize: this.bufferWrapper.readU16(),
      chunkSize: this.bufferWrapper.readU32(),
    };

    this.bufferWrapper.logDebug(`startOffset: ${header.startOffset}`);
    this.bufferWrapper.logDebug(`chunkType: ${header.chunkType}`);
    this.bufferWrapper.logDebug(`headerSize: ${header.headerSize}`);
    this.bufferWrapper.logDebug(`chunkSize: ${header.chunkSize}`);
    this.bufferWrapper.logGroupEnd();
    return header;
  }

  readStringPool(header: ChunkHeader): StringPool {
    this.bufferWrapper.logGroup('readStringPool');

    const stringCount = this.bufferWrapper.readU32();
    this.bufferWrapper.logDebug(`stringCount: ${stringCount}`);

    const styleCount = this.bufferWrapper.readU32();
    this.bufferWrapper.logDebug(`styleCount: ${styleCount}`);

    const flags = this.bufferWrapper.readU32();
    this.bufferWrapper.logDebug(`flags: ${flags}`);

    const stringsStart = this.bufferWrapper.readU32();
    this.bufferWrapper.logDebug(`stringsStart: ${stringsStart}`);

    const stylesStart = this.bufferWrapper.readU32();
    this.bufferWrapper.logDebug(`stylesStart: ${stylesStart}`);

    if (header.chunkType !== ChunkType.STRING_POOL) {
      throw new Error('Invalid string pool header');
    }

    const offsets = [];
    for (let i = 0; i <= stringCount; i++) {
      this.bufferWrapper.logDebug(`offset: ${i}`);
      offsets.push(this.bufferWrapper.readU32());
    }

    const encoding = (flags & StringFlags.UTF8) === StringFlags.UTF8 ? 'utf-8' : 'ucs2';
    this.bufferWrapper.logDebug(`encoding: ${encoding}`);

    const adjustedStringsStart = header.startOffset + stringsStart;
    this.bufferWrapper.cursor = adjustedStringsStart;
    const strings: string[] = [];
    for (let i = 0; i < stringCount; ++i) {
      this.bufferWrapper.logDebug(`string ${i}`);
      this.bufferWrapper.logDebug(`offset: ${offsets[i]}`);
      this.bufferWrapper.cursor = adjustedStringsStart + offsets[i];
      const s = this.readString(encoding);
      this.strings.push(s);
      strings.push(s);
    }

    // Skip styles
    this.bufferWrapper.cursor = header.startOffset + header.chunkSize;

    this.bufferWrapper.logGroupEnd();

    return {
      strings,
      flags,
      stringCount,
      stringsStart,
      styleCount,
      stylesStart,
    };
  }

  readResourceMap(header: ChunkHeader) {
    this.bufferWrapper.logDebug('readResourceMap');
    const count = Math.floor((header.chunkSize - header.headerSize) / 4);
    for (let i = 0; i < count; ++i) {
      this.resources.push(this.bufferWrapper.readU32());
    }
    this.bufferWrapper.logGroupEnd();
    return null;
  }

  readXmlNamespaceStart(/* header */) {
    this.bufferWrapper.logGroup('readXmlNamespaceStart');

    /* const line = */
    this.bufferWrapper.readU32();
    /* const commentRef = */
    this.bufferWrapper.readU32();
    /* const prefixRef = */
    this.bufferWrapper.readS32();
    /* const uriRef = */
    this.bufferWrapper.readS32();

    // We don't currently care about the values, but they could
    // be accessed like so:
    //
    // namespaceURI.prefix = this.strings[prefixRef] // if prefixRef > 0
    // namespaceURI.uri = this.strings[uriRef] // if uriRef > 0

    this.bufferWrapper.logGroupEnd();

    return null;
  }

  readXmlNamespaceEnd(/* header */) {
    this.bufferWrapper.logGroup('readXmlNamespaceEnd');

    /* const line = */
    this.bufferWrapper.readU32();
    /* const commentRef = */
    this.bufferWrapper.readU32();
    /* const prefixRef = */
    this.bufferWrapper.readS32();
    /* const uriRef = */
    this.bufferWrapper.readS32();

    // We don't currently care about the values, but they could
    // be accessed like so:
    //
    // namespaceURI.prefix = this.strings[prefixRef] // if prefixRef > 0
    // namespaceURI.uri = this.strings[uriRef] // if uriRef > 0

    this.bufferWrapper.logGroupEnd();

    return null;
  }

  readXmlElementStart() {
    this.bufferWrapper.logGroup('readXmlElementStart');

    const node: XmlNode = {
      nodeType: NodeType.ELEMENT_NODE,
      attributes: [],
      childNodes: [],
    };

    /* const line = */
    this.bufferWrapper.readU32();
    /* const commentRef = */
    this.bufferWrapper.readU32();
    const nsRef = this.bufferWrapper.readS32();
    const nameRef = this.bufferWrapper.readS32();

    if (nsRef > 0) {
      node.namespaceURI = this.strings[nsRef];
    }

    node.nodeName = this.strings[nameRef];

    /* const attrStart = */
    this.bufferWrapper.readU16();
    /* const attrSize = */
    this.bufferWrapper.readU16();
    const attrCount = this.bufferWrapper.readU16();
    /* const idIndex = */
    this.bufferWrapper.readU16();
    /* const classIndex = */
    this.bufferWrapper.readU16();
    /* const styleIndex = */
    this.bufferWrapper.readU16();

    for (let i = 0; i < attrCount; ++i) {
      node.attributes.push(this.readXmlAttribute());
    }

    if (this.document) {
      this.parent.childNodes.push(node);
      this.parent = node;
    } else {
      this.parent = node;
      this.document = node;
    }

    this.stack.push(node);

    this.bufferWrapper.logGroupEnd();

    return node;
  }

  readXmlAttribute(): XmlAttribute {
    this.bufferWrapper.logGroup('readXmlAttribute');

    const nsRef = this.bufferWrapper.readS32();
    const nameRef = this.bufferWrapper.readS32();
    const valueRef = this.bufferWrapper.readS32();

    let namespaceURI;
    if (nsRef > 0) {
      namespaceURI = this.strings[nsRef];
    }

    let nodeName = this.strings[nameRef];
    if (nodeName.length === 0) {
      // If the name is empty, try to get the resource string from the resource map
      if (this.resources && nameRef < this.resources.length) {
        const resourceId = this.resources[nameRef];
        if (resourceId) {
          // Extract the resource string based on the resource ID
          nodeName = this.getResourceString(resourceId);
        }
      }
    }

    let value;
    if (valueRef > 0) {
      value = this.strings[valueRef];
    }

    const typedValue = this.readTypedValue();

    this.bufferWrapper.logGroupEnd();

    return {
      name: nodeName,
      nodeType: NodeType.ATTRIBUTE_NODE,
      namespaceURI,
      nodeName,
      typedValue,
      value,
    };
  }

  readXmlElementEnd() {
    this.bufferWrapper.logGroup('readXmlElementEnd');

    /* const line = */
    this.bufferWrapper.readU32();
    /* const commentRef = */
    this.bufferWrapper.readU32();
    /* const nsRef = */
    this.bufferWrapper.readS32();
    /* const nameRef = */
    this.bufferWrapper.readS32();

    this.stack.pop();
    this.parent = this.stack[this.stack.length - 1];

    this.bufferWrapper.logGroupEnd();

    return null;
  }

  readXmlCData(/* header */): XmlCData {
    this.bufferWrapper.logGroup('readXmlCData');

    /* const line = */
    this.bufferWrapper.readU32();
    /* const commentRef = */
    this.bufferWrapper.readU32();
    const dataRef = this.bufferWrapper.readS32();

    let data: string | undefined;
    if (dataRef > 0) {
      data = this.strings[dataRef];
    }

    const typedValue = this.readTypedValue();

    const cData: XmlCData = {
      attributes: [],
      childNodes: [],
      nodeType: NodeType.CDATA_SECTION_NODE,
      nodeName: '#cdata',
      data,
      typedValue,
    };

    this.parent.childNodes.push(cData);

    this.bufferWrapper.logGroupEnd();

    return cData;
  }

  readPackageName(): string {
    this.bufferWrapper.logGroup('readPackageName');
    const offset = this.bufferWrapper.cursor;
    let length = 0;
    for (let i = offset; i < this.bufferWrapper.buffer.length && i < offset + 256; i += 2) {
      if (this.bufferWrapper.buffer[i] === 0 && this.bufferWrapper.buffer[i + 1] === 0) {
        length = i - offset;
        break;
      }
    }

    const str = this.bufferWrapper.buffer.toString('utf16le', offset, offset + length);

    this.bufferWrapper.cursor = offset + 256;
    this.bufferWrapper.logGroupEnd();
    return str;
  }

  readPackage(header: ChunkHeader): ResourceTablePackage {
    this.bufferWrapper.logGroup('readPackage');

    const packageEnd = header.startOffset + header.chunkSize;

    // Read package name and other properties as needed
    const id = this.bufferWrapper.readU32();
    const name = this.readPackageName();

    this.bufferWrapper.logDebug(`id: ${id}`);
    this.bufferWrapper.logDebug(`name: ${name}`);

    const typeStringsOffset = this.bufferWrapper.readU32();
    // lastPublicType, ignored
    this.bufferWrapper.readU32();
    // keyStrings
    const keyStringsOffset = this.bufferWrapper.readU32();
    // lastPublicKey, ignored
    this.bufferWrapper.readU32();
    // typeIdOffset, ignored
    this.bufferWrapper.readU32();

    this.bufferWrapper.cursor = header.startOffset + typeStringsOffset;
    const typesStringPoolHeader = this.readChunkHeader();
    const typesStringPool = this.readStringPool(typesStringPoolHeader);
    this.bufferWrapper.cursor = header.startOffset + keyStringsOffset;
    const keysStringPoolHeader = this.readChunkHeader();
    const keysStringPool = this.readStringPool(keysStringPoolHeader);

    // Parse type chunks within the package
    const types: ResourceTableType[] = [];
    this.bufferWrapper.cursor = header.startOffset + header.headerSize;
    while (this.bufferWrapper.cursor < packageEnd) {
      const chunkHeader = this.readChunkHeader();

      this.bufferWrapper.logDebug(`chunkHeader.chunkType: ${chunkHeader.chunkType.toString(16)}`);
      switch (chunkHeader.chunkType) {
        case ChunkType.TABLE_LIBRARY:
          this.bufferWrapper.logDebug('Skipping library chunk');
          this.bufferWrapper.cursor = chunkHeader.startOffset + chunkHeader.chunkSize;
          break;
        case ChunkType.TABLE_TYPE:
          types.push(this.readTypeChunk(chunkHeader, typesStringPool, keysStringPool));
          break;
        case ChunkType.TABLE_TYPE_SPEC:
          this.bufferWrapper.logDebug('Skipping type spec chunk');
          this.bufferWrapper.cursor = chunkHeader.startOffset + chunkHeader.chunkSize;
          break;
        case ChunkType.NULL:
          this.readNull(chunkHeader);
          break;
        default:
          this.bufferWrapper.logDebug(`Skipping chunk of type ${chunkHeader.chunkType.toString(16)}`);
          // Skip this chunk, whether it's a LibraryChunk or anything else
          this.bufferWrapper.cursor = chunkHeader.startOffset + chunkHeader.chunkSize;
          break;
      }
    }

    this.bufferWrapper.logGroupEnd();

    return {
      id,
      name,
      types,
    };
  }

  readTypeChunk(header: ChunkHeader, typeStringsPool: StringPool, keysStringPool: StringPool): ResourceTableType {
    this.bufferWrapper.logGroup('readTypeChunk');

    const id = this.bufferWrapper.readU8();
    this.bufferWrapper.logDebug(`id: ${id}`);
    const flags = this.bufferWrapper.readU8();
    this.bufferWrapper.logDebug(`flags: ${flags}`);
    // Reserved
    const reserved = this.bufferWrapper.readU16();
    if (reserved !== 0) {
      throw new Error(`Reserved field is not 0: ${reserved}`);
    }
    const entriesCount = this.bufferWrapper.readU32();
    this.bufferWrapper.logDebug(`entriesCount: ${entriesCount}`);
    const entriesStart = this.bufferWrapper.readU32();
    this.bufferWrapper.logDebug(`entriesStart: ${entriesStart}`);

    const name = typeStringsPool.strings[id - 1];
    this.bufferWrapper.logDebug(`typename: ${name}`);

    const config = this.readTypeConfig();

    const isSparse = (flags & TypeFlags.SPARSE) !== 0;

    // TODO: Potentially use a map in the future for faster lookups
    const entries: ResourceTableEntry[] = [];
    if (isSparse) {
      this.bufferWrapper.logDebug('Reading sparse entries');
      const start = this.bufferWrapper.cursor;
      for (let i = 0; i < entriesCount; ++i) {
        this.bufferWrapper.cursor = start + i * 4;
        const index = this.bufferWrapper.readU16() & 0xffff;
        const entryOffset = (this.bufferWrapper.readU16() & 0xffff) * 4;
        const entry = this.createEntry(header.startOffset + entriesStart + entryOffset, index, keysStringPool);
        entries.push(entry);
      }
    } else {
      this.bufferWrapper.logDebug('Reading non-sparse entries');
      const start = this.bufferWrapper.cursor;
      for (let i = 0; i < entriesCount; ++i) {
        this.bufferWrapper.cursor = start + i * 4;
        const entryOffset = this.bufferWrapper.readU32();
        if (entryOffset === 0xffffffff) continue;
        const entry = this.createEntry(header.startOffset + entriesStart + entryOffset, i, keysStringPool);
        entries.push(entry);
      }
    }

    this.bufferWrapper.cursor = header.startOffset + header.chunkSize;

    this.bufferWrapper.logGroupEnd();

    return {
      id,
      name,
      config,
      entries,
    };
  }

  createEntry(offset: number, index: number, keysStringPool: StringPool): ResourceTableEntry {
    this.bufferWrapper.logGroup('createEntry');
    this.bufferWrapper.logDebug(`offset: ${offset}`);
    this.bufferWrapper.logDebug(`index: ${index}`);

    this.bufferWrapper.cursor = offset;

    const size = this.bufferWrapper.readU16();
    this.bufferWrapper.logDebug(`size: ${size}`);

    const flags = this.bufferWrapper.readU16();
    this.bufferWrapper.logDebug(`flags: ${flags}`);

    const keyIndex = this.bufferWrapper.readU32();
    this.bufferWrapper.logDebug(`keyIndex: ${keyIndex}`);

    const key = keysStringPool.strings[keyIndex];
    this.bufferWrapper.logDebug(`key: ${key}`);

    let parentEntry = 0;

    let value: TypedValue | undefined;
    const values: Map<number, TypedValue> = new Map();

    if ((flags & EntryFlags.COMPLEX) !== 0) {
      parentEntry = this.bufferWrapper.readU32();
      const countOrValue = this.bufferWrapper.readU32();
      this.bufferWrapper.logDebug(`countOrValue: ${countOrValue}`);

      for (let i = 0; i < countOrValue; ++i) {
        const entryOffset = this.bufferWrapper.readU32();
        const v = this.readTypedValue();
        values.set(entryOffset, v);
      }
    } else {
      value = this.readTypedValue();
    }

    this.bufferWrapper.logGroupEnd();
    return {
      size,
      flags,
      id: index,
      key,
      parentEntry,
      value,
      values,
    };
  }

  readTypeConfig(): ResourceTypeConfig {
    this.bufferWrapper.logGroup('readTypeConfig');
    const start = this.bufferWrapper.cursor;

    const size = this.bufferWrapper.readU32();
    this.bufferWrapper.logDebug(`config size: ${size}`);

    // mcc, ignored
    this.bufferWrapper.readU16();
    // mnc, ignored
    this.bufferWrapper.readU16();
    const language = this.bufferWrapper.readStringWithLength(2);
    this.bufferWrapper.logDebug(`language: ${language}`);
    const region = this.bufferWrapper.readStringWithLength(2);
    this.bufferWrapper.logDebug(`country: ${region}`);

    // Remainder is ignored for now, we only care about languages for string parsing
    this.bufferWrapper.cursor = start + size;

    this.bufferWrapper.logGroupEnd();

    return {
      size,
      language,
      region,
    };
  }

  readNull(header: ChunkHeader) {
    this.bufferWrapper.logGroup('readNull');
    this.bufferWrapper.cursor = header.startOffset + header.chunkSize;
    this.bufferWrapper.logGroupEnd();
    return null;
  }

  parseXml(): XmlNode {
    this.bufferWrapper.logGroup('AndroidBinaryParser.parseXml');

    const mainChunkHeader = this.readChunkHeader();
    if (mainChunkHeader.chunkType !== ChunkType.XML) {
      throw new Error(`Invalid main chunk header: ${mainChunkHeader.chunkType}`);
    }

    while (this.bufferWrapper.cursor < this.bufferWrapper.buffer.length) {
      this.bufferWrapper.logGroup('chunk');
      const start = this.bufferWrapper.cursor;
      const header = this.readChunkHeader();
      switch (header.chunkType) {
        case ChunkType.STRING_POOL:
          this.stringPool = this.readStringPool(header);
          break;
        case ChunkType.XML_RESOURCE_MAP:
          this.readResourceMap(header);
          break;
        case ChunkType.XML_START_NAMESPACE:
          this.readXmlNamespaceStart();
          break;
        case ChunkType.XML_END_NAMESPACE:
          this.readXmlNamespaceEnd();
          break;
        case ChunkType.XML_START_ELEMENT:
          this.readXmlElementStart();
          break;
        case ChunkType.XML_END_ELEMENT:
          this.readXmlElementEnd();
          break;
        case ChunkType.XML_CDATA:
          this.readXmlCData();
          break;
        // TODO: Handle resource table chunk types
        case ChunkType.NULL:
          this.readNull(header);
          break;
        default:
          throw new Error(`Unsupported chunk type '${header.chunkType}'`);
      }

      // Ensure we consume the whole chunk
      const end = start + header.chunkSize;
      if (this.bufferWrapper.cursor !== end) {
        const diff = end - this.bufferWrapper.cursor;
        const type = header.chunkType.toString(16);
        this.bufferWrapper.logDebug(`Cursor is off by ${diff} bytes at ${this.bufferWrapper.cursor} at supposed \
end of chunk of type 0x${type}. The chunk started at offset ${start} and is \
supposed to end at offset ${end}. Ignoring the rest of the chunk.`);
        this.bufferWrapper.cursor = end;
      }

      this.bufferWrapper.logGroupEnd();
    }

    if (!this.document) {
      throw Error('No XML document found');
    }

    this.bufferWrapper.logGroupEnd();

    return this.document;
  }

  parseResourceTable() {
    this.bufferWrapper.logGroup('AndroidBinaryParser.parseResourceTable');
    this.bufferWrapper.cursor = 0;

    // Assuming the buffer is already pointing to the resource table
    const mainChunkHeader = this.readChunkHeader();
    if (mainChunkHeader.chunkType !== ChunkType.TABLE) {
      throw new Error(`Invalid main chunk type: ${mainChunkHeader.chunkType}`);
    }

    const packages = this.bufferWrapper.readU32();
    this.bufferWrapper.logDebug(`packages: ${packages}`);

    if (this.bufferWrapper.buffer.length <= 40) {
      // Apps with no resources will be exactly 40 bytes.
      // Parsing these files leads to out of bounds exceptions, so we'll just return early if file is 40 bytes or less.
      return;
    }

    while (this.bufferWrapper.cursor < this.bufferWrapper.buffer.length) {
      this.bufferWrapper.logGroup('chunk');
      const start = this.bufferWrapper.cursor;
      const header = this.readChunkHeader();
      switch (header.chunkType) {
        case ChunkType.STRING_POOL:
          this.stringPool = this.readStringPool(header);
          break;
        case ChunkType.TABLE_PACKAGE:
          this.packages.push(this.readPackage(header));
          break;
        case ChunkType.NULL:
          this.readNull(header);
          break;
        default:
          throw new Error(`Unsupported chunk type '${header.chunkType}'`);
      }

      // Ensure we consume the whole chunk
      const end = start + header.chunkSize;
      if (this.bufferWrapper.cursor !== end) {
        const diff = end - this.bufferWrapper.cursor;
        const type = header.chunkType.toString(16);
        this.bufferWrapper.logDebug(`Cursor is off by ${diff} bytes at ${this.bufferWrapper.cursor} at supposed \
end of chunk of type 0x${type}. The chunk started at offset ${start} and is \
supposed to end at offset ${end}. Ignoring the rest of the chunk.`);
        this.bufferWrapper.cursor = end;
      }

      this.bufferWrapper.logGroupEnd();
    }

    this.bufferWrapper.logGroupEnd();
  }

  // https://github.com/Ayrx/axmldecoder/blob/680ec1552199666b60b0b6a479dfc63d7f4b6f82/src/xml.rs#L221
  getResourceString(resourceId: number) {
    const i = resourceId - 0x0101_0000;

    return AndroidBinaryParser.RESOURCE_STRINGS[i];
  }

  static RESOURCE_STRINGS: string[] = [
    'theme',
    'label',
    'icon',
    'name',
    'manageSpaceActivity',
    'allowClearUserData',
    'permission',
    'readPermission',
    'writePermission',
    'protectionLevel',
    'permissionGroup',
    'sharedUserId',
    'hasCode',
    'persistent',
    'enabled',
    'debuggable',
    'exported',
    'process',
    'taskAffinity',
    'multiprocess',
    'finishOnTaskLaunch',
    'clearTaskOnLaunch',
    'stateNotNeeded',
    'excludeFromRecents',
    'authorities',
    'syncable',
    'initOrder',
    'grantUriPermissions',
    'priority',
    'launchMode',
    'screenOrientation',
    'configChanges',
    'description',
    'targetPackage',
    'handleProfiling',
    'functionalTest',
    'value',
    'resource',
    'mimeType',
    'scheme',
    'host',
    'port',
    'path',
    'pathPrefix',
    'pathPattern',
    'action',
    'data',
    'targetClass',
    'colorForeground',
    'colorBackground',
    'backgroundDimAmount',
    'disabledAlpha',
    'textAppearance',
    'textAppearanceInverse',
    'textColorPrimary',
    'textColorPrimaryDisableOnly',
    'textColorSecondary',
    'textColorPrimaryInverse',
    'textColorSecondaryInverse',
    'textColorPrimaryNoDisable',
    'textColorSecondaryNoDisable',
    'textColorPrimaryInverseNoDisable',
    'textColorSecondaryInverseNoDisable',
    'textColorHintInverse',
    'textAppearanceLarge',
    'textAppearanceMedium',
    'textAppearanceSmall',
    'textAppearanceLargeInverse',
    'textAppearanceMediumInverse',
    'textAppearanceSmallInverse',
    'textCheckMark',
    'textCheckMarkInverse',
    'buttonStyle',
    'buttonStyleSmall',
    'buttonStyleInset',
    'buttonStyleToggle',
    'galleryItemBackground',
    'listPreferredItemHeight',
    'expandableListPreferredItemPaddingLeft',
    'expandableListPreferredChildPaddingLeft',
    'expandableListPreferredItemIndicatorLeft',
    'expandableListPreferredItemIndicatorRight',
    'expandableListPreferredChildIndicatorLeft',
    'expandableListPreferredChildIndicatorRight',
    'windowBackground',
    'windowFrame',
    'windowNoTitle',
    'windowIsFloating',
    'windowIsTranslucent',
    'windowContentOverlay',
    'windowTitleSize',
    'windowTitleStyle',
    'windowTitleBackgroundStyle',
    'alertDialogStyle',
    'panelBackground',
    'panelFullBackground',
    'panelColorForeground',
    'panelColorBackground',
    'panelTextAppearance',
    'scrollbarSize',
    'scrollbarThumbHorizontal',
    'scrollbarThumbVertical',
    'scrollbarTrackHorizontal',
    'scrollbarTrackVertical',
    'scrollbarAlwaysDrawHorizontalTrack',
    'scrollbarAlwaysDrawVerticalTrack',
    'absListViewStyle',
    'autoCompleteTextViewStyle',
    'checkboxStyle',
    'dropDownListViewStyle',
    'editTextStyle',
    'expandableListViewStyle',
    'galleryStyle',
    'gridViewStyle',
    'imageButtonStyle',
    'imageWellStyle',
    'listViewStyle',
    'listViewWhiteStyle',
    'popupWindowStyle',
    'progressBarStyle',
    'progressBarStyleHorizontal',
    'progressBarStyleSmall',
    'progressBarStyleLarge',
    'seekBarStyle',
    'ratingBarStyle',
    'ratingBarStyleSmall',
    'radioButtonStyle',
    'scrollbarStyle',
    'scrollViewStyle',
    'spinnerStyle',
    'starStyle',
    'tabWidgetStyle',
    'textViewStyle',
    'webViewStyle',
    'dropDownItemStyle',
    'spinnerDropDownItemStyle',
    'dropDownHintAppearance',
    'spinnerItemStyle',
    'mapViewStyle',
    'preferenceScreenStyle',
    'preferenceCategoryStyle',
    'preferenceInformationStyle',
    'preferenceStyle',
    'checkBoxPreferenceStyle',
    'yesNoPreferenceStyle',
    'dialogPreferenceStyle',
    'editTextPreferenceStyle',
    'ringtonePreferenceStyle',
    'preferenceLayoutChild',
    'textSize',
    'typeface',
    'textStyle',
    'textColor',
    'textColorHighlight',
    'textColorHint',
    'textColorLink',
    'state_focused',
    'state_window_focused',
    'state_enabled',
    'state_checkable',
    'state_checked',
    'state_selected',
    'state_active',
    'state_single',
    'state_first',
    'state_middle',
    'state_last',
    'state_pressed',
    'state_expanded',
    'state_empty',
    'state_above_anchor',
    'ellipsize',
    'x',
    'y',
    'windowAnimationStyle',
    'gravity',
    'autoLink',
    'linksClickable',
    'entries',
    'layout_gravity',
    'windowEnterAnimation',
    'windowExitAnimation',
    'windowShowAnimation',
    'windowHideAnimation',
    'activityOpenEnterAnimation',
    'activityOpenExitAnimation',
    'activityCloseEnterAnimation',
    'activityCloseExitAnimation',
    'taskOpenEnterAnimation',
    'taskOpenExitAnimation',
    'taskCloseEnterAnimation',
    'taskCloseExitAnimation',
    'taskToFrontEnterAnimation',
    'taskToFrontExitAnimation',
    'taskToBackEnterAnimation',
    'taskToBackExitAnimation',
    'orientation',
    'keycode',
    'fullDark',
    'topDark',
    'centerDark',
    'bottomDark',
    'fullBright',
    'topBright',
    'centerBright',
    'bottomBright',
    'bottomMedium',
    'centerMedium',
    'id',
    'tag',
    'scrollX',
    'scrollY',
    'background',
    'padding',
    'paddingLeft',
    'paddingTop',
    'paddingRight',
    'paddingBottom',
    'focusable',
    'focusableInTouchMode',
    'visibility',
    'fitsSystemWindows',
    'scrollbars',
    'fadingEdge',
    'fadingEdgeLength',
    'nextFocusLeft',
    'nextFocusRight',
    'nextFocusUp',
    'nextFocusDown',
    'clickable',
    'longClickable',
    'saveEnabled',
    'drawingCacheQuality',
    'duplicateParentState',
    'clipChildren',
    'clipToPadding',
    'layoutAnimation',
    'animationCache',
    'persistentDrawingCache',
    'alwaysDrawnWithCache',
    'addStatesFromChildren',
    'descendantFocusability',
    'layout',
    'inflatedId',
    'layout_width',
    'layout_height',
    'layout_margin',
    'layout_marginLeft',
    'layout_marginTop',
    'layout_marginRight',
    'layout_marginBottom',
    'listSelector',
    'drawSelectorOnTop',
    'stackFromBottom',
    'scrollingCache',
    'textFilterEnabled',
    'transcriptMode',
    'cacheColorHint',
    'dial',
    'hand_hour',
    'hand_minute',
    'format',
    'checked',
    'button',
    'checkMark',
    'foreground',
    'measureAllChildren',
    'groupIndicator',
    'childIndicator',
    'indicatorLeft',
    'indicatorRight',
    'childIndicatorLeft',
    'childIndicatorRight',
    'childDivider',
    'animationDuration',
    'spacing',
    'horizontalSpacing',
    'verticalSpacing',
    'stretchMode',
    'columnWidth',
    'numColumns',
    'src',
    'antialias',
    'filter',
    'dither',
    'scaleType',
    'adjustViewBounds',
    'maxWidth',
    'maxHeight',
    'tint',
    'baselineAlignBottom',
    'cropToPadding',
    'textOn',
    'textOff',
    'baselineAligned',
    'baselineAlignedChildIndex',
    'weightSum',
    'divider',
    'dividerHeight',
    'choiceMode',
    'itemTextAppearance',
    'horizontalDivider',
    'verticalDivider',
    'headerBackground',
    'itemBackground',
    'itemIconDisabledAlpha',
    'rowHeight',
    'maxRows',
    'maxItemsPerRow',
    'moreIcon',
    'max',
    'progress',
    'secondaryProgress',
    'indeterminate',
    'indeterminateOnly',
    'indeterminateDrawable',
    'progressDrawable',
    'indeterminateDuration',
    'indeterminateBehavior',
    'minWidth',
    'minHeight',
    'interpolator',
    'thumb',
    'thumbOffset',
    'numStars',
    'rating',
    'stepSize',
    'isIndicator',
    'checkedButton',
    'stretchColumns',
    'shrinkColumns',
    'collapseColumns',
    'layout_column',
    'layout_span',
    'bufferType',
    'text',
    'hint',
    'textScaleX',
    'cursorVisible',
    'maxLines',
    'lines',
    'height',
    'minLines',
    'maxEms',
    'ems',
    'width',
    'minEms',
    'scrollHorizontally',
    'password',
    'singleLine',
    'selectAllOnFocus',
    'includeFontPadding',
    'maxLength',
    'shadowColor',
    'shadowDx',
    'shadowDy',
    'shadowRadius',
    'numeric',
    'digits',
    'phoneNumber',
    'inputMethod',
    'capitalize',
    'autoText',
    'editable',
    'freezesText',
    'drawableTop',
    'drawableBottom',
    'drawableLeft',
    'drawableRight',
    'drawablePadding',
    'completionHint',
    'completionHintView',
    'completionThreshold',
    'dropDownSelector',
    'popupBackground',
    'inAnimation',
    'outAnimation',
    'flipInterval',
    'fillViewport',
    'prompt',
    'startYear',
    'endYear',
    'mode',
    'layout_x',
    'layout_y',
    'layout_weight',
    'layout_toLeftOf',
    'layout_toRightOf',
    'layout_above',
    'layout_below',
    'layout_alignBaseline',
    'layout_alignLeft',
    'layout_alignTop',
    'layout_alignRight',
    'layout_alignBottom',
    'layout_alignParentLeft',
    'layout_alignParentTop',
    'layout_alignParentRight',
    'layout_alignParentBottom',
    'layout_centerInParent',
    'layout_centerHorizontal',
    'layout_centerVertical',
    'layout_alignWithParentIfMissing',
    'layout_scale',
    'visible',
    'variablePadding',
    'constantSize',
    'oneshot',
    'duration',
    'drawable',
    'shape',
    'innerRadiusRatio',
    'thicknessRatio',
    'startColor',
    'endColor',
    'useLevel',
    'angle',
    'type',
    'centerX',
    'centerY',
    'gradientRadius',
    'color',
    'dashWidth',
    'dashGap',
    'radius',
    'topLeftRadius',
    'topRightRadius',
    'bottomLeftRadius',
    'bottomRightRadius',
    'left',
    'top',
    'right',
    'bottom',
    'minLevel',
    'maxLevel',
    'fromDegrees',
    'toDegrees',
    'pivotX',
    'pivotY',
    'insetLeft',
    'insetRight',
    'insetTop',
    'insetBottom',
    'shareInterpolator',
    'fillBefore',
    'fillAfter',
    'startOffset',
    'repeatCount',
    'repeatMode',
    'zAdjustment',
    'fromXScale',
    'toXScale',
    'fromYScale',
    'toYScale',
    'fromXDelta',
    'toXDelta',
    'fromYDelta',
    'toYDelta',
    'fromAlpha',
    'toAlpha',
    'delay',
    'animation',
    'animationOrder',
    'columnDelay',
    'rowDelay',
    'direction',
    'directionPriority',
    'factor',
    'cycles',
    'searchMode',
    'searchSuggestAuthority',
    'searchSuggestPath',
    'searchSuggestSelection',
    'searchSuggestIntentAction',
    'searchSuggestIntentData',
    'queryActionMsg',
    'suggestActionMsg',
    'suggestActionMsgColumn',
    'menuCategory',
    'orderInCategory',
    'checkableBehavior',
    'title',
    'titleCondensed',
    'alphabeticShortcut',
    'numericShortcut',
    'checkable',
    'selectable',
    'orderingFromXml',
    'key',
    'summary',
    'order',
    'widgetLayout',
    'dependency',
    'defaultValue',
    'shouldDisableView',
    'summaryOn',
    'summaryOff',
    'disableDependentsState',
    'dialogTitle',
    'dialogMessage',
    'dialogIcon',
    'positiveButtonText',
    'negativeButtonText',
    'dialogLayout',
    'entryValues',
    'ringtoneType',
    'showDefault',
    'showSilent',
    'scaleWidth',
    'scaleHeight',
    'scaleGravity',
    'ignoreGravity',
    'foregroundGravity',
    'tileMode',
    'targetActivity',
    'alwaysRetainTaskState',
    'allowTaskReparenting',
    'searchButtonText',
    'colorForegroundInverse',
    'textAppearanceButton',
    'listSeparatorTextViewStyle',
    'streamType',
    'clipOrientation',
    'centerColor',
    'minSdkVersion',
    'windowFullscreen',
    'unselectedAlpha',
    'progressBarStyleSmallTitle',
    'ratingBarStyleIndicator',
    'apiKey',
    'textColorTertiary',
    'textColorTertiaryInverse',
    'listDivider',
    'soundEffectsEnabled',
    'keepScreenOn',
    'lineSpacingExtra',
    'lineSpacingMultiplier',
    'listChoiceIndicatorSingle',
    'listChoiceIndicatorMultiple',
    'versionCode',
    'versionName',
    'marqueeRepeatLimit',
    'windowNoDisplay',
    'backgroundDimEnabled',
    'inputType',
    'isDefault',
    'windowDisablePreview',
    'privateImeOptions',
    'editorExtras',
    'settingsActivity',
    'fastScrollEnabled',
    'reqTouchScreen',
    'reqKeyboardType',
    'reqHardKeyboard',
    'reqNavigation',
    'windowSoftInputMode',
    'imeFullscreenBackground',
    'noHistory',
    'headerDividersEnabled',
    'footerDividersEnabled',
    'candidatesTextStyleSpans',
    'smoothScrollbar',
    'reqFiveWayNav',
    'keyBackground',
    'keyTextSize',
    'labelTextSize',
    'keyTextColor',
    'keyPreviewLayout',
    'keyPreviewOffset',
    'keyPreviewHeight',
    'verticalCorrection',
    'popupLayout',
    'state_long_pressable',
    'keyWidth',
    'keyHeight',
    'horizontalGap',
    'verticalGap',
    'rowEdgeFlags',
    'codes',
    'popupKeyboard',
    'popupCharacters',
    'keyEdgeFlags',
    'isModifier',
    'isSticky',
    'isRepeatable',
    'iconPreview',
    'keyOutputText',
    'keyLabel',
    'keyIcon',
    'keyboardMode',
    'isScrollContainer',
    'fillEnabled',
    'updatePeriodMillis',
    'initialLayout',
    'voiceSearchMode',
    'voiceLanguageModel',
    'voicePromptText',
    'voiceLanguage',
    'voiceMaxResults',
    'bottomOffset',
    'topOffset',
    'allowSingleTap',
    'handle',
    'content',
    'animateOnClick',
    'configure',
    'hapticFeedbackEnabled',
    'innerRadius',
    'thickness',
    'sharedUserLabel',
    'dropDownWidth',
    'dropDownAnchor',
    'imeOptions',
    'imeActionLabel',
    'imeActionId',
    'UNKNOWN',
    'imeExtractEnterAnimation',
    'imeExtractExitAnimation',
    'tension',
    'extraTension',
    'anyDensity',
    'searchSuggestThreshold',
    'includeInGlobalSearch',
    'onClick',
    'targetSdkVersion',
    'maxSdkVersion',
    'testOnly',
    'contentDescription',
    'gestureStrokeWidth',
    'gestureColor',
    'uncertainGestureColor',
    'fadeOffset',
    'fadeDuration',
    'gestureStrokeType',
    'gestureStrokeLengthThreshold',
    'gestureStrokeSquarenessThreshold',
    'gestureStrokeAngleThreshold',
    'eventsInterceptionEnabled',
    'fadeEnabled',
    'backupAgent',
    'allowBackup',
    'glEsVersion',
    'queryAfterZeroResults',
    'dropDownHeight',
    'smallScreens',
    'normalScreens',
    'largeScreens',
    'progressBarStyleInverse',
    'progressBarStyleSmallInverse',
    'progressBarStyleLargeInverse',
    'searchSettingsDescription',
    'textColorPrimaryInverseDisableOnly',
    'autoUrlDetect',
    'resizeable',
    'required',
    'accountType',
    'contentAuthority',
    'userVisible',
    'windowShowWallpaper',
    'wallpaperOpenEnterAnimation',
    'wallpaperOpenExitAnimation',
    'wallpaperCloseEnterAnimation',
    'wallpaperCloseExitAnimation',
    'wallpaperIntraOpenEnterAnimation',
    'wallpaperIntraOpenExitAnimation',
    'wallpaperIntraCloseEnterAnimation',
    'wallpaperIntraCloseExitAnimation',
    'supportsUploading',
    'killAfterRestore',
    'restoreNeedsApplication',
    'smallIcon',
    'accountPreferences',
    'textAppearanceSearchResultSubtitle',
    'textAppearanceSearchResultTitle',
    'summaryColumn',
    'detailColumn',
    'detailSocialSummary',
    'thumbnail',
    'detachWallpaper',
    'finishOnCloseSystemDialogs',
    'scrollbarFadeDuration',
    'scrollbarDefaultDelayBeforeFade',
    'fadeScrollbars',
    'colorBackgroundCacheHint',
    'dropDownHorizontalOffset',
    'dropDownVerticalOffset',
    'quickContactBadgeStyleWindowSmall',
    'quickContactBadgeStyleWindowMedium',
    'quickContactBadgeStyleWindowLarge',
    'quickContactBadgeStyleSmallWindowSmall',
    'quickContactBadgeStyleSmallWindowMedium',
    'quickContactBadgeStyleSmallWindowLarge',
    'author',
    'autoStart',
    'expandableListViewWhiteStyle',
    'installLocation',
    'vmSafeMode',
    'webTextViewStyle',
    'restoreAnyVersion',
    'tabStripLeft',
    'tabStripRight',
    'tabStripEnabled',
    'logo',
    'xlargeScreens',
    'immersive',
    'overScrollMode',
    'overScrollHeader',
    'overScrollFooter',
    'filterTouchesWhenObscured',
    'textSelectHandleLeft',
    'textSelectHandleRight',
    'textSelectHandle',
    'textSelectHandleWindowStyle',
    'popupAnimationStyle',
    'screenSize',
    'screenDensity',
    'allContactsName',
    'windowActionBar',
    'actionBarStyle',
    'navigationMode',
    'displayOptions',
    'subtitle',
    'customNavigationLayout',
    'hardwareAccelerated',
    'measureWithLargestChild',
    'animateFirstView',
    'dropDownSpinnerStyle',
    'actionDropDownStyle',
    'actionButtonStyle',
    'showAsAction',
    'previewImage',
    'actionModeBackground',
    'actionModeCloseDrawable',
    'windowActionModeOverlay',
    'valueFrom',
    'valueTo',
    'valueType',
    'propertyName',
    'ordering',
    'fragment',
    'windowActionBarOverlay',
    'fragmentOpenEnterAnimation',
    'fragmentOpenExitAnimation',
    'fragmentCloseEnterAnimation',
    'fragmentCloseExitAnimation',
    'fragmentFadeEnterAnimation',
    'fragmentFadeExitAnimation',
    'actionBarSize',
    'imeSubtypeLocale',
    'imeSubtypeMode',
    'imeSubtypeExtraValue',
    'splitMotionEvents',
    'listChoiceBackgroundIndicator',
    'spinnerMode',
    'animateLayoutChanges',
    'actionBarTabStyle',
    'actionBarTabBarStyle',
    'actionBarTabTextStyle',
    'actionOverflowButtonStyle',
    'actionModeCloseButtonStyle',
    'titleTextStyle',
    'subtitleTextStyle',
    'iconifiedByDefault',
    'actionLayout',
    'actionViewClass',
    'activatedBackgroundIndicator',
    'state_activated',
    'listPopupWindowStyle',
    'popupMenuStyle',
    'textAppearanceLargePopupMenu',
    'textAppearanceSmallPopupMenu',
    'breadCrumbTitle',
    'breadCrumbShortTitle',
    'listDividerAlertDialog',
    'textColorAlertDialogListItem',
    'loopViews',
    'dialogTheme',
    'alertDialogTheme',
    'dividerVertical',
    'homeAsUpIndicator',
    'enterFadeDuration',
    'exitFadeDuration',
    'selectableItemBackground',
    'autoAdvanceViewId',
    'useIntrinsicSizeAsMinimum',
    'actionModeCutDrawable',
    'actionModeCopyDrawable',
    'actionModePasteDrawable',
    'textEditPasteWindowLayout',
    'textEditNoPasteWindowLayout',
    'textIsSelectable',
    'windowEnableSplitTouch',
    'indeterminateProgressStyle',
    'progressBarPadding',
    'animationResolution',
    'state_accelerated',
    'baseline',
    'homeLayout',
    'opacity',
    'alpha',
    'transformPivotX',
    'transformPivotY',
    'translationX',
    'translationY',
    'scaleX',
    'scaleY',
    'rotation',
    'rotationX',
    'rotationY',
    'showDividers',
    'dividerPadding',
    'borderlessButtonStyle',
    'dividerHorizontal',
    'itemPadding',
    'buttonBarStyle',
    'buttonBarButtonStyle',
    'segmentedButtonStyle',
    'staticWallpaperPreview',
    'allowParallelSyncs',
    'isAlwaysSyncable',
    'verticalScrollbarPosition',
    'fastScrollAlwaysVisible',
    'fastScrollThumbDrawable',
    'fastScrollPreviewBackgroundLeft',
    'fastScrollPreviewBackgroundRight',
    'fastScrollTrackDrawable',
    'fastScrollOverlayPosition',
    'customTokens',
    'nextFocusForward',
    'firstDayOfWeek',
    'showWeekNumber',
    'minDate',
    'maxDate',
    'shownWeekCount',
    'selectedWeekBackgroundColor',
    'focusedMonthDateColor',
    'unfocusedMonthDateColor',
    'weekNumberColor',
    'weekSeparatorLineColor',
    'selectedDateVerticalBar',
    'weekDayTextAppearance',
    'dateTextAppearance',
    'UNKNOWN',
    'spinnersShown',
    'calendarViewShown',
    'state_multiline',
    'detailsElementBackground',
    'textColorHighlightInverse',
    'textColorLinkInverse',
    'editTextColor',
    'editTextBackground',
    'horizontalScrollViewStyle',
    'layerType',
    'alertDialogIcon',
    'windowMinWidthMajor',
    'windowMinWidthMinor',
    'queryHint',
    'fastScrollTextColor',
    'largeHeap',
    'windowCloseOnTouchOutside',
    'datePickerStyle',
    'calendarViewStyle',
    'textEditSidePasteWindowLayout',
    'textEditSideNoPasteWindowLayout',
    'actionMenuTextAppearance',
    'actionMenuTextColor',
    'textCursorDrawable',
    'resizeMode',
    'requiresSmallestWidthDp',
    'compatibleWidthLimitDp',
    'largestWidthLimitDp',
    'state_hovered',
    'state_drag_can_accept',
    'state_drag_hovered',
    'stopWithTask',
    'switchTextOn',
    'switchTextOff',
    'switchPreferenceStyle',
    'switchTextAppearance',
    'track',
    'switchMinWidth',
    'switchPadding',
    'thumbTextPadding',
    'textSuggestionsWindowStyle',
    'textEditSuggestionItemLayout',
    'rowCount',
    'rowOrderPreserved',
    'columnCount',
    'columnOrderPreserved',
    'useDefaultMargins',
    'alignmentMode',
    'layout_row',
    'layout_rowSpan',
    'layout_columnSpan',
    'actionModeSelectAllDrawable',
    'isAuxiliary',
    'accessibilityEventTypes',
    'packageNames',
    'accessibilityFeedbackType',
    'notificationTimeout',
    'accessibilityFlags',
    'canRetrieveWindowContent',
    'listPreferredItemHeightLarge',
    'listPreferredItemHeightSmall',
    'actionBarSplitStyle',
    'actionProviderClass',
    'backgroundStacked',
    'backgroundSplit',
    'textAllCaps',
    'colorPressedHighlight',
    'colorLongPressedHighlight',
    'colorFocusedHighlight',
    'colorActivatedHighlight',
    'colorMultiSelectHighlight',
    'drawableStart',
    'drawableEnd',
    'actionModeStyle',
    'minResizeWidth',
    'minResizeHeight',
    'actionBarWidgetTheme',
    'uiOptions',
    'subtypeLocale',
    'subtypeExtraValue',
    'actionBarDivider',
    'actionBarItemBackground',
    'actionModeSplitBackground',
    'textAppearanceListItem',
    'textAppearanceListItemSmall',
    'targetDescriptions',
    'directionDescriptions',
    'overridesImplicitlyEnabledSubtype',
    'listPreferredItemPaddingLeft',
    'listPreferredItemPaddingRight',
    'requiresFadingEdge',
    'publicKey',
    'parentActivityName',
    'UNKNOWN',
    'isolatedProcess',
    'importantForAccessibility',
    'keyboardLayout',
    'fontFamily',
    'mediaRouteButtonStyle',
    'mediaRouteTypes',
    'supportsRtl',
    'textDirection',
    'textAlignment',
    'layoutDirection',
    'paddingStart',
    'paddingEnd',
    'layout_marginStart',
    'layout_marginEnd',
    'layout_toStartOf',
    'layout_toEndOf',
    'layout_alignStart',
    'layout_alignEnd',
    'layout_alignParentStart',
    'layout_alignParentEnd',
    'listPreferredItemPaddingStart',
    'listPreferredItemPaddingEnd',
    'singleUser',
    'presentationTheme',
    'subtypeId',
    'initialKeyguardLayout',
    'UNKNOWN',
    'widgetCategory',
    'permissionGroupFlags',
    'labelFor',
    'permissionFlags',
    'checkedTextViewStyle',
    'showOnLockScreen',
    'format12Hour',
    'format24Hour',
    'timeZone',
    'mipMap',
    'mirrorForRtl',
    'windowOverscan',
    'requiredForAllUsers',
    'indicatorStart',
    'indicatorEnd',
    'childIndicatorStart',
    'childIndicatorEnd',
    'restrictedAccountType',
    'requiredAccountType',
    'canRequestTouchExplorationMode',
    'canRequestEnhancedWebAccessibility',
    'canRequestFilterKeyEvents',
    'layoutMode',
    'keySet',
    'targetId',
    'fromScene',
    'toScene',
    'transition',
    'transitionOrdering',
    'fadingMode',
    'startDelay',
    'ssp',
    'sspPrefix',
    'sspPattern',
    'addPrintersActivity',
    'vendor',
    'category',
    'isAsciiCapable',
    'autoMirrored',
    'supportsSwitchingToNextInputMethod',
    'requireDeviceUnlock',
    'apduServiceBanner',
    'accessibilityLiveRegion',
    'windowTranslucentStatus',
    'windowTranslucentNavigation',
    'advancedPrintOptionsActivity',
    'banner',
    'windowSwipeToDismiss',
    'isGame',
    'allowEmbedded',
    'setupActivity',
    'fastScrollStyle',
    'windowContentTransitions',
    'windowContentTransitionManager',
    'translationZ',
    'tintMode',
    'controlX1',
    'controlY1',
    'controlX2',
    'controlY2',
    'transitionName',
    'transitionGroup',
    'viewportWidth',
    'viewportHeight',
    'fillColor',
    'pathData',
    'strokeColor',
    'strokeWidth',
    'trimPathStart',
    'trimPathEnd',
    'trimPathOffset',
    'strokeLineCap',
    'strokeLineJoin',
    'strokeMiterLimit',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'colorControlNormal',
    'colorControlActivated',
    'colorButtonNormal',
    'colorControlHighlight',
    'persistableMode',
    'titleTextAppearance',
    'subtitleTextAppearance',
    'slideEdge',
    'actionBarTheme',
    'textAppearanceListItemSecondary',
    'colorPrimary',
    'colorPrimaryDark',
    'colorAccent',
    'nestedScrollingEnabled',
    'windowEnterTransition',
    'windowExitTransition',
    'windowSharedElementEnterTransition',
    'windowSharedElementExitTransition',
    'windowAllowReturnTransitionOverlap',
    'windowAllowEnterTransitionOverlap',
    'sessionService',
    'stackViewStyle',
    'switchStyle',
    'elevation',
    'excludeId',
    'excludeClass',
    'hideOnContentScroll',
    'actionOverflowMenuStyle',
    'documentLaunchMode',
    'maxRecents',
    'autoRemoveFromRecents',
    'stateListAnimator',
    'toId',
    'fromId',
    'reversible',
    'splitTrack',
    'targetName',
    'excludeName',
    'matchOrder',
    'windowDrawsSystemBarBackgrounds',
    'statusBarColor',
    'navigationBarColor',
    'contentInsetStart',
    'contentInsetEnd',
    'contentInsetLeft',
    'contentInsetRight',
    'paddingMode',
    'layout_rowWeight',
    'layout_columnWeight',
    'translateX',
    'translateY',
    'selectableItemBackgroundBorderless',
    'elegantTextHeight',
    'UNKNOWN',
    'UNKNOWN',
    'UNKNOWN',
    'windowTransitionBackgroundFadeDuration',
    'overlapAnchor',
    'progressTint',
    'progressTintMode',
    'progressBackgroundTint',
    'progressBackgroundTintMode',
    'secondaryProgressTint',
    'secondaryProgressTintMode',
    'indeterminateTint',
    'indeterminateTintMode',
    'backgroundTint',
    'backgroundTintMode',
    'foregroundTint',
    'foregroundTintMode',
    'buttonTint',
    'buttonTintMode',
    'thumbTint',
    'thumbTintMode',
    'fullBackupOnly',
    'propertyXName',
    'propertyYName',
    'relinquishTaskIdentity',
    'tileModeX',
    'tileModeY',
    'actionModeShareDrawable',
    'actionModeFindDrawable',
    'actionModeWebSearchDrawable',
    'transitionVisibilityMode',
    'minimumHorizontalAngle',
    'minimumVerticalAngle',
    'maximumAngle',
    'searchViewStyle',
    'closeIcon',
    'goIcon',
    'searchIcon',
    'voiceIcon',
    'commitIcon',
    'suggestionRowLayout',
    'queryBackground',
    'submitBackground',
    'buttonBarPositiveButtonStyle',
    'buttonBarNeutralButtonStyle',
    'buttonBarNegativeButtonStyle',
    'popupElevation',
    'actionBarPopupTheme',
    'multiArch',
    'touchscreenBlocksFocus',
    'windowElevation',
    'launchTaskBehindTargetAnimation',
    'launchTaskBehindSourceAnimation',
    'restrictionType',
    'dayOfWeekBackground',
    'dayOfWeekTextAppearance',
    'headerMonthTextAppearance',
    'headerDayOfMonthTextAppearance',
    'headerYearTextAppearance',
    'yearListItemTextAppearance',
    'yearListSelectorColor',
    'calendarTextColor',
    'recognitionService',
    'timePickerStyle',
    'timePickerDialogTheme',
    'headerTimeTextAppearance',
    'headerAmPmTextAppearance',
    'numbersTextColor',
    'numbersBackgroundColor',
    'numbersSelectorColor',
    'amPmTextColor',
    'amPmBackgroundColor',
    'UNKNOWN',
    'checkMarkTint',
    'checkMarkTintMode',
    'popupTheme',
    'toolbarStyle',
    'windowClipToOutline',
    'datePickerDialogTheme',
    'showText',
    'windowReturnTransition',
    'windowReenterTransition',
    'windowSharedElementReturnTransition',
    'windowSharedElementReenterTransition',
    'resumeWhilePausing',
    'datePickerMode',
    'timePickerMode',
    'inset',
    'letterSpacing',
    'fontFeatureSettings',
    'outlineProvider',
    'contentAgeHint',
    'country',
    'windowSharedElementsUseOverlay',
    'reparent',
    'reparentWithOverlay',
    'ambientShadowAlpha',
    'spotShadowAlpha',
    'navigationIcon',
    'navigationContentDescription',
    'fragmentExitTransition',
    'fragmentEnterTransition',
    'fragmentSharedElementEnterTransition',
    'fragmentReturnTransition',
    'fragmentSharedElementReturnTransition',
    'fragmentReenterTransition',
    'fragmentAllowEnterTransitionOverlap',
    'fragmentAllowReturnTransitionOverlap',
    'patternPathData',
    'strokeAlpha',
    'fillAlpha',
    'windowActivityTransitions',
    'colorEdgeEffect',
    'resizeClip',
    'collapseContentDescription',
    'accessibilityTraversalBefore',
    'accessibilityTraversalAfter',
    'dialogPreferredPadding',
    'searchHintIcon',
    'revisionCode',
    'drawableTint',
    'drawableTintMode',
    'fraction',
    'trackTint',
    'trackTintMode',
    'start',
    'end',
    'breakStrategy',
    'hyphenationFrequency',
    'allowUndo',
    'windowLightStatusBar',
    'numbersInnerTextColor',
    'colorBackgroundFloating',
    'titleTextColor',
    'subtitleTextColor',
    'thumbPosition',
    'scrollIndicators',
    'contextClickable',
    'fingerprintAuthDrawable',
    'logoDescription',
    'extractNativeLibs',
    'fullBackupContent',
    'usesCleartextTraffic',
    'lockTaskMode',
    'autoVerify',
    'showForAllUsers',
    'supportsAssist',
    'supportsLaunchVoiceAssistFromKeyguard',
    'listMenuViewStyle',
    'subMenuArrow',
    'defaultWidth',
    'defaultHeight',
    'resizeableActivity',
    'supportsPictureInPicture',
    'titleMargin',
    'titleMarginStart',
    'titleMarginEnd',
    'titleMarginTop',
    'titleMarginBottom',
    'maxButtonHeight',
    'buttonGravity',
    'collapseIcon',
    'level',
    'contextPopupMenuStyle',
    'textAppearancePopupMenuHeader',
    'windowBackgroundFallback',
    'defaultToDeviceProtectedStorage',
    'directBootAware',
    'preferenceFragmentStyle',
    'canControlMagnification',
    'languageTag',
    'pointerIcon',
    'tickMark',
    'tickMarkTint',
    'tickMarkTintMode',
    'canPerformGestures',
    'externalService',
    'supportsLocalInteraction',
    'startX',
    'startY',
    'endX',
    'endY',
    'offset',
    'use32bitAbi',
    'bitmap',
    'hotSpotX',
    'hotSpotY',
    'version',
    'backupInForeground',
    'countDown',
    'canRecord',
    'tunerCount',
    'fillType',
    'popupEnterTransition',
    'popupExitTransition',
    'forceHasOverlappingRendering',
    'contentInsetStartWithNavigation',
    'contentInsetEndWithActions',
    'numberPickerStyle',
    'enableVrMode',
    'UNKNOWN',
    'networkSecurityConfig',
    'shortcutId',
    'shortcutShortLabel',
    'shortcutLongLabel',
    'shortcutDisabledMessage',
    'roundIcon',
    'contextUri',
    'contextDescription',
    'showMetadataInPreview',
    'colorSecondary',
  ];
}
