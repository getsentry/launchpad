/* eslint-disable no-bitwise */

/**
 * Shared types (AXML and resource table - arsc)
 * See frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h
 * for full definitions & types.
 */

export enum NodeType {
  ELEMENT_NODE = 1,
  ATTRIBUTE_NODE = 2,
  CDATA_SECTION_NODE = 4,
}

export enum ChunkType {
  NULL = 0x0000,
  STRING_POOL = 0x0001,
  TABLE = 0x0002,
  XML = 0x0003,
  XML_START_NAMESPACE = 0x0100,
  XML_END_NAMESPACE = 0x0101,
  XML_START_ELEMENT = 0x0102,
  XML_END_ELEMENT = 0x0103,
  XML_CDATA = 0x0104,
  XML_RESOURCE_MAP = 0x0180,
  TABLE_PACKAGE = 0x0200,
  TABLE_TYPE = 0x0201,
  TABLE_TYPE_SPEC = 0x0202,
  TABLE_LIBRARY = 0x0203,
}

export enum StringFlags {
  SORTED = 1 << 0,
  UTF8 = 1 << 8,
}

export enum TypeFlags {
  SPARSE = 1 << 0,
}

export interface Dimension {
  value: number;
  unit: string;
  rawUnit: number;
}

export interface Fraction {
  value: number;
  type: string;
  rawType?: number;
}

export interface TypedValue {
  value: any;
  type: string;
  rawType: TypedValueRawType;
}

// Taken from android.util.TypedValue
export enum TypedValueRawType {
  COMPLEX_MANTISSA_MASK = 0x00ffffff,
  COMPLEX_MANTISSA_SHIFT = 0x00000008,
  COMPLEX_RADIX_0p23 = 0x00000003,
  COMPLEX_RADIX_16p7 = 0x00000001,
  COMPLEX_RADIX_23p0 = 0x00000000,
  COMPLEX_RADIX_8p15 = 0x00000002,
  COMPLEX_RADIX_MASK = 0x00000003,
  COMPLEX_RADIX_SHIFT = 0x00000004,
  COMPLEX_UNIT_DIP = 0x00000001,
  COMPLEX_UNIT_FRACTION = 0x00000000,
  COMPLEX_UNIT_FRACTION_PARENT = 0x00000001,
  COMPLEX_UNIT_IN = 0x00000004,
  COMPLEX_UNIT_MASK = 0x0000000f,
  COMPLEX_UNIT_MM = 0x00000005,
  COMPLEX_UNIT_PT = 0x00000003,
  COMPLEX_UNIT_PX = 0x00000000,
  COMPLEX_UNIT_SHIFT = 0x00000000,
  COMPLEX_UNIT_SP = 0x00000002,
  DENSITY_DEFAULT = 0x00000000,
  DENSITY_NONE = 0x0000ffff,
  TYPE_ATTRIBUTE = 0x00000002,
  TYPE_DIMENSION = 0x00000005,
  TYPE_FIRST_COLOR_INT = 0x0000001c,
  TYPE_FIRST_INT = 0x00000010,
  TYPE_FLOAT = 0x00000004,
  TYPE_FRACTION = 0x00000006,
  TYPE_INT_BOOLEAN = 0x00000012,
  TYPE_INT_COLOR_ARGB4 = 0x0000001e,
  TYPE_INT_COLOR_ARGB8 = 0x0000001c,
  TYPE_INT_COLOR_RGB4 = 0x0000001f,
  TYPE_INT_COLOR_RGB8 = 0x0000001d,
  TYPE_INT_DEC = 0x00000010,
  TYPE_INT_HEX = 0x00000011,
  TYPE_LAST_COLOR_INT = 0x0000001f,
  TYPE_LAST_INT = 0x0000001f,
  TYPE_NULL = 0x00000000,
  TYPE_REFERENCE = 0x00000001,
  TYPE_STRING = 0x00000003,
}

export enum EntryFlags {
  COMPLEX = 0x0001,
  COMPACT = 0x0008,
}

export interface StringPool {
  stringCount: number;
  styleCount: number;
  flags: StringFlags;
  stringsStart: number;
  stylesStart: number;
  strings: string[];
}

/**
 * AXML types
 */

export interface XmlAttribute {
  namespaceURI?: string;
  nodeType: NodeType;
  nodeName?: string;
  name?: string;
  value?: string;
  typedValue: TypedValue;
}

export interface XmlNode {
  namespaceURI?: string;
  nodeType: NodeType;
  nodeName?: string;
  attributes: XmlAttribute[];
  childNodes: XmlNode[];
}

export interface XmlCData extends XmlNode {
  data?: string;
  typedValue: TypedValue;
}

/**
 * Resource table (arsc) types
 */

export interface ResourceTablePackage {
  id: number;
  name: string;
  types: ResourceTableType[];
}

export interface ResourceTableType {
  id: number;
  name: string;
  config: ResourceTypeConfig;
  // TODO: Maybe use a map in the future for easier id lookup
  entries: ResourceTableEntry[];
}

export enum TypeName {}

// See https://android.googlesource.com/platform/frameworks/base/+/master/libs/androidfw/include/androidfw/ResourceTypes.h#950
// for all, we only care about language/region for string resources
export interface ResourceTypeConfig {
  size: number;
  language: string;
  region: string;
}

export interface ResourceTableEntry {
  size: number;
  flags: number;
  id: number;
  key: string;
  parentEntry: number;
  value?: TypedValue;
  values: Map<number, TypedValue>;
}
export interface ChunkHeader {
  startOffset: number;
  chunkType: ChunkType;
  headerSize: number;
  chunkSize: number;
}
