/* eslint-disable */
import { Reader, Writer, configure, util } from 'protobufjs/minimal';
// @ts-ignore
import * as Long from 'long';
import { Configuration } from './Configuration';

export const protobufPackage = 'aapt.pb';

// Taken from https://android.googlesource.com/platform/frameworks/base/+/master/tools/aapt2/Resources.proto
// and added TS representation for parsing in Typescript.

/** A string pool that wraps the binary form of the C++ class android::ResStringPool. */
export interface StringPool {
  data: Uint8Array;
}

/** The position of a declared entity within a file. */
export interface SourcePosition {
  lineNumber: number;
  columnNumber: number;
}

/** Developer friendly source file information for an entity in the resource table. */
export interface Source {
  /** The index of the string path within the source string pool of a ResourceTable. */
  pathIdx: number;
  position?: SourcePosition;
}

/** The name and version fingerprint of a build tool. */
export interface ToolFingerprint {
  tool: string;
  version: string;
}

/** Top level message representing a resource table. */
export interface ResourceTable {
  /**
   * The string pool containing source paths referenced throughout the resource table. This does
   * not end up in the final binary ARSC file.
   */
  sourcePool?: StringPool;
  /** Resource definitions corresponding to an Android package. */
  package: Package[];
  /** The <overlayable> declarations within the resource table. */
  overlayable: Overlayable[];
  /** The version fingerprints of the tools that built the resource table. */
  toolFingerprint: ToolFingerprint[];
}

/** A package ID in the range [0x00, 0xff]. */
export interface PackageId {
  id: number;
}

/** Defines resources for an Android package. */
export interface Package {
  /**
   * The package ID of this package, in the range [0x00, 0xff].
   * - ID 0x00 is reserved for shared libraries, or when the ID is assigned at run-time.
   * - ID 0x01 is reserved for the 'android' package (framework).
   * - ID range [0x02, 0x7f) is reserved for auto-assignment to shared libraries at run-time.
   * - ID 0x7f is reserved for the application package.
   * - IDs > 0x7f are reserved for the application as well and are treated as feature splits.
   * This may not be set if no ID was assigned.
   */
  packageId?: PackageId;
  /** The Java compatible Android package name of the app. */
  packageName: string;
  /** The series of types defined by the package. */
  type: Type[];
}

/** A type ID in the range [0x01, 0xff]. */
export interface TypeId {
  id: number;
}

/**
 * A set of resources grouped under a common type. Such types include string, layout, xml, dimen,
 * attr, etc. This maps to the second part of a resource identifier in Java (R.type.entry).
 */
export interface Type {
  /** The ID of the type. This may not be set if no ID was assigned. */
  typeId?: TypeId;
  /**
   * The name of the type. This corresponds to the 'type' part of a full resource name of the form
   * package:type/entry. The set of legal type names is listed in Resource.cpp.
   */
  name: string;
  /** The entries defined for this type. */
  entry: Entry[];
}

/** The Visibility of a symbol/entry (public, private, undefined). */
export interface Visibility {
  level: Visibility_Level;
  /** The path at which this entry's visibility was defined (eg. public.xml). */
  source?: Source;
  /** The comment associated with the <public> tag. */
  comment: string;
  /**
   * Indicates that the resource id may change across builds and that the public R.java identifier
   * for this resource should not be final. This is set to `true` for resources in `staging-group`
   * tags.
   */
  stagedApi: boolean;
}

/** The visibility of the resource outside of its package. */
export enum Visibility_Level {
  /**
   * UNKNOWN - No visibility was explicitly specified. This is typically treated as private.
   * The distinction is important when two separate R.java files are generated: a public and
   * private one. An unknown visibility, in this case, would cause the resource to be omitted
   * from either R.java.
   */
  UNKNOWN = 0,
  /**
   * PRIVATE - A resource was explicitly marked as private. This means the resource can not be accessed
   * outside of its package unless the @*package:type/entry notation is used (the asterisk being
   * the private accessor). If two R.java files are generated (private + public), the resource
   * will only be emitted to the private R.java file.
   */
  PRIVATE = 1,
  /**
   * PUBLIC - A resource was explicitly marked as public. This means the resource can be accessed
   * from any package, and is emitted into all R.java files, public and private.
   */
  PUBLIC = 2,
  UNRECOGNIZED = -1,
}

export function visibility_LevelFromJSON(object: any): Visibility_Level {
  switch (object) {
    case 0:
    case 'UNKNOWN':
      return Visibility_Level.UNKNOWN;
    case 1:
    case 'PRIVATE':
      return Visibility_Level.PRIVATE;
    case 2:
    case 'PUBLIC':
      return Visibility_Level.PUBLIC;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Visibility_Level.UNRECOGNIZED;
  }
}

export function visibility_LevelToJSON(object: Visibility_Level): string {
  switch (object) {
    case Visibility_Level.UNKNOWN:
      return 'UNKNOWN';
    case Visibility_Level.PRIVATE:
      return 'PRIVATE';
    case Visibility_Level.PUBLIC:
      return 'PUBLIC';
    default:
      return 'UNKNOWN';
  }
}

/**
 * Whether a resource comes from a compile-time overlay and is explicitly allowed to not overlay an
 * existing resource.
 */
export interface AllowNew {
  /** Where this was defined in source. */
  source?: Source;
  /** Any comment associated with the declaration. */
  comment: string;
}

/** Represents a set of overlayable resources. */
export interface Overlayable {
  /** The name of the <overlayable>. */
  name: string;
  /** The location of the <overlayable> declaration in the source. */
  source?: Source;
  /** The component responsible for enabling and disabling overlays targeting this <overlayable>. */
  actor: string;
}

/** Represents an overlayable <item> declaration within an <overlayable> tag. */
export interface OverlayableItem {
  /** The location of the <item> declaration in source. */
  source?: Source;
  /** Any comment associated with the declaration. */
  comment: string;
  /** The policy defined by the enclosing <policy> tag of this <item>. */
  policy: OverlayableItem_Policy[];
  /**
   * The index into overlayable list that points to the <overlayable> tag that contains
   * this <item>.
   */
  overlayableIdx: number;
}

export enum OverlayableItem_Policy {
  NONE = 0,
  PUBLIC = 1,
  SYSTEM = 2,
  VENDOR = 3,
  PRODUCT = 4,
  SIGNATURE = 5,
  ODM = 6,
  OEM = 7,
  ACTOR = 8,
  CONFIG_SIGNATURE = 9,
  UNRECOGNIZED = -1,
}

export function overlayableItem_PolicyFromJSON(object: any): OverlayableItem_Policy {
  switch (object) {
    case 0:
    case 'NONE':
      return OverlayableItem_Policy.NONE;
    case 1:
    case 'PUBLIC':
      return OverlayableItem_Policy.PUBLIC;
    case 2:
    case 'SYSTEM':
      return OverlayableItem_Policy.SYSTEM;
    case 3:
    case 'VENDOR':
      return OverlayableItem_Policy.VENDOR;
    case 4:
    case 'PRODUCT':
      return OverlayableItem_Policy.PRODUCT;
    case 5:
    case 'SIGNATURE':
      return OverlayableItem_Policy.SIGNATURE;
    case 6:
    case 'ODM':
      return OverlayableItem_Policy.ODM;
    case 7:
    case 'OEM':
      return OverlayableItem_Policy.OEM;
    case 8:
    case 'ACTOR':
      return OverlayableItem_Policy.ACTOR;
    case 9:
    case 'CONFIG_SIGNATURE':
      return OverlayableItem_Policy.CONFIG_SIGNATURE;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return OverlayableItem_Policy.UNRECOGNIZED;
  }
}

export function overlayableItem_PolicyToJSON(object: OverlayableItem_Policy): string {
  switch (object) {
    case OverlayableItem_Policy.NONE:
      return 'NONE';
    case OverlayableItem_Policy.PUBLIC:
      return 'PUBLIC';
    case OverlayableItem_Policy.SYSTEM:
      return 'SYSTEM';
    case OverlayableItem_Policy.VENDOR:
      return 'VENDOR';
    case OverlayableItem_Policy.PRODUCT:
      return 'PRODUCT';
    case OverlayableItem_Policy.SIGNATURE:
      return 'SIGNATURE';
    case OverlayableItem_Policy.ODM:
      return 'ODM';
    case OverlayableItem_Policy.OEM:
      return 'OEM';
    case OverlayableItem_Policy.ACTOR:
      return 'ACTOR';
    case OverlayableItem_Policy.CONFIG_SIGNATURE:
      return 'CONFIG_SIGNATURE';
    default:
      return 'UNKNOWN';
  }
}

/** The staged resource ID definition of a finalized resource. */
export interface StagedId {
  source?: Source;
  stagedId: number;
}

/** An entry ID in the range [0x0000, 0xffff]. */
export interface EntryId {
  id: number;
}

/**
 * An entry declaration. An entry has a full resource ID that is the combination of package ID,
 * type ID, and its own entry ID. An entry on its own has no value, but values are defined for
 * various configurations/variants.
 */
export interface Entry {
  /**
   * The ID of this entry. Together with the package ID and type ID, this forms a full resource ID
   * of the form 0xPPTTEEEE, where PP is the package ID, TT is the type ID, and EEEE is the entry
   * ID.
   * This may not be set if no ID was assigned.
   */
  entryId?: EntryId;
  /**
   * The name of this entry. This corresponds to the 'entry' part of a full resource name of the
   * form package:type/entry.
   */
  name: string;
  /** The visibility of this entry (public, private, undefined). */
  visibility?: Visibility;
  /**
   * Whether this resource, when originating from a compile-time overlay, is allowed to NOT overlay
   * any existing resources.
   */
  allowNew?: AllowNew;
  /** Whether this resource can be overlaid by a runtime resource overlay (RRO). */
  overlayableItem?: OverlayableItem;
  /**
   * The set of values defined for this entry, each corresponding to a different
   * configuration/variant.
   */
  configValue: ConfigValue[];
  /** The staged resource ID of this finalized resource. */
  stagedId?: StagedId;
}

/** A Configuration/Value pair. */
export interface ConfigValue {
  config?: Configuration;
  value?: Value;
}

/** The generic meta-data for every value in a resource table. */
export interface Value {
  /** Where the value was defined. */
  source?: Source;
  /** Any comment associated with the value. */
  comment: string;
  /** Whether the value can be overridden. */
  weak: boolean;
  value?: { $case: 'item'; item: Item } | { $case: 'compoundValue'; compoundValue: CompoundValue };
}

/**
 * An Item is an abstract type. It represents a value that can appear inline in many places, such
 * as XML attribute values or on the right hand side of style attribute definitions. The concrete
 * type is one of the types below. Only one can be set.
 */
export interface Item {
  value?:
    | { $case: 'ref'; ref: Reference }
    | { $case: 'str'; str: String }
    | { $case: 'rawStr'; rawStr: RawString }
    | { $case: 'styledStr'; styledStr: StyledString }
    | { $case: 'file'; file: FileReference }
    | { $case: 'id'; id: Id }
    | { $case: 'prim'; prim: Primitive };
}

/**
 * A CompoundValue is an abstract type. It represents a value that is a made of other values.
 * These can only usually appear as top-level resources. The concrete type is one of the types
 * below. Only one can be set.
 */
export interface CompoundValue {
  value?:
    | { $case: 'attr'; attr: Attribute }
    | { $case: 'style'; style: Style }
    | { $case: 'styleable'; styleable: Styleable }
    | { $case: 'array'; array: Array }
    | { $case: 'plural'; plural: Plural }
    | { $case: 'macro'; macro: MacroBody };
}

/** Message holding a boolean, so it can be optionally encoded. */
export interface Boolean {
  value: boolean;
}

/** A value that is a reference to another resource. This reference can be by name or resource ID. */
export interface Reference {
  type: Reference_Type;
  /** The resource ID (0xPPTTEEEE) of the resource being referred. This is optional. */
  id: number;
  /** The name of the resource being referred. This is optional if the resource ID is set. */
  name: string;
  /** Whether this reference is referencing a private resource (@*package:type/entry). */
  private: boolean;
  /** Whether this reference is dynamic. */
  isDynamic?: Boolean;
  /** The type flags used when compiling the reference. Used for substituting the contents of macros. */
  typeFlags: number;
  /**
   * Whether raw string values would have been accepted in place of this reference definition. Used
   * for substituting the contents of macros.
   */
  allowRaw: boolean;
}

export enum Reference_Type {
  /** REFERENCE - A plain reference (@package:type/entry). */
  REFERENCE = 0,
  /** ATTRIBUTE - A reference to a theme attribute (?package:type/entry). */
  ATTRIBUTE = 1,
  UNRECOGNIZED = -1,
}

export function reference_TypeFromJSON(object: any): Reference_Type {
  switch (object) {
    case 0:
    case 'REFERENCE':
      return Reference_Type.REFERENCE;
    case 1:
    case 'ATTRIBUTE':
      return Reference_Type.ATTRIBUTE;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Reference_Type.UNRECOGNIZED;
  }
}

export function reference_TypeToJSON(object: Reference_Type): string {
  switch (object) {
    case Reference_Type.REFERENCE:
      return 'REFERENCE';
    case Reference_Type.ATTRIBUTE:
      return 'ATTRIBUTE';
    default:
      return 'UNKNOWN';
  }
}

/**
 * A value that represents an ID. This is just a placeholder, as ID values are used to occupy a
 * resource ID (0xPPTTEEEE) as a unique identifier. Their value is unimportant.
 */
export interface Id {}

/** A value that is a string. */
export interface String {
  value: string;
}

/**
 * A value that is a raw string, which is unescaped/uninterpreted. This is typically used to
 * represent the value of a style attribute before the attribute is compiled and the set of
 * allowed values is known.
 */
export interface RawString {
  value: string;
}

/** A string with styling information, like html tags that specify boldness, italics, etc. */
export interface StyledString {
  /** The raw text of the string. */
  value: string;
  span: StyledString_Span[];
}

/** A Span marks a region of the string text that is styled. */
export interface StyledString_Span {
  /**
   * The name of the tag, and its attributes, encoded as follows:
   * tag_name;attr1=value1;attr2=value2;[...]
   */
  tag: string;
  /** The first character position this span applies to, in UTF-16 offset. */
  firstChar: number;
  /** The last character position this span applies to, in UTF-16 offset. */
  lastChar: number;
}

/** A value that is a reference to an external entity, like an XML file or a PNG. */
export interface FileReference {
  /** Path to a file within the APK (typically res/type-config/entry.ext). */
  path: string;
  /**
   * The type of file this path points to. For UAM bundle, this cannot be
   * BINARY_XML.
   */
  type: FileReference_Type;
}

export enum FileReference_Type {
  UNKNOWN = 0,
  PNG = 1,
  BINARY_XML = 2,
  PROTO_XML = 3,
  UNRECOGNIZED = -1,
}

export function fileReference_TypeFromJSON(object: any): FileReference_Type {
  switch (object) {
    case 0:
    case 'UNKNOWN':
      return FileReference_Type.UNKNOWN;
    case 1:
    case 'PNG':
      return FileReference_Type.PNG;
    case 2:
    case 'BINARY_XML':
      return FileReference_Type.BINARY_XML;
    case 3:
    case 'PROTO_XML':
      return FileReference_Type.PROTO_XML;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return FileReference_Type.UNRECOGNIZED;
  }
}

export function fileReference_TypeToJSON(object: FileReference_Type): string {
  switch (object) {
    case FileReference_Type.UNKNOWN:
      return 'UNKNOWN';
    case FileReference_Type.PNG:
      return 'PNG';
    case FileReference_Type.BINARY_XML:
      return 'BINARY_XML';
    case FileReference_Type.PROTO_XML:
      return 'PROTO_XML';
    default:
      return 'UNKNOWN';
  }
}

/**
 * A value that represents a primitive data type (float, int, boolean, etc.).
 * Refer to Res_value in ResourceTypes.h for info on types and formatting
 */
export interface Primitive {
  oneofValue?:
    | { $case: 'nullValue'; nullValue: Primitive_NullType }
    | { $case: 'emptyValue'; emptyValue: Primitive_EmptyType }
    | { $case: 'floatValue'; floatValue: number }
    | { $case: 'dimensionValue'; dimensionValue: number }
    | { $case: 'fractionValue'; fractionValue: number }
    | { $case: 'intDecimalValue'; intDecimalValue: number }
    | { $case: 'intHexadecimalValue'; intHexadecimalValue: number }
    | { $case: 'booleanValue'; booleanValue: boolean }
    | { $case: 'colorArgb8Value'; colorArgb8Value: number }
    | { $case: 'colorRgb8Value'; colorRgb8Value: number }
    | { $case: 'colorArgb4Value'; colorArgb4Value: number }
    | { $case: 'colorRgb4Value'; colorRgb4Value: number }
    | { $case: 'dimensionValueDeprecated'; dimensionValueDeprecated: number }
    | { $case: 'fractionValueDeprecated'; fractionValueDeprecated: number };
}

export interface Primitive_NullType {}

export interface Primitive_EmptyType {}

/** A value that represents an XML attribute and what values it accepts. */
export interface Attribute {
  /**
   * A bitmask of types that this XML attribute accepts. Corresponds to the flags in the
   * enum FormatFlags.
   */
  formatFlags: number;
  /**
   * The smallest integer allowed for this XML attribute. Only makes sense if the format includes
   * FormatFlags::INTEGER.
   */
  minInt: number;
  /**
   * The largest integer allowed for this XML attribute. Only makes sense if the format includes
   * FormatFlags::INTEGER.
   */
  maxInt: number;
  /**
   * The set of enums/flags defined in this attribute. Only makes sense if the format includes
   * either FormatFlags::ENUM or FormatFlags::FLAGS. Having both is an error.
   */
  symbol: Attribute_Symbol[];
}

/** Bitmask of formats allowed for an attribute. */
export enum Attribute_FormatFlags {
  /** NONE - Proto3 requires a default of 0. */
  NONE = 0,
  /** ANY - Allows any type except ENUM and FLAGS. */
  ANY = 65535,
  /** REFERENCE - Allows Reference values. */
  REFERENCE = 1,
  /** STRING - Allows String/StyledString values. */
  STRING = 2,
  /** INTEGER - Allows any integer BinaryPrimitive values. */
  INTEGER = 4,
  /** BOOLEAN - Allows any boolean BinaryPrimitive values. */
  BOOLEAN = 8,
  /** COLOR - Allows any color BinaryPrimitive values. */
  COLOR = 16,
  /** FLOAT - Allows any float BinaryPrimitive values. */
  FLOAT = 32,
  /** DIMENSION - Allows any dimension BinaryPrimitive values. */
  DIMENSION = 64,
  /** FRACTION - Allows any fraction BinaryPrimitive values. */
  FRACTION = 128,
  /** ENUM - Allows enums that are defined in the Attribute's symbols. */
  ENUM = 65536,
  /** FLAGS - ENUM and FLAGS cannot BOTH be set. */
  FLAGS = 131072,
  UNRECOGNIZED = -1,
}

export function attribute_FormatFlagsFromJSON(object: any): Attribute_FormatFlags {
  switch (object) {
    case 0:
    case 'NONE':
      return Attribute_FormatFlags.NONE;
    case 65535:
    case 'ANY':
      return Attribute_FormatFlags.ANY;
    case 1:
    case 'REFERENCE':
      return Attribute_FormatFlags.REFERENCE;
    case 2:
    case 'STRING':
      return Attribute_FormatFlags.STRING;
    case 4:
    case 'INTEGER':
      return Attribute_FormatFlags.INTEGER;
    case 8:
    case 'BOOLEAN':
      return Attribute_FormatFlags.BOOLEAN;
    case 16:
    case 'COLOR':
      return Attribute_FormatFlags.COLOR;
    case 32:
    case 'FLOAT':
      return Attribute_FormatFlags.FLOAT;
    case 64:
    case 'DIMENSION':
      return Attribute_FormatFlags.DIMENSION;
    case 128:
    case 'FRACTION':
      return Attribute_FormatFlags.FRACTION;
    case 65536:
    case 'ENUM':
      return Attribute_FormatFlags.ENUM;
    case 131072:
    case 'FLAGS':
      return Attribute_FormatFlags.FLAGS;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Attribute_FormatFlags.UNRECOGNIZED;
  }
}

export function attribute_FormatFlagsToJSON(object: Attribute_FormatFlags): string {
  switch (object) {
    case Attribute_FormatFlags.NONE:
      return 'NONE';
    case Attribute_FormatFlags.ANY:
      return 'ANY';
    case Attribute_FormatFlags.REFERENCE:
      return 'REFERENCE';
    case Attribute_FormatFlags.STRING:
      return 'STRING';
    case Attribute_FormatFlags.INTEGER:
      return 'INTEGER';
    case Attribute_FormatFlags.BOOLEAN:
      return 'BOOLEAN';
    case Attribute_FormatFlags.COLOR:
      return 'COLOR';
    case Attribute_FormatFlags.FLOAT:
      return 'FLOAT';
    case Attribute_FormatFlags.DIMENSION:
      return 'DIMENSION';
    case Attribute_FormatFlags.FRACTION:
      return 'FRACTION';
    case Attribute_FormatFlags.ENUM:
      return 'ENUM';
    case Attribute_FormatFlags.FLAGS:
      return 'FLAGS';
    default:
      return 'UNKNOWN';
  }
}

/** A Symbol used to represent an enum or a flag. */
export interface Attribute_Symbol {
  /** Where the enum/flag item was defined. */
  source?: Source;
  /** Any comments associated with the enum or flag. */
  comment: string;
  /**
   * The name of the enum/flag as a reference. Enums/flag items are generated as ID resource
   * values.
   */
  name?: Reference;
  /** The value of the enum/flag. */
  value: number;
  /** The data type of the enum/flag as defined in android::Res_value. */
  type: number;
}

/** A value that represents a style. */
export interface Style {
  /** The optinal style from which this style inherits attributes. */
  parent?: Reference;
  /** The source file information of the parent inheritance declaration. */
  parentSource?: Source;
  /** The set of XML attribute/value pairs for this style. */
  entry: Style_Entry[];
}

/** An XML attribute/value pair defined in the style. */
export interface Style_Entry {
  /** Where the entry was defined. */
  source?: Source;
  /** Any comments associated with the entry. */
  comment: string;
  /** A reference to the XML attribute. */
  key?: Reference;
  /** The Item defined for this XML attribute. */
  item?: Item;
}

/**
 * A value that represents a <declare-styleable> XML resource. These are not real resources and
 * only end up as Java fields in the generated R.java. They do not end up in the binary ARSC file.
 */
export interface Styleable {
  /** The set of attribute declarations. */
  entry: Styleable_Entry[];
}

/** An attribute defined for this styleable. */
export interface Styleable_Entry {
  /** Where the attribute was defined within the <declare-styleable> block. */
  source?: Source;
  /** Any comments associated with the declaration. */
  comment: string;
  /** The reference to the attribute. */
  attr?: Reference;
}

/** A value that represents an array of resource values. */
export interface Array {
  /** The list of array elements. */
  element: Array_Element[];
}

/** A single element of the array. */
export interface Array_Element {
  /** Where the element was defined. */
  source?: Source;
  /** Any comments associated with the element. */
  comment: string;
  /** The value assigned to this element. */
  item?: Item;
}

/** A value that represents a string and its many variations based on plurality. */
export interface Plural {
  /** The set of arity/plural mappings. */
  entry: Plural_Entry[];
}

/** The arity of the plural. */
export enum Plural_Arity {
  ZERO = 0,
  ONE = 1,
  TWO = 2,
  FEW = 3,
  MANY = 4,
  OTHER = 5,
  UNRECOGNIZED = -1,
}

export function plural_ArityFromJSON(object: any): Plural_Arity {
  switch (object) {
    case 0:
    case 'ZERO':
      return Plural_Arity.ZERO;
    case 1:
    case 'ONE':
      return Plural_Arity.ONE;
    case 2:
    case 'TWO':
      return Plural_Arity.TWO;
    case 3:
    case 'FEW':
      return Plural_Arity.FEW;
    case 4:
    case 'MANY':
      return Plural_Arity.MANY;
    case 5:
    case 'OTHER':
      return Plural_Arity.OTHER;
    case -1:
    case 'UNRECOGNIZED':
    default:
      return Plural_Arity.UNRECOGNIZED;
  }
}

export function plural_ArityToJSON(object: Plural_Arity): string {
  switch (object) {
    case Plural_Arity.ZERO:
      return 'ZERO';
    case Plural_Arity.ONE:
      return 'ONE';
    case Plural_Arity.TWO:
      return 'TWO';
    case Plural_Arity.FEW:
      return 'FEW';
    case Plural_Arity.MANY:
      return 'MANY';
    case Plural_Arity.OTHER:
      return 'OTHER';
    default:
      return 'UNKNOWN';
  }
}

/** The plural value for a given arity. */
export interface Plural_Entry {
  /** Where the plural was defined. */
  source?: Source;
  /** Any comments associated with the plural. */
  comment: string;
  /** The arity of the plural. */
  arity: Plural_Arity;
  /** The value assigned to this plural. */
  item?: Item;
}

/**
 * Defines an abstract XmlNode that must be either an XmlElement, or
 * a text node represented by a string.
 */
export interface XmlNode {
  node?: { $case: 'element'; element: XmlElement } | { $case: 'text'; text: string };
  /** Source line and column info. */
  source?: SourcePosition;
}

/** An <element> in an XML document. */
export interface XmlElement {
  /** Namespaces defined on this element. */
  namespaceDeclaration: XmlNamespace[];
  /** The namespace URI of this element. */
  namespaceUri: string;
  /** The name of this element. */
  name: string;
  /** The attributes of this element. */
  attribute: XmlAttribute[];
  /** The children of this element. */
  child: XmlNode[];
}

/** A namespace declaration on an XmlElement (xmlns:android="http://..."). */
export interface XmlNamespace {
  prefix: string;
  uri: string;
  /** Source line and column info. */
  source?: SourcePosition;
}

/** An attribute defined on an XmlElement (android:text="..."). */
export interface XmlAttribute {
  namespaceUri: string;
  name: string;
  value: string;
  /** Source line and column info. */
  source?: SourcePosition;
  /** The optional resource ID (0xPPTTEEEE) of the attribute. */
  resourceId: number;
  /** The optional interpreted/compiled version of the `value` string. */
  compiledItem?: Item;
}

export interface MacroBody {
  rawString: string;
  styleString?: StyleString;
  untranslatableSections: UntranslatableSection[];
  namespaceStack: NamespaceAlias[];
  source?: SourcePosition;
}

export interface NamespaceAlias {
  prefix: string;
  packageName: string;
  isPrivate: boolean;
}

export interface StyleString {
  str: string;
  spans: StyleString_Span[];
}

export interface StyleString_Span {
  name: string;
  startIndex: number;
  endIndex: number;
}

export interface UntranslatableSection {
  startIndex: number;
  endIndex: number;
}

const baseStringPool: object = {};

export const StringPool = {
  encode(message: StringPool, writer: Writer = Writer.create()): Writer {
    if (message.data.length !== 0) {
      writer.uint32(10).bytes(message.data);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): StringPool {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseStringPool } as StringPool;
    message.data = new Uint8Array();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.data = reader.bytes();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): StringPool {
    const message = { ...baseStringPool } as StringPool;
    message.data = new Uint8Array();
    if (object.data !== undefined && object.data !== null) {
      message.data = bytesFromBase64(object.data);
    }
    return message;
  },

  toJSON(message: StringPool): unknown {
    const obj: any = {};
    message.data !== undefined &&
      (obj.data = base64FromBytes(message.data !== undefined ? message.data : new Uint8Array()));
    return obj;
  },

  fromPartial(object: DeepPartial<StringPool>): StringPool {
    const message = { ...baseStringPool } as StringPool;
    if (object.data !== undefined && object.data !== null) {
      message.data = object.data;
    } else {
      message.data = new Uint8Array();
    }
    return message;
  },
};

const baseSourcePosition: object = { lineNumber: 0, columnNumber: 0 };

export const SourcePosition = {
  encode(message: SourcePosition, writer: Writer = Writer.create()): Writer {
    if (message.lineNumber !== 0) {
      writer.uint32(8).uint32(message.lineNumber);
    }
    if (message.columnNumber !== 0) {
      writer.uint32(16).uint32(message.columnNumber);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): SourcePosition {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseSourcePosition } as SourcePosition;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.lineNumber = reader.uint32();
          break;
        case 2:
          message.columnNumber = reader.uint32();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): SourcePosition {
    const message = { ...baseSourcePosition } as SourcePosition;
    if (object.lineNumber !== undefined && object.lineNumber !== null) {
      message.lineNumber = Number(object.lineNumber);
    }
    if (object.columnNumber !== undefined && object.columnNumber !== null) {
      message.columnNumber = Number(object.columnNumber);
    }
    return message;
  },

  toJSON(message: SourcePosition): unknown {
    const obj: any = {};
    message.lineNumber !== undefined && (obj.lineNumber = message.lineNumber);
    message.columnNumber !== undefined && (obj.columnNumber = message.columnNumber);
    return obj;
  },

  fromPartial(object: DeepPartial<SourcePosition>): SourcePosition {
    const message = { ...baseSourcePosition } as SourcePosition;
    if (object.lineNumber !== undefined && object.lineNumber !== null) {
      message.lineNumber = object.lineNumber;
    } else {
      message.lineNumber = 0;
    }
    if (object.columnNumber !== undefined && object.columnNumber !== null) {
      message.columnNumber = object.columnNumber;
    } else {
      message.columnNumber = 0;
    }
    return message;
  },
};

const baseSource: object = { pathIdx: 0 };

export const Source = {
  encode(message: Source, writer: Writer = Writer.create()): Writer {
    if (message.pathIdx !== 0) {
      writer.uint32(8).uint32(message.pathIdx);
    }
    if (message.position !== undefined) {
      SourcePosition.encode(message.position, writer.uint32(18).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Source {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseSource } as Source;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.pathIdx = reader.uint32();
          break;
        case 2:
          message.position = SourcePosition.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Source {
    const message = { ...baseSource } as Source;
    if (object.pathIdx !== undefined && object.pathIdx !== null) {
      message.pathIdx = Number(object.pathIdx);
    }
    if (object.position !== undefined && object.position !== null) {
      message.position = SourcePosition.fromJSON(object.position);
    }
    return message;
  },

  toJSON(message: Source): unknown {
    const obj: any = {};
    message.pathIdx !== undefined && (obj.pathIdx = message.pathIdx);
    message.position !== undefined &&
      (obj.position = message.position ? SourcePosition.toJSON(message.position) : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<Source>): Source {
    const message = { ...baseSource } as Source;
    if (object.pathIdx !== undefined && object.pathIdx !== null) {
      message.pathIdx = object.pathIdx;
    } else {
      message.pathIdx = 0;
    }
    if (object.position !== undefined && object.position !== null) {
      message.position = SourcePosition.fromPartial(object.position);
    } else {
      message.position = undefined;
    }
    return message;
  },
};

const baseToolFingerprint: object = { tool: '', version: '' };

export const ToolFingerprint = {
  encode(message: ToolFingerprint, writer: Writer = Writer.create()): Writer {
    if (message.tool !== '') {
      writer.uint32(10).string(message.tool);
    }
    if (message.version !== '') {
      writer.uint32(18).string(message.version);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): ToolFingerprint {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseToolFingerprint } as ToolFingerprint;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.tool = reader.string();
          break;
        case 2:
          message.version = reader.string();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): ToolFingerprint {
    const message = { ...baseToolFingerprint } as ToolFingerprint;
    if (object.tool !== undefined && object.tool !== null) {
      message.tool = String(object.tool);
    }
    if (object.version !== undefined && object.version !== null) {
      message.version = String(object.version);
    }
    return message;
  },

  toJSON(message: ToolFingerprint): unknown {
    const obj: any = {};
    message.tool !== undefined && (obj.tool = message.tool);
    message.version !== undefined && (obj.version = message.version);
    return obj;
  },

  fromPartial(object: DeepPartial<ToolFingerprint>): ToolFingerprint {
    const message = { ...baseToolFingerprint } as ToolFingerprint;
    if (object.tool !== undefined && object.tool !== null) {
      message.tool = object.tool;
    } else {
      message.tool = '';
    }
    if (object.version !== undefined && object.version !== null) {
      message.version = object.version;
    } else {
      message.version = '';
    }
    return message;
  },
};

const baseResourceTable: object = {};

export const ResourceTable = {
  encode(message: ResourceTable, writer: Writer = Writer.create()): Writer {
    if (message.sourcePool !== undefined) {
      StringPool.encode(message.sourcePool, writer.uint32(10).fork()).ldelim();
    }
    for (const v of message.package) {
      Package.encode(v!, writer.uint32(18).fork()).ldelim();
    }
    for (const v of message.overlayable) {
      Overlayable.encode(v!, writer.uint32(26).fork()).ldelim();
    }
    for (const v of message.toolFingerprint) {
      ToolFingerprint.encode(v!, writer.uint32(34).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): ResourceTable {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseResourceTable } as ResourceTable;
    message.package = [];
    message.overlayable = [];
    message.toolFingerprint = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.sourcePool = StringPool.decode(reader, reader.uint32());
          break;
        case 2:
          message.package.push(Package.decode(reader, reader.uint32()));
          break;
        case 3:
          message.overlayable.push(Overlayable.decode(reader, reader.uint32()));
          break;
        case 4:
          message.toolFingerprint.push(ToolFingerprint.decode(reader, reader.uint32()));
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): ResourceTable {
    const message = { ...baseResourceTable } as ResourceTable;
    message.package = [];
    message.overlayable = [];
    message.toolFingerprint = [];
    if (object.sourcePool !== undefined && object.sourcePool !== null) {
      message.sourcePool = StringPool.fromJSON(object.sourcePool);
    }
    if (object.package !== undefined && object.package !== null) {
      for (const e of object.package) {
        message.package.push(Package.fromJSON(e));
      }
    }
    if (object.overlayable !== undefined && object.overlayable !== null) {
      for (const e of object.overlayable) {
        message.overlayable.push(Overlayable.fromJSON(e));
      }
    }
    if (object.toolFingerprint !== undefined && object.toolFingerprint !== null) {
      for (const e of object.toolFingerprint) {
        message.toolFingerprint.push(ToolFingerprint.fromJSON(e));
      }
    }
    return message;
  },

  toJSON(message: ResourceTable): unknown {
    const obj: any = {};
    message.sourcePool !== undefined &&
      (obj.sourcePool = message.sourcePool ? StringPool.toJSON(message.sourcePool) : undefined);
    if (message.package) {
      obj.package = message.package.map((e) => (e ? Package.toJSON(e) : undefined));
    } else {
      obj.package = [];
    }
    if (message.overlayable) {
      obj.overlayable = message.overlayable.map((e) => (e ? Overlayable.toJSON(e) : undefined));
    } else {
      obj.overlayable = [];
    }
    if (message.toolFingerprint) {
      obj.toolFingerprint = message.toolFingerprint.map((e) => (e ? ToolFingerprint.toJSON(e) : undefined));
    } else {
      obj.toolFingerprint = [];
    }
    return obj;
  },

  fromPartial(object: DeepPartial<ResourceTable>): ResourceTable {
    const message = { ...baseResourceTable } as ResourceTable;
    message.package = [];
    message.overlayable = [];
    message.toolFingerprint = [];
    if (object.sourcePool !== undefined && object.sourcePool !== null) {
      message.sourcePool = StringPool.fromPartial(object.sourcePool);
    } else {
      message.sourcePool = undefined;
    }
    if (object.package !== undefined && object.package !== null) {
      for (const e of object.package) {
        message.package.push(Package.fromPartial(e));
      }
    }
    if (object.overlayable !== undefined && object.overlayable !== null) {
      for (const e of object.overlayable) {
        message.overlayable.push(Overlayable.fromPartial(e));
      }
    }
    if (object.toolFingerprint !== undefined && object.toolFingerprint !== null) {
      for (const e of object.toolFingerprint) {
        message.toolFingerprint.push(ToolFingerprint.fromPartial(e));
      }
    }
    return message;
  },
};

const basePackageId: object = { id: 0 };

export const PackageId = {
  encode(message: PackageId, writer: Writer = Writer.create()): Writer {
    if (message.id !== 0) {
      writer.uint32(8).uint32(message.id);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): PackageId {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...basePackageId } as PackageId;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.id = reader.uint32();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): PackageId {
    const message = { ...basePackageId } as PackageId;
    if (object.id !== undefined && object.id !== null) {
      message.id = Number(object.id);
    }
    return message;
  },

  toJSON(message: PackageId): unknown {
    const obj: any = {};
    message.id !== undefined && (obj.id = message.id);
    return obj;
  },

  fromPartial(object: DeepPartial<PackageId>): PackageId {
    const message = { ...basePackageId } as PackageId;
    if (object.id !== undefined && object.id !== null) {
      message.id = object.id;
    } else {
      message.id = 0;
    }
    return message;
  },
};

const basePackage: object = { packageName: '' };

export const Package = {
  encode(message: Package, writer: Writer = Writer.create()): Writer {
    if (message.packageId !== undefined) {
      PackageId.encode(message.packageId, writer.uint32(10).fork()).ldelim();
    }
    if (message.packageName !== '') {
      writer.uint32(18).string(message.packageName);
    }
    for (const v of message.type) {
      Type.encode(v!, writer.uint32(26).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Package {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...basePackage } as Package;
    message.type = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.packageId = PackageId.decode(reader, reader.uint32());
          break;
        case 2:
          message.packageName = reader.string();
          break;
        case 3:
          message.type.push(Type.decode(reader, reader.uint32()));
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Package {
    const message = { ...basePackage } as Package;
    message.type = [];
    if (object.packageId !== undefined && object.packageId !== null) {
      message.packageId = PackageId.fromJSON(object.packageId);
    }
    if (object.packageName !== undefined && object.packageName !== null) {
      message.packageName = String(object.packageName);
    }
    if (object.type !== undefined && object.type !== null) {
      for (const e of object.type) {
        message.type.push(Type.fromJSON(e));
      }
    }
    return message;
  },

  toJSON(message: Package): unknown {
    const obj: any = {};
    message.packageId !== undefined &&
      (obj.packageId = message.packageId ? PackageId.toJSON(message.packageId) : undefined);
    message.packageName !== undefined && (obj.packageName = message.packageName);
    if (message.type) {
      obj.type = message.type.map((e) => (e ? Type.toJSON(e) : undefined));
    } else {
      obj.type = [];
    }
    return obj;
  },

  fromPartial(object: DeepPartial<Package>): Package {
    const message = { ...basePackage } as Package;
    message.type = [];
    if (object.packageId !== undefined && object.packageId !== null) {
      message.packageId = PackageId.fromPartial(object.packageId);
    } else {
      message.packageId = undefined;
    }
    if (object.packageName !== undefined && object.packageName !== null) {
      message.packageName = object.packageName;
    } else {
      message.packageName = '';
    }
    if (object.type !== undefined && object.type !== null) {
      for (const e of object.type) {
        message.type.push(Type.fromPartial(e));
      }
    }
    return message;
  },
};

const baseTypeId: object = { id: 0 };

export const TypeId = {
  encode(message: TypeId, writer: Writer = Writer.create()): Writer {
    if (message.id !== 0) {
      writer.uint32(8).uint32(message.id);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): TypeId {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseTypeId } as TypeId;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.id = reader.uint32();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): TypeId {
    const message = { ...baseTypeId } as TypeId;
    if (object.id !== undefined && object.id !== null) {
      message.id = Number(object.id);
    }
    return message;
  },

  toJSON(message: TypeId): unknown {
    const obj: any = {};
    message.id !== undefined && (obj.id = message.id);
    return obj;
  },

  fromPartial(object: DeepPartial<TypeId>): TypeId {
    const message = { ...baseTypeId } as TypeId;
    if (object.id !== undefined && object.id !== null) {
      message.id = object.id;
    } else {
      message.id = 0;
    }
    return message;
  },
};

const baseType: object = { name: '' };

export const Type = {
  encode(message: Type, writer: Writer = Writer.create()): Writer {
    if (message.typeId !== undefined) {
      TypeId.encode(message.typeId, writer.uint32(10).fork()).ldelim();
    }
    if (message.name !== '') {
      writer.uint32(18).string(message.name);
    }
    for (const v of message.entry) {
      Entry.encode(v!, writer.uint32(26).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Type {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseType } as Type;
    message.entry = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.typeId = TypeId.decode(reader, reader.uint32());
          break;
        case 2:
          message.name = reader.string();
          break;
        case 3:
          message.entry.push(Entry.decode(reader, reader.uint32()));
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Type {
    const message = { ...baseType } as Type;
    message.entry = [];
    if (object.typeId !== undefined && object.typeId !== null) {
      message.typeId = TypeId.fromJSON(object.typeId);
    }
    if (object.name !== undefined && object.name !== null) {
      message.name = String(object.name);
    }
    if (object.entry !== undefined && object.entry !== null) {
      for (const e of object.entry) {
        message.entry.push(Entry.fromJSON(e));
      }
    }
    return message;
  },

  toJSON(message: Type): unknown {
    const obj: any = {};
    message.typeId !== undefined && (obj.typeId = message.typeId ? TypeId.toJSON(message.typeId) : undefined);
    message.name !== undefined && (obj.name = message.name);
    if (message.entry) {
      obj.entry = message.entry.map((e) => (e ? Entry.toJSON(e) : undefined));
    } else {
      obj.entry = [];
    }
    return obj;
  },

  fromPartial(object: DeepPartial<Type>): Type {
    const message = { ...baseType } as Type;
    message.entry = [];
    if (object.typeId !== undefined && object.typeId !== null) {
      message.typeId = TypeId.fromPartial(object.typeId);
    } else {
      message.typeId = undefined;
    }
    if (object.name !== undefined && object.name !== null) {
      message.name = object.name;
    } else {
      message.name = '';
    }
    if (object.entry !== undefined && object.entry !== null) {
      for (const e of object.entry) {
        message.entry.push(Entry.fromPartial(e));
      }
    }
    return message;
  },
};

const baseVisibility: object = { level: 0, comment: '', stagedApi: false };

export const Visibility = {
  encode(message: Visibility, writer: Writer = Writer.create()): Writer {
    if (message.level !== 0) {
      writer.uint32(8).int32(message.level);
    }
    if (message.source !== undefined) {
      Source.encode(message.source, writer.uint32(18).fork()).ldelim();
    }
    if (message.comment !== '') {
      writer.uint32(26).string(message.comment);
    }
    if (message.stagedApi === true) {
      writer.uint32(32).bool(message.stagedApi);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Visibility {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseVisibility } as Visibility;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.level = reader.int32() as any;
          break;
        case 2:
          message.source = Source.decode(reader, reader.uint32());
          break;
        case 3:
          message.comment = reader.string();
          break;
        case 4:
          message.stagedApi = reader.bool();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Visibility {
    const message = { ...baseVisibility } as Visibility;
    if (object.level !== undefined && object.level !== null) {
      message.level = visibility_LevelFromJSON(object.level);
    }
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromJSON(object.source);
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = String(object.comment);
    }
    if (object.stagedApi !== undefined && object.stagedApi !== null) {
      message.stagedApi = Boolean(object.stagedApi);
    }
    return message;
  },

  toJSON(message: Visibility): unknown {
    const obj: any = {};
    message.level !== undefined && (obj.level = visibility_LevelToJSON(message.level));
    message.source !== undefined && (obj.source = message.source ? Source.toJSON(message.source) : undefined);
    message.comment !== undefined && (obj.comment = message.comment);
    message.stagedApi !== undefined && (obj.stagedApi = message.stagedApi);
    return obj;
  },

  fromPartial(object: DeepPartial<Visibility>): Visibility {
    const message = { ...baseVisibility } as Visibility;
    if (object.level !== undefined && object.level !== null) {
      message.level = object.level;
    } else {
      message.level = 0;
    }
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = object.comment;
    } else {
      message.comment = '';
    }
    if (object.stagedApi !== undefined && object.stagedApi !== null) {
      message.stagedApi = object.stagedApi;
    } else {
      message.stagedApi = false;
    }
    return message;
  },
};

const baseAllowNew: object = { comment: '' };

export const AllowNew = {
  encode(message: AllowNew, writer: Writer = Writer.create()): Writer {
    if (message.source !== undefined) {
      Source.encode(message.source, writer.uint32(10).fork()).ldelim();
    }
    if (message.comment !== '') {
      writer.uint32(18).string(message.comment);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): AllowNew {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseAllowNew } as AllowNew;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.source = Source.decode(reader, reader.uint32());
          break;
        case 2:
          message.comment = reader.string();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): AllowNew {
    const message = { ...baseAllowNew } as AllowNew;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromJSON(object.source);
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = String(object.comment);
    }
    return message;
  },

  toJSON(message: AllowNew): unknown {
    const obj: any = {};
    message.source !== undefined && (obj.source = message.source ? Source.toJSON(message.source) : undefined);
    message.comment !== undefined && (obj.comment = message.comment);
    return obj;
  },

  fromPartial(object: DeepPartial<AllowNew>): AllowNew {
    const message = { ...baseAllowNew } as AllowNew;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = object.comment;
    } else {
      message.comment = '';
    }
    return message;
  },
};

const baseOverlayable: object = { name: '', actor: '' };

export const Overlayable = {
  encode(message: Overlayable, writer: Writer = Writer.create()): Writer {
    if (message.name !== '') {
      writer.uint32(10).string(message.name);
    }
    if (message.source !== undefined) {
      Source.encode(message.source, writer.uint32(18).fork()).ldelim();
    }
    if (message.actor !== '') {
      writer.uint32(26).string(message.actor);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Overlayable {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseOverlayable } as Overlayable;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.name = reader.string();
          break;
        case 2:
          message.source = Source.decode(reader, reader.uint32());
          break;
        case 3:
          message.actor = reader.string();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Overlayable {
    const message = { ...baseOverlayable } as Overlayable;
    if (object.name !== undefined && object.name !== null) {
      message.name = String(object.name);
    }
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromJSON(object.source);
    }
    if (object.actor !== undefined && object.actor !== null) {
      message.actor = String(object.actor);
    }
    return message;
  },

  toJSON(message: Overlayable): unknown {
    const obj: any = {};
    message.name !== undefined && (obj.name = message.name);
    message.source !== undefined && (obj.source = message.source ? Source.toJSON(message.source) : undefined);
    message.actor !== undefined && (obj.actor = message.actor);
    return obj;
  },

  fromPartial(object: DeepPartial<Overlayable>): Overlayable {
    const message = { ...baseOverlayable } as Overlayable;
    if (object.name !== undefined && object.name !== null) {
      message.name = object.name;
    } else {
      message.name = '';
    }
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    if (object.actor !== undefined && object.actor !== null) {
      message.actor = object.actor;
    } else {
      message.actor = '';
    }
    return message;
  },
};

const baseOverlayableItem: object = {
  comment: '',
  policy: 0,
  overlayableIdx: 0,
};

export const OverlayableItem = {
  encode(message: OverlayableItem, writer: Writer = Writer.create()): Writer {
    if (message.source !== undefined) {
      Source.encode(message.source, writer.uint32(10).fork()).ldelim();
    }
    if (message.comment !== '') {
      writer.uint32(18).string(message.comment);
    }
    writer.uint32(26).fork();
    for (const v of message.policy) {
      writer.int32(v);
    }
    writer.ldelim();
    if (message.overlayableIdx !== 0) {
      writer.uint32(32).uint32(message.overlayableIdx);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): OverlayableItem {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseOverlayableItem } as OverlayableItem;
    message.policy = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.source = Source.decode(reader, reader.uint32());
          break;
        case 2:
          message.comment = reader.string();
          break;
        case 3:
          if ((tag & 7) === 2) {
            const end2 = reader.uint32() + reader.pos;
            while (reader.pos < end2) {
              message.policy.push(reader.int32() as any);
            }
          } else {
            message.policy.push(reader.int32() as any);
          }
          break;
        case 4:
          message.overlayableIdx = reader.uint32();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): OverlayableItem {
    const message = { ...baseOverlayableItem } as OverlayableItem;
    message.policy = [];
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromJSON(object.source);
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = String(object.comment);
    }
    if (object.policy !== undefined && object.policy !== null) {
      for (const e of object.policy) {
        message.policy.push(overlayableItem_PolicyFromJSON(e));
      }
    }
    if (object.overlayableIdx !== undefined && object.overlayableIdx !== null) {
      message.overlayableIdx = Number(object.overlayableIdx);
    }
    return message;
  },

  toJSON(message: OverlayableItem): unknown {
    const obj: any = {};
    message.source !== undefined && (obj.source = message.source ? Source.toJSON(message.source) : undefined);
    message.comment !== undefined && (obj.comment = message.comment);
    if (message.policy) {
      obj.policy = message.policy.map((e) => overlayableItem_PolicyToJSON(e));
    } else {
      obj.policy = [];
    }
    message.overlayableIdx !== undefined && (obj.overlayableIdx = message.overlayableIdx);
    return obj;
  },

  fromPartial(object: DeepPartial<OverlayableItem>): OverlayableItem {
    const message = { ...baseOverlayableItem } as OverlayableItem;
    message.policy = [];
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = object.comment;
    } else {
      message.comment = '';
    }
    if (object.policy !== undefined && object.policy !== null) {
      for (const e of object.policy) {
        message.policy.push(e);
      }
    }
    if (object.overlayableIdx !== undefined && object.overlayableIdx !== null) {
      message.overlayableIdx = object.overlayableIdx;
    } else {
      message.overlayableIdx = 0;
    }
    return message;
  },
};

const baseStagedId: object = { stagedId: 0 };

export const StagedId = {
  encode(message: StagedId, writer: Writer = Writer.create()): Writer {
    if (message.source !== undefined) {
      Source.encode(message.source, writer.uint32(10).fork()).ldelim();
    }
    if (message.stagedId !== 0) {
      writer.uint32(16).uint32(message.stagedId);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): StagedId {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseStagedId } as StagedId;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.source = Source.decode(reader, reader.uint32());
          break;
        case 2:
          message.stagedId = reader.uint32();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): StagedId {
    const message = { ...baseStagedId } as StagedId;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromJSON(object.source);
    }
    if (object.stagedId !== undefined && object.stagedId !== null) {
      message.stagedId = Number(object.stagedId);
    }
    return message;
  },

  toJSON(message: StagedId): unknown {
    const obj: any = {};
    message.source !== undefined && (obj.source = message.source ? Source.toJSON(message.source) : undefined);
    message.stagedId !== undefined && (obj.stagedId = message.stagedId);
    return obj;
  },

  fromPartial(object: DeepPartial<StagedId>): StagedId {
    const message = { ...baseStagedId } as StagedId;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    if (object.stagedId !== undefined && object.stagedId !== null) {
      message.stagedId = object.stagedId;
    } else {
      message.stagedId = 0;
    }
    return message;
  },
};

const baseEntryId: object = { id: 0 };

export const EntryId = {
  encode(message: EntryId, writer: Writer = Writer.create()): Writer {
    if (message.id !== 0) {
      writer.uint32(8).uint32(message.id);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): EntryId {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseEntryId } as EntryId;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.id = reader.uint32();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): EntryId {
    const message = { ...baseEntryId } as EntryId;
    if (object.id !== undefined && object.id !== null) {
      message.id = Number(object.id);
    }
    return message;
  },

  toJSON(message: EntryId): unknown {
    const obj: any = {};
    message.id !== undefined && (obj.id = message.id);
    return obj;
  },

  fromPartial(object: DeepPartial<EntryId>): EntryId {
    const message = { ...baseEntryId } as EntryId;
    if (object.id !== undefined && object.id !== null) {
      message.id = object.id;
    } else {
      message.id = 0;
    }
    return message;
  },
};

const baseEntry: object = { name: '' };

export const Entry = {
  encode(message: Entry, writer: Writer = Writer.create()): Writer {
    if (message.entryId !== undefined) {
      EntryId.encode(message.entryId, writer.uint32(10).fork()).ldelim();
    }
    if (message.name !== '') {
      writer.uint32(18).string(message.name);
    }
    if (message.visibility !== undefined) {
      Visibility.encode(message.visibility, writer.uint32(26).fork()).ldelim();
    }
    if (message.allowNew !== undefined) {
      AllowNew.encode(message.allowNew, writer.uint32(34).fork()).ldelim();
    }
    if (message.overlayableItem !== undefined) {
      OverlayableItem.encode(message.overlayableItem, writer.uint32(42).fork()).ldelim();
    }
    for (const v of message.configValue) {
      ConfigValue.encode(v!, writer.uint32(50).fork()).ldelim();
    }
    if (message.stagedId !== undefined) {
      StagedId.encode(message.stagedId, writer.uint32(58).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Entry {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseEntry } as Entry;
    message.configValue = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.entryId = EntryId.decode(reader, reader.uint32());
          break;
        case 2:
          message.name = reader.string();
          break;
        case 3:
          message.visibility = Visibility.decode(reader, reader.uint32());
          break;
        case 4:
          message.allowNew = AllowNew.decode(reader, reader.uint32());
          break;
        case 5:
          message.overlayableItem = OverlayableItem.decode(reader, reader.uint32());
          break;
        case 6:
          message.configValue.push(ConfigValue.decode(reader, reader.uint32()));
          break;
        case 7:
          message.stagedId = StagedId.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Entry {
    const message = { ...baseEntry } as Entry;
    message.configValue = [];
    if (object.entryId !== undefined && object.entryId !== null) {
      message.entryId = EntryId.fromJSON(object.entryId);
    }
    if (object.name !== undefined && object.name !== null) {
      message.name = String(object.name);
    }
    if (object.visibility !== undefined && object.visibility !== null) {
      message.visibility = Visibility.fromJSON(object.visibility);
    }
    if (object.allowNew !== undefined && object.allowNew !== null) {
      message.allowNew = AllowNew.fromJSON(object.allowNew);
    }
    if (object.overlayableItem !== undefined && object.overlayableItem !== null) {
      message.overlayableItem = OverlayableItem.fromJSON(object.overlayableItem);
    }
    if (object.configValue !== undefined && object.configValue !== null) {
      for (const e of object.configValue) {
        message.configValue.push(ConfigValue.fromJSON(e));
      }
    }
    if (object.stagedId !== undefined && object.stagedId !== null) {
      message.stagedId = StagedId.fromJSON(object.stagedId);
    }
    return message;
  },

  toJSON(message: Entry): unknown {
    const obj: any = {};
    message.entryId !== undefined && (obj.entryId = message.entryId ? EntryId.toJSON(message.entryId) : undefined);
    message.name !== undefined && (obj.name = message.name);
    message.visibility !== undefined &&
      (obj.visibility = message.visibility ? Visibility.toJSON(message.visibility) : undefined);
    message.allowNew !== undefined && (obj.allowNew = message.allowNew ? AllowNew.toJSON(message.allowNew) : undefined);
    message.overlayableItem !== undefined &&
      (obj.overlayableItem = message.overlayableItem ? OverlayableItem.toJSON(message.overlayableItem) : undefined);
    if (message.configValue) {
      obj.configValue = message.configValue.map((e) => (e ? ConfigValue.toJSON(e) : undefined));
    } else {
      obj.configValue = [];
    }
    message.stagedId !== undefined && (obj.stagedId = message.stagedId ? StagedId.toJSON(message.stagedId) : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<Entry>): Entry {
    const message = { ...baseEntry } as Entry;
    message.configValue = [];
    if (object.entryId !== undefined && object.entryId !== null) {
      message.entryId = EntryId.fromPartial(object.entryId);
    } else {
      message.entryId = undefined;
    }
    if (object.name !== undefined && object.name !== null) {
      message.name = object.name;
    } else {
      message.name = '';
    }
    if (object.visibility !== undefined && object.visibility !== null) {
      message.visibility = Visibility.fromPartial(object.visibility);
    } else {
      message.visibility = undefined;
    }
    if (object.allowNew !== undefined && object.allowNew !== null) {
      message.allowNew = AllowNew.fromPartial(object.allowNew);
    } else {
      message.allowNew = undefined;
    }
    if (object.overlayableItem !== undefined && object.overlayableItem !== null) {
      message.overlayableItem = OverlayableItem.fromPartial(object.overlayableItem);
    } else {
      message.overlayableItem = undefined;
    }
    if (object.configValue !== undefined && object.configValue !== null) {
      for (const e of object.configValue) {
        message.configValue.push(ConfigValue.fromPartial(e));
      }
    }
    if (object.stagedId !== undefined && object.stagedId !== null) {
      message.stagedId = StagedId.fromPartial(object.stagedId);
    } else {
      message.stagedId = undefined;
    }
    return message;
  },
};

const baseConfigValue: object = {};

export const ConfigValue = {
  encode(message: ConfigValue, writer: Writer = Writer.create()): Writer {
    if (message.config !== undefined) {
      Configuration.encode(message.config, writer.uint32(10).fork()).ldelim();
    }
    if (message.value !== undefined) {
      Value.encode(message.value, writer.uint32(18).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): ConfigValue {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseConfigValue } as ConfigValue;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.config = Configuration.decode(reader, reader.uint32());
          break;
        case 2:
          message.value = Value.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): ConfigValue {
    const message = { ...baseConfigValue } as ConfigValue;
    if (object.config !== undefined && object.config !== null) {
      message.config = Configuration.fromJSON(object.config);
    }
    if (object.value !== undefined && object.value !== null) {
      message.value = Value.fromJSON(object.value);
    }
    return message;
  },

  toJSON(message: ConfigValue): unknown {
    const obj: any = {};
    message.config !== undefined && (obj.config = message.config ? Configuration.toJSON(message.config) : undefined);
    message.value !== undefined && (obj.value = message.value ? Value.toJSON(message.value) : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<ConfigValue>): ConfigValue {
    const message = { ...baseConfigValue } as ConfigValue;
    if (object.config !== undefined && object.config !== null) {
      message.config = Configuration.fromPartial(object.config);
    } else {
      message.config = undefined;
    }
    if (object.value !== undefined && object.value !== null) {
      message.value = Value.fromPartial(object.value);
    } else {
      message.value = undefined;
    }
    return message;
  },
};

const baseValue: object = { comment: '', weak: false };

export const Value = {
  encode(message: Value, writer: Writer = Writer.create()): Writer {
    if (message.source !== undefined) {
      Source.encode(message.source, writer.uint32(10).fork()).ldelim();
    }
    if (message.comment !== '') {
      writer.uint32(18).string(message.comment);
    }
    if (message.weak === true) {
      writer.uint32(24).bool(message.weak);
    }
    if (message.value?.$case === 'item') {
      Item.encode(message.value.item, writer.uint32(34).fork()).ldelim();
    }
    if (message.value?.$case === 'compoundValue') {
      CompoundValue.encode(message.value.compoundValue, writer.uint32(42).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Value {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseValue } as Value;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.source = Source.decode(reader, reader.uint32());
          break;
        case 2:
          message.comment = reader.string();
          break;
        case 3:
          message.weak = reader.bool();
          break;
        case 4:
          message.value = {
            $case: 'item',
            item: Item.decode(reader, reader.uint32()),
          };
          break;
        case 5:
          message.value = {
            $case: 'compoundValue',
            compoundValue: CompoundValue.decode(reader, reader.uint32()),
          };
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Value {
    const message = { ...baseValue } as Value;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromJSON(object.source);
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = String(object.comment);
    }
    if (object.weak !== undefined && object.weak !== null) {
      message.weak = Boolean(object.weak);
    }
    if (object.item !== undefined && object.item !== null) {
      message.value = { $case: 'item', item: Item.fromJSON(object.item) };
    }
    if (object.compoundValue !== undefined && object.compoundValue !== null) {
      message.value = {
        $case: 'compoundValue',
        compoundValue: CompoundValue.fromJSON(object.compoundValue),
      };
    }
    return message;
  },

  toJSON(message: Value): unknown {
    const obj: any = {};
    message.source !== undefined && (obj.source = message.source ? Source.toJSON(message.source) : undefined);
    message.comment !== undefined && (obj.comment = message.comment);
    message.weak !== undefined && (obj.weak = message.weak);
    message.value?.$case === 'item' && (obj.item = message.value?.item ? Item.toJSON(message.value?.item) : undefined);
    message.value?.$case === 'compoundValue' &&
      (obj.compoundValue = message.value?.compoundValue
        ? CompoundValue.toJSON(message.value?.compoundValue)
        : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<Value>): Value {
    const message = { ...baseValue } as Value;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = object.comment;
    } else {
      message.comment = '';
    }
    if (object.weak !== undefined && object.weak !== null) {
      message.weak = object.weak;
    } else {
      message.weak = false;
    }
    if (object.value?.$case === 'item' && object.value?.item !== undefined && object.value?.item !== null) {
      message.value = {
        $case: 'item',
        item: Item.fromPartial(object.value.item),
      };
    }
    if (
      object.value?.$case === 'compoundValue' &&
      object.value?.compoundValue !== undefined &&
      object.value?.compoundValue !== null
    ) {
      message.value = {
        $case: 'compoundValue',
        compoundValue: CompoundValue.fromPartial(object.value.compoundValue),
      };
    }
    return message;
  },
};

const baseItem: object = {};

export const Item = {
  encode(message: Item, writer: Writer = Writer.create()): Writer {
    if (message.value?.$case === 'ref') {
      Reference.encode(message.value.ref, writer.uint32(10).fork()).ldelim();
    }
    if (message.value?.$case === 'str') {
      StringValue.encode(message.value.str, writer.uint32(18).fork()).ldelim();
    }
    if (message.value?.$case === 'rawStr') {
      RawString.encode(message.value.rawStr, writer.uint32(26).fork()).ldelim();
    }
    if (message.value?.$case === 'styledStr') {
      StyledString.encode(message.value.styledStr, writer.uint32(34).fork()).ldelim();
    }
    if (message.value?.$case === 'file') {
      FileReference.encode(message.value.file, writer.uint32(42).fork()).ldelim();
    }
    if (message.value?.$case === 'id') {
      Id.encode(message.value.id, writer.uint32(50).fork()).ldelim();
    }
    if (message.value?.$case === 'prim') {
      Primitive.encode(message.value.prim, writer.uint32(58).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Item {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseItem } as Item;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.value = {
            $case: 'ref',
            ref: Reference.decode(reader, reader.uint32()),
          };
          break;
        case 2:
          message.value = {
            $case: 'str',
            str: StringValue.decode(reader, reader.uint32()),
          };
          break;
        case 3:
          message.value = {
            $case: 'rawStr',
            rawStr: RawString.decode(reader, reader.uint32()),
          };
          break;
        case 4:
          message.value = {
            $case: 'styledStr',
            styledStr: StyledString.decode(reader, reader.uint32()),
          };
          break;
        case 5:
          message.value = {
            $case: 'file',
            file: FileReference.decode(reader, reader.uint32()),
          };
          break;
        case 6:
          message.value = {
            $case: 'id',
            id: Id.decode(reader, reader.uint32()),
          };
          break;
        case 7:
          message.value = {
            $case: 'prim',
            prim: Primitive.decode(reader, reader.uint32()),
          };
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Item {
    const message = { ...baseItem } as Item;
    if (object.ref !== undefined && object.ref !== null) {
      message.value = { $case: 'ref', ref: Reference.fromJSON(object.ref) };
    }
    if (object.str !== undefined && object.str !== null) {
      message.value = { $case: 'str', str: StringValue.fromJSON(object.str) };
    }
    if (object.rawStr !== undefined && object.rawStr !== null) {
      message.value = {
        $case: 'rawStr',
        rawStr: RawString.fromJSON(object.rawStr),
      };
    }
    if (object.styledStr !== undefined && object.styledStr !== null) {
      message.value = {
        $case: 'styledStr',
        styledStr: StyledString.fromJSON(object.styledStr),
      };
    }
    if (object.file !== undefined && object.file !== null) {
      message.value = {
        $case: 'file',
        file: FileReference.fromJSON(object.file),
      };
    }
    if (object.id !== undefined && object.id !== null) {
      message.value = { $case: 'id', id: Id.fromJSON(object.id) };
    }
    if (object.prim !== undefined && object.prim !== null) {
      message.value = { $case: 'prim', prim: Primitive.fromJSON(object.prim) };
    }
    return message;
  },

  toJSON(message: Item): unknown {
    const obj: any = {};
    message.value?.$case === 'ref' && (obj.ref = message.value?.ref ? Reference.toJSON(message.value?.ref) : undefined);
    message.value?.$case === 'str' &&
      (obj.str = message.value?.str ? StringValue.toJSON(message.value?.str) : undefined);
    message.value?.$case === 'rawStr' &&
      (obj.rawStr = message.value?.rawStr ? RawString.toJSON(message.value?.rawStr) : undefined);
    message.value?.$case === 'styledStr' &&
      (obj.styledStr = message.value?.styledStr ? StyledString.toJSON(message.value?.styledStr) : undefined);
    message.value?.$case === 'file' &&
      (obj.file = message.value?.file ? FileReference.toJSON(message.value?.file) : undefined);
    message.value?.$case === 'id' && (obj.id = message.value?.id ? Id.toJSON(message.value?.id) : undefined);
    message.value?.$case === 'prim' &&
      (obj.prim = message.value?.prim ? Primitive.toJSON(message.value?.prim) : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<Item>): Item {
    const message = { ...baseItem } as Item;
    if (object.value?.$case === 'ref' && object.value?.ref !== undefined && object.value?.ref !== null) {
      message.value = {
        $case: 'ref',
        ref: Reference.fromPartial(object.value.ref),
      };
    }
    if (object.value?.$case === 'str' && object.value?.str !== undefined && object.value?.str !== null) {
      message.value = {
        $case: 'str',
        str: StringValue.fromPartial(object.value.str),
      };
    }
    if (object.value?.$case === 'rawStr' && object.value?.rawStr !== undefined && object.value?.rawStr !== null) {
      message.value = {
        $case: 'rawStr',
        rawStr: RawString.fromPartial(object.value.rawStr),
      };
    }
    if (
      object.value?.$case === 'styledStr' &&
      object.value?.styledStr !== undefined &&
      object.value?.styledStr !== null
    ) {
      message.value = {
        $case: 'styledStr',
        styledStr: StyledString.fromPartial(object.value.styledStr),
      };
    }
    if (object.value?.$case === 'file' && object.value?.file !== undefined && object.value?.file !== null) {
      message.value = {
        $case: 'file',
        file: FileReference.fromPartial(object.value.file),
      };
    }
    if (object.value?.$case === 'id' && object.value?.id !== undefined && object.value?.id !== null) {
      message.value = { $case: 'id', id: Id.fromPartial(object.value.id) };
    }
    if (object.value?.$case === 'prim' && object.value?.prim !== undefined && object.value?.prim !== null) {
      message.value = {
        $case: 'prim',
        prim: Primitive.fromPartial(object.value.prim),
      };
    }
    return message;
  },
};

const baseCompoundValue: object = {};

export const CompoundValue = {
  encode(message: CompoundValue, writer: Writer = Writer.create()): Writer {
    if (message.value?.$case === 'attr') {
      Attribute.encode(message.value.attr, writer.uint32(10).fork()).ldelim();
    }
    if (message.value?.$case === 'style') {
      Style.encode(message.value.style, writer.uint32(18).fork()).ldelim();
    }
    if (message.value?.$case === 'styleable') {
      Styleable.encode(message.value.styleable, writer.uint32(26).fork()).ldelim();
    }
    if (message.value?.$case === 'array') {
      Array.encode(message.value.array, writer.uint32(34).fork()).ldelim();
    }
    if (message.value?.$case === 'plural') {
      Plural.encode(message.value.plural, writer.uint32(42).fork()).ldelim();
    }
    if (message.value?.$case === 'macro') {
      MacroBody.encode(message.value.macro, writer.uint32(50).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): CompoundValue {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseCompoundValue } as CompoundValue;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.value = {
            $case: 'attr',
            attr: Attribute.decode(reader, reader.uint32()),
          };
          break;
        case 2:
          message.value = {
            $case: 'style',
            style: Style.decode(reader, reader.uint32()),
          };
          break;
        case 3:
          message.value = {
            $case: 'styleable',
            styleable: Styleable.decode(reader, reader.uint32()),
          };
          break;
        case 4:
          message.value = {
            $case: 'array',
            array: Array.decode(reader, reader.uint32()),
          };
          break;
        case 5:
          message.value = {
            $case: 'plural',
            plural: Plural.decode(reader, reader.uint32()),
          };
          break;
        case 6:
          message.value = {
            $case: 'macro',
            macro: MacroBody.decode(reader, reader.uint32()),
          };
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): CompoundValue {
    const message = { ...baseCompoundValue } as CompoundValue;
    if (object.attr !== undefined && object.attr !== null) {
      message.value = { $case: 'attr', attr: Attribute.fromJSON(object.attr) };
    }
    if (object.style !== undefined && object.style !== null) {
      message.value = { $case: 'style', style: Style.fromJSON(object.style) };
    }
    if (object.styleable !== undefined && object.styleable !== null) {
      message.value = {
        $case: 'styleable',
        styleable: Styleable.fromJSON(object.styleable),
      };
    }
    if (object.array !== undefined && object.array !== null) {
      message.value = { $case: 'array', array: Array.fromJSON(object.array) };
    }
    if (object.plural !== undefined && object.plural !== null) {
      message.value = {
        $case: 'plural',
        plural: Plural.fromJSON(object.plural),
      };
    }
    if (object.macro !== undefined && object.macro !== null) {
      message.value = {
        $case: 'macro',
        macro: MacroBody.fromJSON(object.macro),
      };
    }
    return message;
  },

  toJSON(message: CompoundValue): unknown {
    const obj: any = {};
    message.value?.$case === 'attr' &&
      (obj.attr = message.value?.attr ? Attribute.toJSON(message.value?.attr) : undefined);
    message.value?.$case === 'style' &&
      (obj.style = message.value?.style ? Style.toJSON(message.value?.style) : undefined);
    message.value?.$case === 'styleable' &&
      (obj.styleable = message.value?.styleable ? Styleable.toJSON(message.value?.styleable) : undefined);
    message.value?.$case === 'array' &&
      (obj.array = message.value?.array ? Array.toJSON(message.value?.array) : undefined);
    message.value?.$case === 'plural' &&
      (obj.plural = message.value?.plural ? Plural.toJSON(message.value?.plural) : undefined);
    message.value?.$case === 'macro' &&
      (obj.macro = message.value?.macro ? MacroBody.toJSON(message.value?.macro) : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<CompoundValue>): CompoundValue {
    const message = { ...baseCompoundValue } as CompoundValue;
    if (object.value?.$case === 'attr' && object.value?.attr !== undefined && object.value?.attr !== null) {
      message.value = {
        $case: 'attr',
        attr: Attribute.fromPartial(object.value.attr),
      };
    }
    if (object.value?.$case === 'style' && object.value?.style !== undefined && object.value?.style !== null) {
      message.value = {
        $case: 'style',
        style: Style.fromPartial(object.value.style),
      };
    }
    if (
      object.value?.$case === 'styleable' &&
      object.value?.styleable !== undefined &&
      object.value?.styleable !== null
    ) {
      message.value = {
        $case: 'styleable',
        styleable: Styleable.fromPartial(object.value.styleable),
      };
    }
    if (object.value?.$case === 'array' && object.value?.array !== undefined && object.value?.array !== null) {
      message.value = {
        $case: 'array',
        array: Array.fromPartial(object.value.array),
      };
    }
    if (object.value?.$case === 'plural' && object.value?.plural !== undefined && object.value?.plural !== null) {
      message.value = {
        $case: 'plural',
        plural: Plural.fromPartial(object.value.plural),
      };
    }
    if (object.value?.$case === 'macro' && object.value?.macro !== undefined && object.value?.macro !== null) {
      message.value = {
        $case: 'macro',
        macro: MacroBody.fromPartial(object.value.macro),
      };
    }
    return message;
  },
};

const baseBoolean: object = { value: false };

export const BooleanValue = {
  encode(message: Boolean, writer: Writer = Writer.create()): Writer {
    if (message.value === true) {
      writer.uint32(8).bool(message.value);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Boolean {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseBoolean } as Boolean;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.value = reader.bool();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Boolean {
    const message = { ...baseBoolean } as Boolean;
    if (object.value !== undefined && object.value !== null) {
      message.value = Boolean(object.value);
    }
    return message;
  },

  toJSON(message: Boolean): unknown {
    const obj: any = {};
    message.value !== undefined && (obj.value = message.value);
    return obj;
  },

  fromPartial(object: DeepPartial<Boolean>): Boolean {
    const message = { ...baseBoolean } as Boolean;
    if (object.value !== undefined && object.value !== null) {
      message.value = object.value;
    } else {
      message.value = false;
    }
    return message;
  },
};

const baseReference: object = {
  type: 0,
  id: 0,
  name: '',
  private: false,
  typeFlags: 0,
  allowRaw: false,
};

export const Reference = {
  encode(message: Reference, writer: Writer = Writer.create()): Writer {
    if (message.type !== 0) {
      writer.uint32(8).int32(message.type);
    }
    if (message.id !== 0) {
      writer.uint32(16).uint32(message.id);
    }
    if (message.name !== '') {
      writer.uint32(26).string(message.name);
    }
    if (message.private === true) {
      writer.uint32(32).bool(message.private);
    }
    if (message.isDynamic !== undefined) {
      BooleanValue.encode(message.isDynamic, writer.uint32(42).fork()).ldelim();
    }
    if (message.typeFlags !== 0) {
      writer.uint32(48).uint32(message.typeFlags);
    }
    if (message.allowRaw === true) {
      writer.uint32(56).bool(message.allowRaw);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Reference {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseReference } as Reference;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.type = reader.int32() as any;
          break;
        case 2:
          message.id = reader.uint32();
          break;
        case 3:
          message.name = reader.string();
          break;
        case 4:
          message.private = reader.bool();
          break;
        case 5:
          message.isDynamic = BooleanValue.decode(reader, reader.uint32());
          break;
        case 6:
          message.typeFlags = reader.uint32();
          break;
        case 7:
          message.allowRaw = reader.bool();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Reference {
    const message = { ...baseReference } as Reference;
    if (object.type !== undefined && object.type !== null) {
      message.type = reference_TypeFromJSON(object.type);
    }
    if (object.id !== undefined && object.id !== null) {
      message.id = Number(object.id);
    }
    if (object.name !== undefined && object.name !== null) {
      message.name = String(object.name);
    }
    if (object.private !== undefined && object.private !== null) {
      message.private = Boolean(object.private);
    }
    if (object.isDynamic !== undefined && object.isDynamic !== null) {
      message.isDynamic = BooleanValue.fromJSON(object.isDynamic);
    }
    if (object.typeFlags !== undefined && object.typeFlags !== null) {
      message.typeFlags = Number(object.typeFlags);
    }
    if (object.allowRaw !== undefined && object.allowRaw !== null) {
      message.allowRaw = Boolean(object.allowRaw);
    }
    return message;
  },

  toJSON(message: Reference): unknown {
    const obj: any = {};
    message.type !== undefined && (obj.type = reference_TypeToJSON(message.type));
    message.id !== undefined && (obj.id = message.id);
    message.name !== undefined && (obj.name = message.name);
    message.private !== undefined && (obj.private = message.private);
    message.isDynamic !== undefined &&
      (obj.isDynamic = message.isDynamic ? BooleanValue.toJSON(message.isDynamic) : undefined);
    message.typeFlags !== undefined && (obj.typeFlags = message.typeFlags);
    message.allowRaw !== undefined && (obj.allowRaw = message.allowRaw);
    return obj;
  },

  fromPartial(object: DeepPartial<Reference>): Reference {
    const message = { ...baseReference } as Reference;
    if (object.type !== undefined && object.type !== null) {
      message.type = object.type;
    } else {
      message.type = 0;
    }
    if (object.id !== undefined && object.id !== null) {
      message.id = object.id;
    } else {
      message.id = 0;
    }
    if (object.name !== undefined && object.name !== null) {
      message.name = object.name;
    } else {
      message.name = '';
    }
    if (object.private !== undefined && object.private !== null) {
      message.private = object.private;
    } else {
      message.private = false;
    }
    if (object.isDynamic !== undefined && object.isDynamic !== null) {
      message.isDynamic = BooleanValue.fromPartial(object.isDynamic);
    } else {
      message.isDynamic = undefined;
    }
    if (object.typeFlags !== undefined && object.typeFlags !== null) {
      message.typeFlags = object.typeFlags;
    } else {
      message.typeFlags = 0;
    }
    if (object.allowRaw !== undefined && object.allowRaw !== null) {
      message.allowRaw = object.allowRaw;
    } else {
      message.allowRaw = false;
    }
    return message;
  },
};

const baseId: object = {};

export const Id = {
  encode(_: Id, writer: Writer = Writer.create()): Writer {
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Id {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseId } as Id;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(_: any): Id {
    const message = { ...baseId } as Id;
    return message;
  },

  toJSON(_: Id): unknown {
    const obj: any = {};
    return obj;
  },

  fromPartial(_: DeepPartial<Id>): Id {
    const message = { ...baseId } as Id;
    return message;
  },
};

const baseString: object = { value: '' };

export const StringValue = {
  encode(message: String, writer: Writer = Writer.create()): Writer {
    if (message.value !== '') {
      writer.uint32(10).string(message.value);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): String {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseString } as String;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.value = reader.string();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): String {
    const message = { ...baseString } as String;
    if (object.value !== undefined && object.value !== null) {
      message.value = String(object.value);
    }
    return message;
  },

  toJSON(message: String): unknown {
    const obj: any = {};
    message.value !== undefined && (obj.value = message.value);
    return obj;
  },

  fromPartial(object: DeepPartial<String>): String {
    const message = { ...baseString } as String;
    if (object.value !== undefined && object.value !== null) {
      message.value = object.value;
    } else {
      message.value = '';
    }
    return message;
  },
};

const baseRawString: object = { value: '' };

export const RawString = {
  encode(message: RawString, writer: Writer = Writer.create()): Writer {
    if (message.value !== '') {
      writer.uint32(10).string(message.value);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): RawString {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseRawString } as RawString;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.value = reader.string();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): RawString {
    const message = { ...baseRawString } as RawString;
    if (object.value !== undefined && object.value !== null) {
      message.value = String(object.value);
    }
    return message;
  },

  toJSON(message: RawString): unknown {
    const obj: any = {};
    message.value !== undefined && (obj.value = message.value);
    return obj;
  },

  fromPartial(object: DeepPartial<RawString>): RawString {
    const message = { ...baseRawString } as RawString;
    if (object.value !== undefined && object.value !== null) {
      message.value = object.value;
    } else {
      message.value = '';
    }
    return message;
  },
};

const baseStyledString: object = { value: '' };

export const StyledString = {
  encode(message: StyledString, writer: Writer = Writer.create()): Writer {
    if (message.value !== '') {
      writer.uint32(10).string(message.value);
    }
    for (const v of message.span) {
      StyledString_Span.encode(v!, writer.uint32(18).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): StyledString {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseStyledString } as StyledString;
    message.span = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.value = reader.string();
          break;
        case 2:
          message.span.push(StyledString_Span.decode(reader, reader.uint32()));
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): StyledString {
    const message = { ...baseStyledString } as StyledString;
    message.span = [];
    if (object.value !== undefined && object.value !== null) {
      message.value = String(object.value);
    }
    if (object.span !== undefined && object.span !== null) {
      for (const e of object.span) {
        message.span.push(StyledString_Span.fromJSON(e));
      }
    }
    return message;
  },

  toJSON(message: StyledString): unknown {
    const obj: any = {};
    message.value !== undefined && (obj.value = message.value);
    if (message.span) {
      obj.span = message.span.map((e) => (e ? StyledString_Span.toJSON(e) : undefined));
    } else {
      obj.span = [];
    }
    return obj;
  },

  fromPartial(object: DeepPartial<StyledString>): StyledString {
    const message = { ...baseStyledString } as StyledString;
    message.span = [];
    if (object.value !== undefined && object.value !== null) {
      message.value = object.value;
    } else {
      message.value = '';
    }
    if (object.span !== undefined && object.span !== null) {
      for (const e of object.span) {
        message.span.push(StyledString_Span.fromPartial(e));
      }
    }
    return message;
  },
};

const baseStyledString_Span: object = { tag: '', firstChar: 0, lastChar: 0 };

export const StyledString_Span = {
  encode(message: StyledString_Span, writer: Writer = Writer.create()): Writer {
    if (message.tag !== '') {
      writer.uint32(10).string(message.tag);
    }
    if (message.firstChar !== 0) {
      writer.uint32(16).uint32(message.firstChar);
    }
    if (message.lastChar !== 0) {
      writer.uint32(24).uint32(message.lastChar);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): StyledString_Span {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseStyledString_Span } as StyledString_Span;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.tag = reader.string();
          break;
        case 2:
          message.firstChar = reader.uint32();
          break;
        case 3:
          message.lastChar = reader.uint32();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): StyledString_Span {
    const message = { ...baseStyledString_Span } as StyledString_Span;
    if (object.tag !== undefined && object.tag !== null) {
      message.tag = String(object.tag);
    }
    if (object.firstChar !== undefined && object.firstChar !== null) {
      message.firstChar = Number(object.firstChar);
    }
    if (object.lastChar !== undefined && object.lastChar !== null) {
      message.lastChar = Number(object.lastChar);
    }
    return message;
  },

  toJSON(message: StyledString_Span): unknown {
    const obj: any = {};
    message.tag !== undefined && (obj.tag = message.tag);
    message.firstChar !== undefined && (obj.firstChar = message.firstChar);
    message.lastChar !== undefined && (obj.lastChar = message.lastChar);
    return obj;
  },

  fromPartial(object: DeepPartial<StyledString_Span>): StyledString_Span {
    const message = { ...baseStyledString_Span } as StyledString_Span;
    if (object.tag !== undefined && object.tag !== null) {
      message.tag = object.tag;
    } else {
      message.tag = '';
    }
    if (object.firstChar !== undefined && object.firstChar !== null) {
      message.firstChar = object.firstChar;
    } else {
      message.firstChar = 0;
    }
    if (object.lastChar !== undefined && object.lastChar !== null) {
      message.lastChar = object.lastChar;
    } else {
      message.lastChar = 0;
    }
    return message;
  },
};

const baseFileReference: object = { path: '', type: 0 };

export const FileReference = {
  encode(message: FileReference, writer: Writer = Writer.create()): Writer {
    if (message.path !== '') {
      writer.uint32(10).string(message.path);
    }
    if (message.type !== 0) {
      writer.uint32(16).int32(message.type);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): FileReference {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseFileReference } as FileReference;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.path = reader.string();
          break;
        case 2:
          message.type = reader.int32() as any;
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): FileReference {
    const message = { ...baseFileReference } as FileReference;
    if (object.path !== undefined && object.path !== null) {
      message.path = String(object.path);
    }
    if (object.type !== undefined && object.type !== null) {
      message.type = fileReference_TypeFromJSON(object.type);
    }
    return message;
  },

  toJSON(message: FileReference): unknown {
    const obj: any = {};
    message.path !== undefined && (obj.path = message.path);
    message.type !== undefined && (obj.type = fileReference_TypeToJSON(message.type));
    return obj;
  },

  fromPartial(object: DeepPartial<FileReference>): FileReference {
    const message = { ...baseFileReference } as FileReference;
    if (object.path !== undefined && object.path !== null) {
      message.path = object.path;
    } else {
      message.path = '';
    }
    if (object.type !== undefined && object.type !== null) {
      message.type = object.type;
    } else {
      message.type = 0;
    }
    return message;
  },
};

const basePrimitive: object = {};

export const Primitive = {
  encode(message: Primitive, writer: Writer = Writer.create()): Writer {
    if (message.oneofValue?.$case === 'nullValue') {
      Primitive_NullType.encode(message.oneofValue.nullValue, writer.uint32(10).fork()).ldelim();
    }
    if (message.oneofValue?.$case === 'emptyValue') {
      Primitive_EmptyType.encode(message.oneofValue.emptyValue, writer.uint32(18).fork()).ldelim();
    }
    if (message.oneofValue?.$case === 'floatValue') {
      writer.uint32(29).float(message.oneofValue.floatValue);
    }
    if (message.oneofValue?.$case === 'dimensionValue') {
      writer.uint32(104).uint32(message.oneofValue.dimensionValue);
    }
    if (message.oneofValue?.$case === 'fractionValue') {
      writer.uint32(112).uint32(message.oneofValue.fractionValue);
    }
    if (message.oneofValue?.$case === 'intDecimalValue') {
      writer.uint32(48).int32(message.oneofValue.intDecimalValue);
    }
    if (message.oneofValue?.$case === 'intHexadecimalValue') {
      writer.uint32(56).uint32(message.oneofValue.intHexadecimalValue);
    }
    if (message.oneofValue?.$case === 'booleanValue') {
      writer.uint32(64).bool(message.oneofValue.booleanValue);
    }
    if (message.oneofValue?.$case === 'colorArgb8Value') {
      writer.uint32(72).uint32(message.oneofValue.colorArgb8Value);
    }
    if (message.oneofValue?.$case === 'colorRgb8Value') {
      writer.uint32(80).uint32(message.oneofValue.colorRgb8Value);
    }
    if (message.oneofValue?.$case === 'colorArgb4Value') {
      writer.uint32(88).uint32(message.oneofValue.colorArgb4Value);
    }
    if (message.oneofValue?.$case === 'colorRgb4Value') {
      writer.uint32(96).uint32(message.oneofValue.colorRgb4Value);
    }
    if (message.oneofValue?.$case === 'dimensionValueDeprecated') {
      writer.uint32(37).float(message.oneofValue.dimensionValueDeprecated);
    }
    if (message.oneofValue?.$case === 'fractionValueDeprecated') {
      writer.uint32(45).float(message.oneofValue.fractionValueDeprecated);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Primitive {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...basePrimitive } as Primitive;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.oneofValue = {
            $case: 'nullValue',
            nullValue: Primitive_NullType.decode(reader, reader.uint32()),
          };
          break;
        case 2:
          message.oneofValue = {
            $case: 'emptyValue',
            emptyValue: Primitive_EmptyType.decode(reader, reader.uint32()),
          };
          break;
        case 3:
          message.oneofValue = {
            $case: 'floatValue',
            floatValue: reader.float(),
          };
          break;
        case 13:
          message.oneofValue = {
            $case: 'dimensionValue',
            dimensionValue: reader.uint32(),
          };
          break;
        case 14:
          message.oneofValue = {
            $case: 'fractionValue',
            fractionValue: reader.uint32(),
          };
          break;
        case 6:
          message.oneofValue = {
            $case: 'intDecimalValue',
            intDecimalValue: reader.int32(),
          };
          break;
        case 7:
          message.oneofValue = {
            $case: 'intHexadecimalValue',
            intHexadecimalValue: reader.uint32(),
          };
          break;
        case 8:
          message.oneofValue = {
            $case: 'booleanValue',
            booleanValue: reader.bool(),
          };
          break;
        case 9:
          message.oneofValue = {
            $case: 'colorArgb8Value',
            colorArgb8Value: reader.uint32(),
          };
          break;
        case 10:
          message.oneofValue = {
            $case: 'colorRgb8Value',
            colorRgb8Value: reader.uint32(),
          };
          break;
        case 11:
          message.oneofValue = {
            $case: 'colorArgb4Value',
            colorArgb4Value: reader.uint32(),
          };
          break;
        case 12:
          message.oneofValue = {
            $case: 'colorRgb4Value',
            colorRgb4Value: reader.uint32(),
          };
          break;
        case 4:
          message.oneofValue = {
            $case: 'dimensionValueDeprecated',
            dimensionValueDeprecated: reader.float(),
          };
          break;
        case 5:
          message.oneofValue = {
            $case: 'fractionValueDeprecated',
            fractionValueDeprecated: reader.float(),
          };
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Primitive {
    const message = { ...basePrimitive } as Primitive;
    if (object.nullValue !== undefined && object.nullValue !== null) {
      message.oneofValue = {
        $case: 'nullValue',
        nullValue: Primitive_NullType.fromJSON(object.nullValue),
      };
    }
    if (object.emptyValue !== undefined && object.emptyValue !== null) {
      message.oneofValue = {
        $case: 'emptyValue',
        emptyValue: Primitive_EmptyType.fromJSON(object.emptyValue),
      };
    }
    if (object.floatValue !== undefined && object.floatValue !== null) {
      message.oneofValue = {
        $case: 'floatValue',
        floatValue: Number(object.floatValue),
      };
    }
    if (object.dimensionValue !== undefined && object.dimensionValue !== null) {
      message.oneofValue = {
        $case: 'dimensionValue',
        dimensionValue: Number(object.dimensionValue),
      };
    }
    if (object.fractionValue !== undefined && object.fractionValue !== null) {
      message.oneofValue = {
        $case: 'fractionValue',
        fractionValue: Number(object.fractionValue),
      };
    }
    if (object.intDecimalValue !== undefined && object.intDecimalValue !== null) {
      message.oneofValue = {
        $case: 'intDecimalValue',
        intDecimalValue: Number(object.intDecimalValue),
      };
    }
    if (object.intHexadecimalValue !== undefined && object.intHexadecimalValue !== null) {
      message.oneofValue = {
        $case: 'intHexadecimalValue',
        intHexadecimalValue: Number(object.intHexadecimalValue),
      };
    }
    if (object.booleanValue !== undefined && object.booleanValue !== null) {
      message.oneofValue = {
        $case: 'booleanValue',
        booleanValue: Boolean(object.booleanValue),
      };
    }
    if (object.colorArgb8Value !== undefined && object.colorArgb8Value !== null) {
      message.oneofValue = {
        $case: 'colorArgb8Value',
        colorArgb8Value: Number(object.colorArgb8Value),
      };
    }
    if (object.colorRgb8Value !== undefined && object.colorRgb8Value !== null) {
      message.oneofValue = {
        $case: 'colorRgb8Value',
        colorRgb8Value: Number(object.colorRgb8Value),
      };
    }
    if (object.colorArgb4Value !== undefined && object.colorArgb4Value !== null) {
      message.oneofValue = {
        $case: 'colorArgb4Value',
        colorArgb4Value: Number(object.colorArgb4Value),
      };
    }
    if (object.colorRgb4Value !== undefined && object.colorRgb4Value !== null) {
      message.oneofValue = {
        $case: 'colorRgb4Value',
        colorRgb4Value: Number(object.colorRgb4Value),
      };
    }
    if (object.dimensionValueDeprecated !== undefined && object.dimensionValueDeprecated !== null) {
      message.oneofValue = {
        $case: 'dimensionValueDeprecated',
        dimensionValueDeprecated: Number(object.dimensionValueDeprecated),
      };
    }
    if (object.fractionValueDeprecated !== undefined && object.fractionValueDeprecated !== null) {
      message.oneofValue = {
        $case: 'fractionValueDeprecated',
        fractionValueDeprecated: Number(object.fractionValueDeprecated),
      };
    }
    return message;
  },

  toJSON(message: Primitive): unknown {
    const obj: any = {};
    message.oneofValue?.$case === 'nullValue' &&
      (obj.nullValue = message.oneofValue?.nullValue
        ? Primitive_NullType.toJSON(message.oneofValue?.nullValue)
        : undefined);
    message.oneofValue?.$case === 'emptyValue' &&
      (obj.emptyValue = message.oneofValue?.emptyValue
        ? Primitive_EmptyType.toJSON(message.oneofValue?.emptyValue)
        : undefined);
    message.oneofValue?.$case === 'floatValue' && (obj.floatValue = message.oneofValue?.floatValue);
    message.oneofValue?.$case === 'dimensionValue' && (obj.dimensionValue = message.oneofValue?.dimensionValue);
    message.oneofValue?.$case === 'fractionValue' && (obj.fractionValue = message.oneofValue?.fractionValue);
    message.oneofValue?.$case === 'intDecimalValue' && (obj.intDecimalValue = message.oneofValue?.intDecimalValue);
    message.oneofValue?.$case === 'intHexadecimalValue' &&
      (obj.intHexadecimalValue = message.oneofValue?.intHexadecimalValue);
    message.oneofValue?.$case === 'booleanValue' && (obj.booleanValue = message.oneofValue?.booleanValue);
    message.oneofValue?.$case === 'colorArgb8Value' && (obj.colorArgb8Value = message.oneofValue?.colorArgb8Value);
    message.oneofValue?.$case === 'colorRgb8Value' && (obj.colorRgb8Value = message.oneofValue?.colorRgb8Value);
    message.oneofValue?.$case === 'colorArgb4Value' && (obj.colorArgb4Value = message.oneofValue?.colorArgb4Value);
    message.oneofValue?.$case === 'colorRgb4Value' && (obj.colorRgb4Value = message.oneofValue?.colorRgb4Value);
    message.oneofValue?.$case === 'dimensionValueDeprecated' &&
      (obj.dimensionValueDeprecated = message.oneofValue?.dimensionValueDeprecated);
    message.oneofValue?.$case === 'fractionValueDeprecated' &&
      (obj.fractionValueDeprecated = message.oneofValue?.fractionValueDeprecated);
    return obj;
  },

  fromPartial(object: DeepPartial<Primitive>): Primitive {
    const message = { ...basePrimitive } as Primitive;
    if (
      object.oneofValue?.$case === 'nullValue' &&
      object.oneofValue?.nullValue !== undefined &&
      object.oneofValue?.nullValue !== null
    ) {
      message.oneofValue = {
        $case: 'nullValue',
        nullValue: Primitive_NullType.fromPartial(object.oneofValue.nullValue),
      };
    }
    if (
      object.oneofValue?.$case === 'emptyValue' &&
      object.oneofValue?.emptyValue !== undefined &&
      object.oneofValue?.emptyValue !== null
    ) {
      message.oneofValue = {
        $case: 'emptyValue',
        emptyValue: Primitive_EmptyType.fromPartial(object.oneofValue.emptyValue),
      };
    }
    if (
      object.oneofValue?.$case === 'floatValue' &&
      object.oneofValue?.floatValue !== undefined &&
      object.oneofValue?.floatValue !== null
    ) {
      message.oneofValue = {
        $case: 'floatValue',
        floatValue: object.oneofValue.floatValue,
      };
    }
    if (
      object.oneofValue?.$case === 'dimensionValue' &&
      object.oneofValue?.dimensionValue !== undefined &&
      object.oneofValue?.dimensionValue !== null
    ) {
      message.oneofValue = {
        $case: 'dimensionValue',
        dimensionValue: object.oneofValue.dimensionValue,
      };
    }
    if (
      object.oneofValue?.$case === 'fractionValue' &&
      object.oneofValue?.fractionValue !== undefined &&
      object.oneofValue?.fractionValue !== null
    ) {
      message.oneofValue = {
        $case: 'fractionValue',
        fractionValue: object.oneofValue.fractionValue,
      };
    }
    if (
      object.oneofValue?.$case === 'intDecimalValue' &&
      object.oneofValue?.intDecimalValue !== undefined &&
      object.oneofValue?.intDecimalValue !== null
    ) {
      message.oneofValue = {
        $case: 'intDecimalValue',
        intDecimalValue: object.oneofValue.intDecimalValue,
      };
    }
    if (
      object.oneofValue?.$case === 'intHexadecimalValue' &&
      object.oneofValue?.intHexadecimalValue !== undefined &&
      object.oneofValue?.intHexadecimalValue !== null
    ) {
      message.oneofValue = {
        $case: 'intHexadecimalValue',
        intHexadecimalValue: object.oneofValue.intHexadecimalValue,
      };
    }
    if (
      object.oneofValue?.$case === 'booleanValue' &&
      object.oneofValue?.booleanValue !== undefined &&
      object.oneofValue?.booleanValue !== null
    ) {
      message.oneofValue = {
        $case: 'booleanValue',
        booleanValue: object.oneofValue.booleanValue,
      };
    }
    if (
      object.oneofValue?.$case === 'colorArgb8Value' &&
      object.oneofValue?.colorArgb8Value !== undefined &&
      object.oneofValue?.colorArgb8Value !== null
    ) {
      message.oneofValue = {
        $case: 'colorArgb8Value',
        colorArgb8Value: object.oneofValue.colorArgb8Value,
      };
    }
    if (
      object.oneofValue?.$case === 'colorRgb8Value' &&
      object.oneofValue?.colorRgb8Value !== undefined &&
      object.oneofValue?.colorRgb8Value !== null
    ) {
      message.oneofValue = {
        $case: 'colorRgb8Value',
        colorRgb8Value: object.oneofValue.colorRgb8Value,
      };
    }
    if (
      object.oneofValue?.$case === 'colorArgb4Value' &&
      object.oneofValue?.colorArgb4Value !== undefined &&
      object.oneofValue?.colorArgb4Value !== null
    ) {
      message.oneofValue = {
        $case: 'colorArgb4Value',
        colorArgb4Value: object.oneofValue.colorArgb4Value,
      };
    }
    if (
      object.oneofValue?.$case === 'colorRgb4Value' &&
      object.oneofValue?.colorRgb4Value !== undefined &&
      object.oneofValue?.colorRgb4Value !== null
    ) {
      message.oneofValue = {
        $case: 'colorRgb4Value',
        colorRgb4Value: object.oneofValue.colorRgb4Value,
      };
    }
    if (
      object.oneofValue?.$case === 'dimensionValueDeprecated' &&
      object.oneofValue?.dimensionValueDeprecated !== undefined &&
      object.oneofValue?.dimensionValueDeprecated !== null
    ) {
      message.oneofValue = {
        $case: 'dimensionValueDeprecated',
        dimensionValueDeprecated: object.oneofValue.dimensionValueDeprecated,
      };
    }
    if (
      object.oneofValue?.$case === 'fractionValueDeprecated' &&
      object.oneofValue?.fractionValueDeprecated !== undefined &&
      object.oneofValue?.fractionValueDeprecated !== null
    ) {
      message.oneofValue = {
        $case: 'fractionValueDeprecated',
        fractionValueDeprecated: object.oneofValue.fractionValueDeprecated,
      };
    }
    return message;
  },
};

const basePrimitive_NullType: object = {};

export const Primitive_NullType = {
  encode(_: Primitive_NullType, writer: Writer = Writer.create()): Writer {
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Primitive_NullType {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...basePrimitive_NullType } as Primitive_NullType;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(_: any): Primitive_NullType {
    const message = { ...basePrimitive_NullType } as Primitive_NullType;
    return message;
  },

  toJSON(_: Primitive_NullType): unknown {
    const obj: any = {};
    return obj;
  },

  fromPartial(_: DeepPartial<Primitive_NullType>): Primitive_NullType {
    const message = { ...basePrimitive_NullType } as Primitive_NullType;
    return message;
  },
};

const basePrimitive_EmptyType: object = {};

export const Primitive_EmptyType = {
  encode(_: Primitive_EmptyType, writer: Writer = Writer.create()): Writer {
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Primitive_EmptyType {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...basePrimitive_EmptyType } as Primitive_EmptyType;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(_: any): Primitive_EmptyType {
    const message = { ...basePrimitive_EmptyType } as Primitive_EmptyType;
    return message;
  },

  toJSON(_: Primitive_EmptyType): unknown {
    const obj: any = {};
    return obj;
  },

  fromPartial(_: DeepPartial<Primitive_EmptyType>): Primitive_EmptyType {
    const message = { ...basePrimitive_EmptyType } as Primitive_EmptyType;
    return message;
  },
};

const baseAttribute: object = { formatFlags: 0, minInt: 0, maxInt: 0 };

export const Attribute = {
  encode(message: Attribute, writer: Writer = Writer.create()): Writer {
    if (message.formatFlags !== 0) {
      writer.uint32(8).uint32(message.formatFlags);
    }
    if (message.minInt !== 0) {
      writer.uint32(16).int32(message.minInt);
    }
    if (message.maxInt !== 0) {
      writer.uint32(24).int32(message.maxInt);
    }
    for (const v of message.symbol) {
      Attribute_Symbol.encode(v!, writer.uint32(34).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Attribute {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseAttribute } as Attribute;
    message.symbol = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.formatFlags = reader.uint32();
          break;
        case 2:
          message.minInt = reader.int32();
          break;
        case 3:
          message.maxInt = reader.int32();
          break;
        case 4:
          message.symbol.push(Attribute_Symbol.decode(reader, reader.uint32()));
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Attribute {
    const message = { ...baseAttribute } as Attribute;
    message.symbol = [];
    if (object.formatFlags !== undefined && object.formatFlags !== null) {
      message.formatFlags = Number(object.formatFlags);
    }
    if (object.minInt !== undefined && object.minInt !== null) {
      message.minInt = Number(object.minInt);
    }
    if (object.maxInt !== undefined && object.maxInt !== null) {
      message.maxInt = Number(object.maxInt);
    }
    if (object.symbol !== undefined && object.symbol !== null) {
      for (const e of object.symbol) {
        message.symbol.push(Attribute_Symbol.fromJSON(e));
      }
    }
    return message;
  },

  toJSON(message: Attribute): unknown {
    const obj: any = {};
    message.formatFlags !== undefined && (obj.formatFlags = message.formatFlags);
    message.minInt !== undefined && (obj.minInt = message.minInt);
    message.maxInt !== undefined && (obj.maxInt = message.maxInt);
    if (message.symbol) {
      obj.symbol = message.symbol.map((e) => (e ? Attribute_Symbol.toJSON(e) : undefined));
    } else {
      obj.symbol = [];
    }
    return obj;
  },

  fromPartial(object: DeepPartial<Attribute>): Attribute {
    const message = { ...baseAttribute } as Attribute;
    message.symbol = [];
    if (object.formatFlags !== undefined && object.formatFlags !== null) {
      message.formatFlags = object.formatFlags;
    } else {
      message.formatFlags = 0;
    }
    if (object.minInt !== undefined && object.minInt !== null) {
      message.minInt = object.minInt;
    } else {
      message.minInt = 0;
    }
    if (object.maxInt !== undefined && object.maxInt !== null) {
      message.maxInt = object.maxInt;
    } else {
      message.maxInt = 0;
    }
    if (object.symbol !== undefined && object.symbol !== null) {
      for (const e of object.symbol) {
        message.symbol.push(Attribute_Symbol.fromPartial(e));
      }
    }
    return message;
  },
};

const baseAttribute_Symbol: object = { comment: '', value: 0, type: 0 };

export const Attribute_Symbol = {
  encode(message: Attribute_Symbol, writer: Writer = Writer.create()): Writer {
    if (message.source !== undefined) {
      Source.encode(message.source, writer.uint32(10).fork()).ldelim();
    }
    if (message.comment !== '') {
      writer.uint32(18).string(message.comment);
    }
    if (message.name !== undefined) {
      Reference.encode(message.name, writer.uint32(26).fork()).ldelim();
    }
    if (message.value !== 0) {
      writer.uint32(32).uint32(message.value);
    }
    if (message.type !== 0) {
      writer.uint32(40).uint32(message.type);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Attribute_Symbol {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseAttribute_Symbol } as Attribute_Symbol;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.source = Source.decode(reader, reader.uint32());
          break;
        case 2:
          message.comment = reader.string();
          break;
        case 3:
          message.name = Reference.decode(reader, reader.uint32());
          break;
        case 4:
          message.value = reader.uint32();
          break;
        case 5:
          message.type = reader.uint32();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Attribute_Symbol {
    const message = { ...baseAttribute_Symbol } as Attribute_Symbol;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromJSON(object.source);
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = String(object.comment);
    }
    if (object.name !== undefined && object.name !== null) {
      message.name = Reference.fromJSON(object.name);
    }
    if (object.value !== undefined && object.value !== null) {
      message.value = Number(object.value);
    }
    if (object.type !== undefined && object.type !== null) {
      message.type = Number(object.type);
    }
    return message;
  },

  toJSON(message: Attribute_Symbol): unknown {
    const obj: any = {};
    message.source !== undefined && (obj.source = message.source ? Source.toJSON(message.source) : undefined);
    message.comment !== undefined && (obj.comment = message.comment);
    message.name !== undefined && (obj.name = message.name ? Reference.toJSON(message.name) : undefined);
    message.value !== undefined && (obj.value = message.value);
    message.type !== undefined && (obj.type = message.type);
    return obj;
  },

  fromPartial(object: DeepPartial<Attribute_Symbol>): Attribute_Symbol {
    const message = { ...baseAttribute_Symbol } as Attribute_Symbol;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = object.comment;
    } else {
      message.comment = '';
    }
    if (object.name !== undefined && object.name !== null) {
      message.name = Reference.fromPartial(object.name);
    } else {
      message.name = undefined;
    }
    if (object.value !== undefined && object.value !== null) {
      message.value = object.value;
    } else {
      message.value = 0;
    }
    if (object.type !== undefined && object.type !== null) {
      message.type = object.type;
    } else {
      message.type = 0;
    }
    return message;
  },
};

const baseStyle: object = {};

export const Style = {
  encode(message: Style, writer: Writer = Writer.create()): Writer {
    if (message.parent !== undefined) {
      Reference.encode(message.parent, writer.uint32(10).fork()).ldelim();
    }
    if (message.parentSource !== undefined) {
      Source.encode(message.parentSource, writer.uint32(18).fork()).ldelim();
    }
    for (const v of message.entry) {
      Style_Entry.encode(v!, writer.uint32(26).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Style {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseStyle } as Style;
    message.entry = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.parent = Reference.decode(reader, reader.uint32());
          break;
        case 2:
          message.parentSource = Source.decode(reader, reader.uint32());
          break;
        case 3:
          message.entry.push(Style_Entry.decode(reader, reader.uint32()));
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Style {
    const message = { ...baseStyle } as Style;
    message.entry = [];
    if (object.parent !== undefined && object.parent !== null) {
      message.parent = Reference.fromJSON(object.parent);
    }
    if (object.parentSource !== undefined && object.parentSource !== null) {
      message.parentSource = Source.fromJSON(object.parentSource);
    }
    if (object.entry !== undefined && object.entry !== null) {
      for (const e of object.entry) {
        message.entry.push(Style_Entry.fromJSON(e));
      }
    }
    return message;
  },

  toJSON(message: Style): unknown {
    const obj: any = {};
    message.parent !== undefined && (obj.parent = message.parent ? Reference.toJSON(message.parent) : undefined);
    message.parentSource !== undefined &&
      (obj.parentSource = message.parentSource ? Source.toJSON(message.parentSource) : undefined);
    if (message.entry) {
      obj.entry = message.entry.map((e) => (e ? Style_Entry.toJSON(e) : undefined));
    } else {
      obj.entry = [];
    }
    return obj;
  },

  fromPartial(object: DeepPartial<Style>): Style {
    const message = { ...baseStyle } as Style;
    message.entry = [];
    if (object.parent !== undefined && object.parent !== null) {
      message.parent = Reference.fromPartial(object.parent);
    } else {
      message.parent = undefined;
    }
    if (object.parentSource !== undefined && object.parentSource !== null) {
      message.parentSource = Source.fromPartial(object.parentSource);
    } else {
      message.parentSource = undefined;
    }
    if (object.entry !== undefined && object.entry !== null) {
      for (const e of object.entry) {
        message.entry.push(Style_Entry.fromPartial(e));
      }
    }
    return message;
  },
};

const baseStyle_Entry: object = { comment: '' };

export const Style_Entry = {
  encode(message: Style_Entry, writer: Writer = Writer.create()): Writer {
    if (message.source !== undefined) {
      Source.encode(message.source, writer.uint32(10).fork()).ldelim();
    }
    if (message.comment !== '') {
      writer.uint32(18).string(message.comment);
    }
    if (message.key !== undefined) {
      Reference.encode(message.key, writer.uint32(26).fork()).ldelim();
    }
    if (message.item !== undefined) {
      Item.encode(message.item, writer.uint32(34).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Style_Entry {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseStyle_Entry } as Style_Entry;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.source = Source.decode(reader, reader.uint32());
          break;
        case 2:
          message.comment = reader.string();
          break;
        case 3:
          message.key = Reference.decode(reader, reader.uint32());
          break;
        case 4:
          message.item = Item.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Style_Entry {
    const message = { ...baseStyle_Entry } as Style_Entry;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromJSON(object.source);
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = String(object.comment);
    }
    if (object.key !== undefined && object.key !== null) {
      message.key = Reference.fromJSON(object.key);
    }
    if (object.item !== undefined && object.item !== null) {
      message.item = Item.fromJSON(object.item);
    }
    return message;
  },

  toJSON(message: Style_Entry): unknown {
    const obj: any = {};
    message.source !== undefined && (obj.source = message.source ? Source.toJSON(message.source) : undefined);
    message.comment !== undefined && (obj.comment = message.comment);
    message.key !== undefined && (obj.key = message.key ? Reference.toJSON(message.key) : undefined);
    message.item !== undefined && (obj.item = message.item ? Item.toJSON(message.item) : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<Style_Entry>): Style_Entry {
    const message = { ...baseStyle_Entry } as Style_Entry;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = object.comment;
    } else {
      message.comment = '';
    }
    if (object.key !== undefined && object.key !== null) {
      message.key = Reference.fromPartial(object.key);
    } else {
      message.key = undefined;
    }
    if (object.item !== undefined && object.item !== null) {
      message.item = Item.fromPartial(object.item);
    } else {
      message.item = undefined;
    }
    return message;
  },
};

const baseStyleable: object = {};

export const Styleable = {
  encode(message: Styleable, writer: Writer = Writer.create()): Writer {
    for (const v of message.entry) {
      Styleable_Entry.encode(v!, writer.uint32(10).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Styleable {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseStyleable } as Styleable;
    message.entry = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.entry.push(Styleable_Entry.decode(reader, reader.uint32()));
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Styleable {
    const message = { ...baseStyleable } as Styleable;
    message.entry = [];
    if (object.entry !== undefined && object.entry !== null) {
      for (const e of object.entry) {
        message.entry.push(Styleable_Entry.fromJSON(e));
      }
    }
    return message;
  },

  toJSON(message: Styleable): unknown {
    const obj: any = {};
    if (message.entry) {
      obj.entry = message.entry.map((e) => (e ? Styleable_Entry.toJSON(e) : undefined));
    } else {
      obj.entry = [];
    }
    return obj;
  },

  fromPartial(object: DeepPartial<Styleable>): Styleable {
    const message = { ...baseStyleable } as Styleable;
    message.entry = [];
    if (object.entry !== undefined && object.entry !== null) {
      for (const e of object.entry) {
        message.entry.push(Styleable_Entry.fromPartial(e));
      }
    }
    return message;
  },
};

const baseStyleable_Entry: object = { comment: '' };

export const Styleable_Entry = {
  encode(message: Styleable_Entry, writer: Writer = Writer.create()): Writer {
    if (message.source !== undefined) {
      Source.encode(message.source, writer.uint32(10).fork()).ldelim();
    }
    if (message.comment !== '') {
      writer.uint32(18).string(message.comment);
    }
    if (message.attr !== undefined) {
      Reference.encode(message.attr, writer.uint32(26).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Styleable_Entry {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseStyleable_Entry } as Styleable_Entry;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.source = Source.decode(reader, reader.uint32());
          break;
        case 2:
          message.comment = reader.string();
          break;
        case 3:
          message.attr = Reference.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Styleable_Entry {
    const message = { ...baseStyleable_Entry } as Styleable_Entry;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromJSON(object.source);
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = String(object.comment);
    }
    if (object.attr !== undefined && object.attr !== null) {
      message.attr = Reference.fromJSON(object.attr);
    }
    return message;
  },

  toJSON(message: Styleable_Entry): unknown {
    const obj: any = {};
    message.source !== undefined && (obj.source = message.source ? Source.toJSON(message.source) : undefined);
    message.comment !== undefined && (obj.comment = message.comment);
    message.attr !== undefined && (obj.attr = message.attr ? Reference.toJSON(message.attr) : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<Styleable_Entry>): Styleable_Entry {
    const message = { ...baseStyleable_Entry } as Styleable_Entry;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = object.comment;
    } else {
      message.comment = '';
    }
    if (object.attr !== undefined && object.attr !== null) {
      message.attr = Reference.fromPartial(object.attr);
    } else {
      message.attr = undefined;
    }
    return message;
  },
};

const baseArray: object = {};

export const Array = {
  encode(message: Array, writer: Writer = Writer.create()): Writer {
    for (const v of message.element) {
      Array_Element.encode(v!, writer.uint32(10).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Array {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseArray } as Array;
    message.element = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.element.push(Array_Element.decode(reader, reader.uint32()));
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Array {
    const message = { ...baseArray } as Array;
    message.element = [];
    if (object.element !== undefined && object.element !== null) {
      for (const e of object.element) {
        message.element.push(Array_Element.fromJSON(e));
      }
    }
    return message;
  },

  toJSON(message: Array): unknown {
    const obj: any = {};
    if (message.element) {
      obj.element = message.element.map((e) => (e ? Array_Element.toJSON(e) : undefined));
    } else {
      obj.element = [];
    }
    return obj;
  },

  fromPartial(object: DeepPartial<Array>): Array {
    const message = { ...baseArray } as Array;
    message.element = [];
    if (object.element !== undefined && object.element !== null) {
      for (const e of object.element) {
        message.element.push(Array_Element.fromPartial(e));
      }
    }
    return message;
  },
};

const baseArray_Element: object = { comment: '' };

export const Array_Element = {
  encode(message: Array_Element, writer: Writer = Writer.create()): Writer {
    if (message.source !== undefined) {
      Source.encode(message.source, writer.uint32(10).fork()).ldelim();
    }
    if (message.comment !== '') {
      writer.uint32(18).string(message.comment);
    }
    if (message.item !== undefined) {
      Item.encode(message.item, writer.uint32(26).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Array_Element {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseArray_Element } as Array_Element;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.source = Source.decode(reader, reader.uint32());
          break;
        case 2:
          message.comment = reader.string();
          break;
        case 3:
          message.item = Item.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Array_Element {
    const message = { ...baseArray_Element } as Array_Element;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromJSON(object.source);
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = String(object.comment);
    }
    if (object.item !== undefined && object.item !== null) {
      message.item = Item.fromJSON(object.item);
    }
    return message;
  },

  toJSON(message: Array_Element): unknown {
    const obj: any = {};
    message.source !== undefined && (obj.source = message.source ? Source.toJSON(message.source) : undefined);
    message.comment !== undefined && (obj.comment = message.comment);
    message.item !== undefined && (obj.item = message.item ? Item.toJSON(message.item) : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<Array_Element>): Array_Element {
    const message = { ...baseArray_Element } as Array_Element;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = object.comment;
    } else {
      message.comment = '';
    }
    if (object.item !== undefined && object.item !== null) {
      message.item = Item.fromPartial(object.item);
    } else {
      message.item = undefined;
    }
    return message;
  },
};

const basePlural: object = {};

export const Plural = {
  encode(message: Plural, writer: Writer = Writer.create()): Writer {
    for (const v of message.entry) {
      Plural_Entry.encode(v!, writer.uint32(10).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Plural {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...basePlural } as Plural;
    message.entry = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.entry.push(Plural_Entry.decode(reader, reader.uint32()));
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Plural {
    const message = { ...basePlural } as Plural;
    message.entry = [];
    if (object.entry !== undefined && object.entry !== null) {
      for (const e of object.entry) {
        message.entry.push(Plural_Entry.fromJSON(e));
      }
    }
    return message;
  },

  toJSON(message: Plural): unknown {
    const obj: any = {};
    if (message.entry) {
      obj.entry = message.entry.map((e) => (e ? Plural_Entry.toJSON(e) : undefined));
    } else {
      obj.entry = [];
    }
    return obj;
  },

  fromPartial(object: DeepPartial<Plural>): Plural {
    const message = { ...basePlural } as Plural;
    message.entry = [];
    if (object.entry !== undefined && object.entry !== null) {
      for (const e of object.entry) {
        message.entry.push(Plural_Entry.fromPartial(e));
      }
    }
    return message;
  },
};

const basePlural_Entry: object = { comment: '', arity: 0 };

export const Plural_Entry = {
  encode(message: Plural_Entry, writer: Writer = Writer.create()): Writer {
    if (message.source !== undefined) {
      Source.encode(message.source, writer.uint32(10).fork()).ldelim();
    }
    if (message.comment !== '') {
      writer.uint32(18).string(message.comment);
    }
    if (message.arity !== 0) {
      writer.uint32(24).int32(message.arity);
    }
    if (message.item !== undefined) {
      Item.encode(message.item, writer.uint32(34).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): Plural_Entry {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...basePlural_Entry } as Plural_Entry;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.source = Source.decode(reader, reader.uint32());
          break;
        case 2:
          message.comment = reader.string();
          break;
        case 3:
          message.arity = reader.int32() as any;
          break;
        case 4:
          message.item = Item.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): Plural_Entry {
    const message = { ...basePlural_Entry } as Plural_Entry;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromJSON(object.source);
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = String(object.comment);
    }
    if (object.arity !== undefined && object.arity !== null) {
      message.arity = plural_ArityFromJSON(object.arity);
    }
    if (object.item !== undefined && object.item !== null) {
      message.item = Item.fromJSON(object.item);
    }
    return message;
  },

  toJSON(message: Plural_Entry): unknown {
    const obj: any = {};
    message.source !== undefined && (obj.source = message.source ? Source.toJSON(message.source) : undefined);
    message.comment !== undefined && (obj.comment = message.comment);
    message.arity !== undefined && (obj.arity = plural_ArityToJSON(message.arity));
    message.item !== undefined && (obj.item = message.item ? Item.toJSON(message.item) : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<Plural_Entry>): Plural_Entry {
    const message = { ...basePlural_Entry } as Plural_Entry;
    if (object.source !== undefined && object.source !== null) {
      message.source = Source.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    if (object.comment !== undefined && object.comment !== null) {
      message.comment = object.comment;
    } else {
      message.comment = '';
    }
    if (object.arity !== undefined && object.arity !== null) {
      message.arity = object.arity;
    } else {
      message.arity = 0;
    }
    if (object.item !== undefined && object.item !== null) {
      message.item = Item.fromPartial(object.item);
    } else {
      message.item = undefined;
    }
    return message;
  },
};

const baseXmlNode: object = {};

export const XmlNode = {
  encode(message: XmlNode, writer: Writer = Writer.create()): Writer {
    if (message.node?.$case === 'element') {
      XmlElement.encode(message.node.element, writer.uint32(10).fork()).ldelim();
    }
    if (message.node?.$case === 'text') {
      writer.uint32(18).string(message.node.text);
    }
    if (message.source !== undefined) {
      SourcePosition.encode(message.source, writer.uint32(26).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): XmlNode {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseXmlNode } as XmlNode;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.node = {
            $case: 'element',
            element: XmlElement.decode(reader, reader.uint32()),
          };
          break;
        case 2:
          message.node = { $case: 'text', text: reader.string() };
          break;
        case 3:
          message.source = SourcePosition.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): XmlNode {
    const message = { ...baseXmlNode } as XmlNode;
    if (object.element !== undefined && object.element !== null) {
      message.node = {
        $case: 'element',
        element: XmlElement.fromJSON(object.element),
      };
    }
    if (object.text !== undefined && object.text !== null) {
      message.node = { $case: 'text', text: String(object.text) };
    }
    if (object.source !== undefined && object.source !== null) {
      message.source = SourcePosition.fromJSON(object.source);
    }
    return message;
  },

  toJSON(message: XmlNode): unknown {
    const obj: any = {};
    message.node?.$case === 'element' &&
      (obj.element = message.node?.element ? XmlElement.toJSON(message.node?.element) : undefined);
    message.node?.$case === 'text' && (obj.text = message.node?.text);
    message.source !== undefined && (obj.source = message.source ? SourcePosition.toJSON(message.source) : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<XmlNode>): XmlNode {
    const message = { ...baseXmlNode } as XmlNode;
    if (object.node?.$case === 'element' && object.node?.element !== undefined && object.node?.element !== null) {
      message.node = {
        $case: 'element',
        element: XmlElement.fromPartial(object.node.element),
      };
    }
    if (object.node?.$case === 'text' && object.node?.text !== undefined && object.node?.text !== null) {
      message.node = { $case: 'text', text: object.node.text };
    }
    if (object.source !== undefined && object.source !== null) {
      message.source = SourcePosition.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    return message;
  },
};

const baseXmlElement: object = { namespaceUri: '', name: '' };

export const XmlElement = {
  encode(message: XmlElement, writer: Writer = Writer.create()): Writer {
    for (const v of message.namespaceDeclaration) {
      XmlNamespace.encode(v!, writer.uint32(10).fork()).ldelim();
    }
    if (message.namespaceUri !== '') {
      writer.uint32(18).string(message.namespaceUri);
    }
    if (message.name !== '') {
      writer.uint32(26).string(message.name);
    }
    for (const v of message.attribute) {
      XmlAttribute.encode(v!, writer.uint32(34).fork()).ldelim();
    }
    for (const v of message.child) {
      XmlNode.encode(v!, writer.uint32(42).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): XmlElement {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseXmlElement } as XmlElement;
    message.namespaceDeclaration = [];
    message.attribute = [];
    message.child = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.namespaceDeclaration.push(XmlNamespace.decode(reader, reader.uint32()));
          break;
        case 2:
          message.namespaceUri = reader.string();
          break;
        case 3:
          message.name = reader.string();
          break;
        case 4:
          message.attribute.push(XmlAttribute.decode(reader, reader.uint32()));
          break;
        case 5:
          message.child.push(XmlNode.decode(reader, reader.uint32()));
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): XmlElement {
    const message = { ...baseXmlElement } as XmlElement;
    message.namespaceDeclaration = [];
    message.attribute = [];
    message.child = [];
    if (object.namespaceDeclaration !== undefined && object.namespaceDeclaration !== null) {
      for (const e of object.namespaceDeclaration) {
        message.namespaceDeclaration.push(XmlNamespace.fromJSON(e));
      }
    }
    if (object.namespaceUri !== undefined && object.namespaceUri !== null) {
      message.namespaceUri = String(object.namespaceUri);
    }
    if (object.name !== undefined && object.name !== null) {
      message.name = String(object.name);
    }
    if (object.attribute !== undefined && object.attribute !== null) {
      for (const e of object.attribute) {
        message.attribute.push(XmlAttribute.fromJSON(e));
      }
    }
    if (object.child !== undefined && object.child !== null) {
      for (const e of object.child) {
        message.child.push(XmlNode.fromJSON(e));
      }
    }
    return message;
  },

  toJSON(message: XmlElement): unknown {
    const obj: any = {};
    if (message.namespaceDeclaration) {
      obj.namespaceDeclaration = message.namespaceDeclaration.map((e) => (e ? XmlNamespace.toJSON(e) : undefined));
    } else {
      obj.namespaceDeclaration = [];
    }
    message.namespaceUri !== undefined && (obj.namespaceUri = message.namespaceUri);
    message.name !== undefined && (obj.name = message.name);
    if (message.attribute) {
      obj.attribute = message.attribute.map((e) => (e ? XmlAttribute.toJSON(e) : undefined));
    } else {
      obj.attribute = [];
    }
    if (message.child) {
      obj.child = message.child.map((e) => (e ? XmlNode.toJSON(e) : undefined));
    } else {
      obj.child = [];
    }
    return obj;
  },

  fromPartial(object: DeepPartial<XmlElement>): XmlElement {
    const message = { ...baseXmlElement } as XmlElement;
    message.namespaceDeclaration = [];
    message.attribute = [];
    message.child = [];
    if (object.namespaceDeclaration !== undefined && object.namespaceDeclaration !== null) {
      for (const e of object.namespaceDeclaration) {
        message.namespaceDeclaration.push(XmlNamespace.fromPartial(e));
      }
    }
    if (object.namespaceUri !== undefined && object.namespaceUri !== null) {
      message.namespaceUri = object.namespaceUri;
    } else {
      message.namespaceUri = '';
    }
    if (object.name !== undefined && object.name !== null) {
      message.name = object.name;
    } else {
      message.name = '';
    }
    if (object.attribute !== undefined && object.attribute !== null) {
      for (const e of object.attribute) {
        message.attribute.push(XmlAttribute.fromPartial(e));
      }
    }
    if (object.child !== undefined && object.child !== null) {
      for (const e of object.child) {
        message.child.push(XmlNode.fromPartial(e));
      }
    }
    return message;
  },
};

const baseXmlNamespace: object = { prefix: '', uri: '' };

export const XmlNamespace = {
  encode(message: XmlNamespace, writer: Writer = Writer.create()): Writer {
    if (message.prefix !== '') {
      writer.uint32(10).string(message.prefix);
    }
    if (message.uri !== '') {
      writer.uint32(18).string(message.uri);
    }
    if (message.source !== undefined) {
      SourcePosition.encode(message.source, writer.uint32(26).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): XmlNamespace {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseXmlNamespace } as XmlNamespace;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.prefix = reader.string();
          break;
        case 2:
          message.uri = reader.string();
          break;
        case 3:
          message.source = SourcePosition.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): XmlNamespace {
    const message = { ...baseXmlNamespace } as XmlNamespace;
    if (object.prefix !== undefined && object.prefix !== null) {
      message.prefix = String(object.prefix);
    }
    if (object.uri !== undefined && object.uri !== null) {
      message.uri = String(object.uri);
    }
    if (object.source !== undefined && object.source !== null) {
      message.source = SourcePosition.fromJSON(object.source);
    }
    return message;
  },

  toJSON(message: XmlNamespace): unknown {
    const obj: any = {};
    message.prefix !== undefined && (obj.prefix = message.prefix);
    message.uri !== undefined && (obj.uri = message.uri);
    message.source !== undefined && (obj.source = message.source ? SourcePosition.toJSON(message.source) : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<XmlNamespace>): XmlNamespace {
    const message = { ...baseXmlNamespace } as XmlNamespace;
    if (object.prefix !== undefined && object.prefix !== null) {
      message.prefix = object.prefix;
    } else {
      message.prefix = '';
    }
    if (object.uri !== undefined && object.uri !== null) {
      message.uri = object.uri;
    } else {
      message.uri = '';
    }
    if (object.source !== undefined && object.source !== null) {
      message.source = SourcePosition.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    return message;
  },
};

const baseXmlAttribute: object = {
  namespaceUri: '',
  name: '',
  value: '',
  resourceId: 0,
};

export const XmlAttribute = {
  encode(message: XmlAttribute, writer: Writer = Writer.create()): Writer {
    if (message.namespaceUri !== '') {
      writer.uint32(10).string(message.namespaceUri);
    }
    if (message.name !== '') {
      writer.uint32(18).string(message.name);
    }
    if (message.value !== '') {
      writer.uint32(26).string(message.value);
    }
    if (message.source !== undefined) {
      SourcePosition.encode(message.source, writer.uint32(34).fork()).ldelim();
    }
    if (message.resourceId !== 0) {
      writer.uint32(40).uint32(message.resourceId);
    }
    if (message.compiledItem !== undefined) {
      Item.encode(message.compiledItem, writer.uint32(50).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): XmlAttribute {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseXmlAttribute } as XmlAttribute;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.namespaceUri = reader.string();
          break;
        case 2:
          message.name = reader.string();
          break;
        case 3:
          message.value = reader.string();
          break;
        case 4:
          message.source = SourcePosition.decode(reader, reader.uint32());
          break;
        case 5:
          message.resourceId = reader.uint32();
          break;
        case 6:
          message.compiledItem = Item.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): XmlAttribute {
    const message = { ...baseXmlAttribute } as XmlAttribute;
    if (object.namespaceUri !== undefined && object.namespaceUri !== null) {
      message.namespaceUri = String(object.namespaceUri);
    }
    if (object.name !== undefined && object.name !== null) {
      message.name = String(object.name);
    }
    if (object.value !== undefined && object.value !== null) {
      message.value = String(object.value);
    }
    if (object.source !== undefined && object.source !== null) {
      message.source = SourcePosition.fromJSON(object.source);
    }
    if (object.resourceId !== undefined && object.resourceId !== null) {
      message.resourceId = Number(object.resourceId);
    }
    if (object.compiledItem !== undefined && object.compiledItem !== null) {
      message.compiledItem = Item.fromJSON(object.compiledItem);
    }
    return message;
  },

  toJSON(message: XmlAttribute): unknown {
    const obj: any = {};
    message.namespaceUri !== undefined && (obj.namespaceUri = message.namespaceUri);
    message.name !== undefined && (obj.name = message.name);
    message.value !== undefined && (obj.value = message.value);
    message.source !== undefined && (obj.source = message.source ? SourcePosition.toJSON(message.source) : undefined);
    message.resourceId !== undefined && (obj.resourceId = message.resourceId);
    message.compiledItem !== undefined &&
      (obj.compiledItem = message.compiledItem ? Item.toJSON(message.compiledItem) : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<XmlAttribute>): XmlAttribute {
    const message = { ...baseXmlAttribute } as XmlAttribute;
    if (object.namespaceUri !== undefined && object.namespaceUri !== null) {
      message.namespaceUri = object.namespaceUri;
    } else {
      message.namespaceUri = '';
    }
    if (object.name !== undefined && object.name !== null) {
      message.name = object.name;
    } else {
      message.name = '';
    }
    if (object.value !== undefined && object.value !== null) {
      message.value = object.value;
    } else {
      message.value = '';
    }
    if (object.source !== undefined && object.source !== null) {
      message.source = SourcePosition.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    if (object.resourceId !== undefined && object.resourceId !== null) {
      message.resourceId = object.resourceId;
    } else {
      message.resourceId = 0;
    }
    if (object.compiledItem !== undefined && object.compiledItem !== null) {
      message.compiledItem = Item.fromPartial(object.compiledItem);
    } else {
      message.compiledItem = undefined;
    }
    return message;
  },
};

const baseMacroBody: object = { rawString: '' };

export const MacroBody = {
  encode(message: MacroBody, writer: Writer = Writer.create()): Writer {
    if (message.rawString !== '') {
      writer.uint32(10).string(message.rawString);
    }
    if (message.styleString !== undefined) {
      StyleString.encode(message.styleString, writer.uint32(18).fork()).ldelim();
    }
    for (const v of message.untranslatableSections) {
      UntranslatableSection.encode(v!, writer.uint32(26).fork()).ldelim();
    }
    for (const v of message.namespaceStack) {
      NamespaceAlias.encode(v!, writer.uint32(34).fork()).ldelim();
    }
    if (message.source !== undefined) {
      SourcePosition.encode(message.source, writer.uint32(42).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): MacroBody {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseMacroBody } as MacroBody;
    message.untranslatableSections = [];
    message.namespaceStack = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.rawString = reader.string();
          break;
        case 2:
          message.styleString = StyleString.decode(reader, reader.uint32());
          break;
        case 3:
          message.untranslatableSections.push(UntranslatableSection.decode(reader, reader.uint32()));
          break;
        case 4:
          message.namespaceStack.push(NamespaceAlias.decode(reader, reader.uint32()));
          break;
        case 5:
          message.source = SourcePosition.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): MacroBody {
    const message = { ...baseMacroBody } as MacroBody;
    message.untranslatableSections = [];
    message.namespaceStack = [];
    if (object.rawString !== undefined && object.rawString !== null) {
      message.rawString = String(object.rawString);
    }
    if (object.styleString !== undefined && object.styleString !== null) {
      message.styleString = StyleString.fromJSON(object.styleString);
    }
    if (object.untranslatableSections !== undefined && object.untranslatableSections !== null) {
      for (const e of object.untranslatableSections) {
        message.untranslatableSections.push(UntranslatableSection.fromJSON(e));
      }
    }
    if (object.namespaceStack !== undefined && object.namespaceStack !== null) {
      for (const e of object.namespaceStack) {
        message.namespaceStack.push(NamespaceAlias.fromJSON(e));
      }
    }
    if (object.source !== undefined && object.source !== null) {
      message.source = SourcePosition.fromJSON(object.source);
    }
    return message;
  },

  toJSON(message: MacroBody): unknown {
    const obj: any = {};
    message.rawString !== undefined && (obj.rawString = message.rawString);
    message.styleString !== undefined &&
      (obj.styleString = message.styleString ? StyleString.toJSON(message.styleString) : undefined);
    if (message.untranslatableSections) {
      obj.untranslatableSections = message.untranslatableSections.map((e) =>
        e ? UntranslatableSection.toJSON(e) : undefined,
      );
    } else {
      obj.untranslatableSections = [];
    }
    if (message.namespaceStack) {
      obj.namespaceStack = message.namespaceStack.map((e) => (e ? NamespaceAlias.toJSON(e) : undefined));
    } else {
      obj.namespaceStack = [];
    }
    message.source !== undefined && (obj.source = message.source ? SourcePosition.toJSON(message.source) : undefined);
    return obj;
  },

  fromPartial(object: DeepPartial<MacroBody>): MacroBody {
    const message = { ...baseMacroBody } as MacroBody;
    message.untranslatableSections = [];
    message.namespaceStack = [];
    if (object.rawString !== undefined && object.rawString !== null) {
      message.rawString = object.rawString;
    } else {
      message.rawString = '';
    }
    if (object.styleString !== undefined && object.styleString !== null) {
      message.styleString = StyleString.fromPartial(object.styleString);
    } else {
      message.styleString = undefined;
    }
    if (object.untranslatableSections !== undefined && object.untranslatableSections !== null) {
      for (const e of object.untranslatableSections) {
        message.untranslatableSections.push(UntranslatableSection.fromPartial(e));
      }
    }
    if (object.namespaceStack !== undefined && object.namespaceStack !== null) {
      for (const e of object.namespaceStack) {
        message.namespaceStack.push(NamespaceAlias.fromPartial(e));
      }
    }
    if (object.source !== undefined && object.source !== null) {
      message.source = SourcePosition.fromPartial(object.source);
    } else {
      message.source = undefined;
    }
    return message;
  },
};

const baseNamespaceAlias: object = {
  prefix: '',
  packageName: '',
  isPrivate: false,
};

export const NamespaceAlias = {
  encode(message: NamespaceAlias, writer: Writer = Writer.create()): Writer {
    if (message.prefix !== '') {
      writer.uint32(10).string(message.prefix);
    }
    if (message.packageName !== '') {
      writer.uint32(18).string(message.packageName);
    }
    if (message.isPrivate === true) {
      writer.uint32(24).bool(message.isPrivate);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): NamespaceAlias {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseNamespaceAlias } as NamespaceAlias;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.prefix = reader.string();
          break;
        case 2:
          message.packageName = reader.string();
          break;
        case 3:
          message.isPrivate = reader.bool();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): NamespaceAlias {
    const message = { ...baseNamespaceAlias } as NamespaceAlias;
    if (object.prefix !== undefined && object.prefix !== null) {
      message.prefix = String(object.prefix);
    }
    if (object.packageName !== undefined && object.packageName !== null) {
      message.packageName = String(object.packageName);
    }
    if (object.isPrivate !== undefined && object.isPrivate !== null) {
      message.isPrivate = Boolean(object.isPrivate);
    }
    return message;
  },

  toJSON(message: NamespaceAlias): unknown {
    const obj: any = {};
    message.prefix !== undefined && (obj.prefix = message.prefix);
    message.packageName !== undefined && (obj.packageName = message.packageName);
    message.isPrivate !== undefined && (obj.isPrivate = message.isPrivate);
    return obj;
  },

  fromPartial(object: DeepPartial<NamespaceAlias>): NamespaceAlias {
    const message = { ...baseNamespaceAlias } as NamespaceAlias;
    if (object.prefix !== undefined && object.prefix !== null) {
      message.prefix = object.prefix;
    } else {
      message.prefix = '';
    }
    if (object.packageName !== undefined && object.packageName !== null) {
      message.packageName = object.packageName;
    } else {
      message.packageName = '';
    }
    if (object.isPrivate !== undefined && object.isPrivate !== null) {
      message.isPrivate = object.isPrivate;
    } else {
      message.isPrivate = false;
    }
    return message;
  },
};

const baseStyleString: object = { str: '' };

export const StyleString = {
  encode(message: StyleString, writer: Writer = Writer.create()): Writer {
    if (message.str !== '') {
      writer.uint32(10).string(message.str);
    }
    for (const v of message.spans) {
      StyleString_Span.encode(v!, writer.uint32(18).fork()).ldelim();
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): StyleString {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseStyleString } as StyleString;
    message.spans = [];
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.str = reader.string();
          break;
        case 2:
          message.spans.push(StyleString_Span.decode(reader, reader.uint32()));
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): StyleString {
    const message = { ...baseStyleString } as StyleString;
    message.spans = [];
    if (object.str !== undefined && object.str !== null) {
      message.str = String(object.str);
    }
    if (object.spans !== undefined && object.spans !== null) {
      for (const e of object.spans) {
        message.spans.push(StyleString_Span.fromJSON(e));
      }
    }
    return message;
  },

  toJSON(message: StyleString): unknown {
    const obj: any = {};
    message.str !== undefined && (obj.str = message.str);
    if (message.spans) {
      obj.spans = message.spans.map((e) => (e ? StyleString_Span.toJSON(e) : undefined));
    } else {
      obj.spans = [];
    }
    return obj;
  },

  fromPartial(object: DeepPartial<StyleString>): StyleString {
    const message = { ...baseStyleString } as StyleString;
    message.spans = [];
    if (object.str !== undefined && object.str !== null) {
      message.str = object.str;
    } else {
      message.str = '';
    }
    if (object.spans !== undefined && object.spans !== null) {
      for (const e of object.spans) {
        message.spans.push(StyleString_Span.fromPartial(e));
      }
    }
    return message;
  },
};

const baseStyleString_Span: object = { name: '', startIndex: 0, endIndex: 0 };

export const StyleString_Span = {
  encode(message: StyleString_Span, writer: Writer = Writer.create()): Writer {
    if (message.name !== '') {
      writer.uint32(10).string(message.name);
    }
    if (message.startIndex !== 0) {
      writer.uint32(16).uint32(message.startIndex);
    }
    if (message.endIndex !== 0) {
      writer.uint32(24).uint32(message.endIndex);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): StyleString_Span {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseStyleString_Span } as StyleString_Span;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.name = reader.string();
          break;
        case 2:
          message.startIndex = reader.uint32();
          break;
        case 3:
          message.endIndex = reader.uint32();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): StyleString_Span {
    const message = { ...baseStyleString_Span } as StyleString_Span;
    if (object.name !== undefined && object.name !== null) {
      message.name = String(object.name);
    }
    if (object.startIndex !== undefined && object.startIndex !== null) {
      message.startIndex = Number(object.startIndex);
    }
    if (object.endIndex !== undefined && object.endIndex !== null) {
      message.endIndex = Number(object.endIndex);
    }
    return message;
  },

  toJSON(message: StyleString_Span): unknown {
    const obj: any = {};
    message.name !== undefined && (obj.name = message.name);
    message.startIndex !== undefined && (obj.startIndex = message.startIndex);
    message.endIndex !== undefined && (obj.endIndex = message.endIndex);
    return obj;
  },

  fromPartial(object: DeepPartial<StyleString_Span>): StyleString_Span {
    const message = { ...baseStyleString_Span } as StyleString_Span;
    if (object.name !== undefined && object.name !== null) {
      message.name = object.name;
    } else {
      message.name = '';
    }
    if (object.startIndex !== undefined && object.startIndex !== null) {
      message.startIndex = object.startIndex;
    } else {
      message.startIndex = 0;
    }
    if (object.endIndex !== undefined && object.endIndex !== null) {
      message.endIndex = object.endIndex;
    } else {
      message.endIndex = 0;
    }
    return message;
  },
};

const baseUntranslatableSection: object = { startIndex: 0, endIndex: 0 };

export const UntranslatableSection = {
  encode(message: UntranslatableSection, writer: Writer = Writer.create()): Writer {
    if (message.startIndex !== 0) {
      writer.uint32(8).uint64(message.startIndex);
    }
    if (message.endIndex !== 0) {
      writer.uint32(16).uint64(message.endIndex);
    }
    return writer;
  },

  decode(input: Reader | Uint8Array, length?: number): UntranslatableSection {
    const reader = input instanceof Reader ? input : new Reader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = { ...baseUntranslatableSection } as UntranslatableSection;
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.startIndex = longToNumber(reader.uint64() as Long);
          break;
        case 2:
          message.endIndex = longToNumber(reader.uint64() as Long);
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },

  fromJSON(object: any): UntranslatableSection {
    const message = { ...baseUntranslatableSection } as UntranslatableSection;
    if (object.startIndex !== undefined && object.startIndex !== null) {
      message.startIndex = Number(object.startIndex);
    }
    if (object.endIndex !== undefined && object.endIndex !== null) {
      message.endIndex = Number(object.endIndex);
    }
    return message;
  },

  toJSON(message: UntranslatableSection): unknown {
    const obj: any = {};
    message.startIndex !== undefined && (obj.startIndex = message.startIndex);
    message.endIndex !== undefined && (obj.endIndex = message.endIndex);
    return obj;
  },

  fromPartial(object: DeepPartial<UntranslatableSection>): UntranslatableSection {
    const message = { ...baseUntranslatableSection } as UntranslatableSection;
    if (object.startIndex !== undefined && object.startIndex !== null) {
      message.startIndex = object.startIndex;
    } else {
      message.startIndex = 0;
    }
    if (object.endIndex !== undefined && object.endIndex !== null) {
      message.endIndex = object.endIndex;
    } else {
      message.endIndex = 0;
    }
    return message;
  },
};

declare var self: any | undefined;
declare var window: any | undefined;
declare var global: any | undefined;
var globalThis: any = (() => {
  if (typeof globalThis !== 'undefined') return globalThis;
  if (typeof self !== 'undefined') return self;
  if (typeof window !== 'undefined') return window;
  if (typeof global !== 'undefined') return global;
  throw 'Unable to locate global object';
})();

const atob: (b64: string) => string =
  globalThis.atob || ((b64) => globalThis.Buffer.from(b64, 'base64').toString('binary'));
function bytesFromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; ++i) {
    arr[i] = bin.charCodeAt(i);
  }
  return arr;
}

const btoa: (bin: string) => string =
  globalThis.btoa || ((bin) => globalThis.Buffer.from(bin, 'binary').toString('base64'));
export function base64FromBytes(arr: Uint8Array): string {
  const bin: string[] = [];
  for (const byte of arr) {
    bin.push(String.fromCharCode(byte));
  }
  return btoa(bin.join(''));
}

type Builtin = Date | Function | Uint8Array | string | number | boolean | undefined;
// @ts-ignore
export type DeepPartial<T> = T extends Builtin
  ? T
  : // @ts-ignore
    T extends Array<infer U>
    ? // @ts-ignore
      Array<DeepPartial<U>>
    : T extends ReadonlyArray<infer U>
      ? ReadonlyArray<DeepPartial<U>>
      : T extends { $case: string }
        ? { [K in keyof Omit<T, '$case'>]?: DeepPartial<T[K]> } & {
            $case: T['$case'];
          }
        : T extends {}
          ? { [K in keyof T]?: DeepPartial<T[K]> }
          : Partial<T>;

function longToNumber(long: Long): number {
  if (long.gt(Number.MAX_SAFE_INTEGER)) {
    throw new globalThis.Error('Value is larger than Number.MAX_SAFE_INTEGER');
  }
  return long.toNumber();
}

// If you get a compile-error about 'Constructor<Long> and ... have no overlap',
// add '--ts_proto_opt=esModuleInterop=true' as a flag when calling 'protoc'.
// @ts-ignore
if (util.Long !== Long) {
  util.Long = Long as any;
  configure();
}
