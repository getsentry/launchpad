export interface DexFileHeader {
  classDefsSize: number;
  classDefsOff: number;
  stringIdsOff: number;
  typeIdsOff: number;
  fieldIdsOff: number;
  protoIdsOff: number;
  methodIdsOff: number;

  // Ignoring fields for now:
  // checksum: number;
  // signature: number[20];
  // fileSize: number;
  // headerSize: number;
  // endianTag: number;
  // linkSize: number;
  // linkOffset: number;
  // mapOffset: number;
  // typeIdsSize: number;
  // prototypeIdsSize: number;
  // fieldIdsSize: number;
  // methodIdsSize: number;
  // dataSize: number;
  // dataOffset: number;
}

export interface ClassDefinition {
  signature: string;
  sourceFileName: string | null | undefined;
  annotations: Annotation[];
  methods: Method[];
  accessFlags: AccessFlag[];
  superclass: ClassDefinition | null | undefined;
  interfaces: ClassDefinition[];

  // Ignoring fields for now:
  // dataOffset: number;
  // staticValuesOffset: number;
}

export interface Method {
  classSignature: string;
  prototype: Prototype;
  name: string;
  annotations?: Annotation[];
  accessFlags?: AccessFlag[];
  parameters?: Parameter[];
}

export interface Prototype {
  shortyDescriptor: string;
  returnType: string;
  parameters: string[];
}

export interface Parameter {
  name: string;
  type: string;
  annotations: Annotation[];
}

export interface Annotation {
  typeName: string;
  elements: Record<string, string>;
  parameterIndex?: number;
}

export interface AnnotationsDirectory {
  classAnnotationsOffset: number;
  methodAnnotations: MethodAnnotation[];
  parameterAnnotations: ParameterAnnotation[];

  // Ignoring fields for now:
  // fieldsSize: number;
  // annotatedMethodsSize: number;
  // annotatedParametersSize: number;
  // fieldAnnotations: FieldAnnotation[];
}

export interface MethodAnnotation {
  methodIndex: number;
  annotationsOffset: number;
}

export interface ParameterAnnotation {
  methodIndex: number;
  annotationsOffset: number;
}

export enum EncodedValueType {
  BYTE = 0x00,
  SHORT = 0x02,
  CHAR = 0x03,
  INT = 0x04,
  LONG = 0x06,
  FLOAT = 0x10,
  DOUBLE = 0x11,
  METHOD_TYPE = 0x15,
  METHOD_HANDLE = 0x16,
  STRING = 0x17,
  TYPE = 0x18,
  FIELD = 0x19,
  METHOD = 0x1a,
  ENUM = 0x1b,
  ARRAY = 0x1c,
  ANNOTATION = 0x1d,
  NULL = 0x1e,
  BOOLEAN = 0x1f,
}

export enum AnnotationVisibility {
  BUILD = 0x00,
  RUNTIME = 0x01,
  SYSTEM = 0x02,
}

// https://source.android.com/docs/core/runtime/dex-format#endian-constant
export const ENDIAN_CONSTANT = 0x12345678;
// https://source.android.com/docs/core/runtime/dex-format#no-index
export const NO_INDEX = 0xffffffff;

// https://source.android.com/docs/core/runtime/dex-format#access-flags
export enum AccessFlag {
  PUBLIC = 0x1,
  PRIVATE = 0x2,
  PROTECTED = 0x4,
  STATIC = 0x8,
  FINAL = 0x10,
  SYNCHRONIZED = 0x20,
  VOLATILE = 0x40,
  BRIDGE = 0x40,
  TRANSIENT = 0x80,
  VARARGS = 0x80,
  NATIVE = 0x100,
  INTERFACE = 0x200,
  ABSTRACT = 0x400,
  STRICT = 0x800,
  SYNTHETIC = 0x1000,
  ANNOTATION = 0x2000,
  ENUM = 0x4000,
  // 0x8000 is unused
  CONSTRUCTOR = 0x10000,
  DECLARED_SYNCHRONIZED = 0x20000,
}
