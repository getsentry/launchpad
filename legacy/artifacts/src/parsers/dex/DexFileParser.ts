/* eslint-disable no-bitwise */

import { stringify } from '../../utils/stringify';
import { BufferWrapper } from '../BufferWrapper';
import {
  AccessFlag,
  Annotation,
  AnnotationVisibility,
  AnnotationsDirectory,
  ClassDefinition,
  DexFileHeader,
  ENDIAN_CONSTANT,
  EncodedValueType,
  Method,
  MethodAnnotation,
  NO_INDEX,
  Parameter,
  ParameterAnnotation,
  Prototype,
} from './DexFileParserTypes';

export class DexFileParser {
  header: DexFileHeader;

  bufferWrapper: BufferWrapper;

  constructor(buffer: Buffer, debug: boolean = false) {
    this.bufferWrapper = new BufferWrapper(buffer, debug);
    this.header = this.readHeader();
  }

  parseClassDefinitions(): ClassDefinition[] {
    return this.getClassDefinitions();
  }

  // https://source.android.com/docs/core/runtime/dex-format#header-item
  private readHeader(): DexFileHeader {
    this.bufferWrapper.logGroup('readHeader');

    this.bufferWrapper.cursor = 0;

    const magic: string[] = [];
    // First 8 bytes will be 'dex\n{version}\0', if not, invalid file
    for (let i = 0; i < 8; i++) {
      magic.push(String.fromCharCode(this.bufferWrapper.readU8()));
    }
    if (magic.slice(0, 3).join('') !== 'dex') {
      throw Error('Invalid dex file magic');
    }

    const version = magic.slice(4, 8).join('');
    this.bufferWrapper.logDebug(`Dex version: ${version}`);

    this.bufferWrapper.readU32(); // checksum
    this.bufferWrapper.cursor += 20; // signature
    this.bufferWrapper.readU32(); // file size
    this.bufferWrapper.readU32(); // header size
    const endianTag = this.bufferWrapper.readU32();

    if (endianTag !== ENDIAN_CONSTANT) {
      throw new Error(`Unsupported endian tag ${endianTag.toString(16)}`);
    }

    this.bufferWrapper.readU32(); // link size
    this.bufferWrapper.readU32(); // link offset
    this.bufferWrapper.readU32(); // map offset
    this.bufferWrapper.readU32(); // string ids size
    const stringIdsOff = this.bufferWrapper.readU32();
    this.bufferWrapper.readU32(); // type ids size
    const typeIdsOff = this.bufferWrapper.readU32();
    this.bufferWrapper.readU32(); // prototype ids size
    const protoIdsOff = this.bufferWrapper.readU32(); // prototype ids offset
    this.bufferWrapper.readU32(); // field ids size
    const fieldIdsOff = this.bufferWrapper.readU32(); // field ids offset
    this.bufferWrapper.readU32(); // method ids size
    const methodIdsOff = this.bufferWrapper.readU32();
    const classDefsSize = this.bufferWrapper.readU32();
    const classDefsOff = this.bufferWrapper.readU32();
    this.bufferWrapper.readU32(); // data size
    this.bufferWrapper.readU32(); // data offset

    this.bufferWrapper.logGroupEnd();
    return {
      classDefsSize,
      classDefsOff,
      stringIdsOff,
      typeIdsOff,
      fieldIdsOff,
      methodIdsOff,
      protoIdsOff,
    };
  }

  // https://source.android.com/docs/core/runtime/dex-format#class-def-item
  private getClassDefinitions(): ClassDefinition[] {
    this.bufferWrapper.logGroup('getClassDefinitions');

    const classDefs: ClassDefinition[] = [];
    const pendingSuperclasses: [number, string][] = [];
    const pendingInterfaces: [number, string[]][] = [];
    const classBySignature = new Map<string, ClassDefinition>();

    for (let i = 0; i < this.header.classDefsSize; i++) {
      this.bufferWrapper.cursor = this.header.classDefsOff + i * 32;
      const classIdx = this.bufferWrapper.readU32();
      const accessFlags = this.parseAccessFlags(this.bufferWrapper.readU32()); // access flags
      const superclassIndex = this.bufferWrapper.readU32();
      const interfacesOffset = this.bufferWrapper.readU32();

      const sourceFileIdx = this.bufferWrapper.readU32();
      const annotationsOffset = this.bufferWrapper.readU32();
      const classDataOffset = this.bufferWrapper.readU32(); // Class data offset
      this.bufferWrapper.readU32(); // static values offset
      const signature = this.getTypeName(classIdx);

      if (superclassIndex !== NO_INDEX) {
        const superclassSignature = this.getTypeName(superclassIndex);
        pendingSuperclasses.push([i, superclassSignature]);
      }

      // Not NO_INDEX on purpose.
      if (interfacesOffset !== 0) {
        pendingInterfaces.push([i, this.getTypeList(interfacesOffset)]);
      }

      let sourceFileName: string | null = null;
      if (sourceFileIdx !== NO_INDEX) {
        sourceFileName = this.getString(sourceFileIdx);
      }

      const annotationsDirectory = this.parseAnnotationsDirectory(annotationsOffset);

      this.bufferWrapper.logDebug(`Finding annotations for class: ${signature}`);
      let annotations: Annotation[] = [];
      if (annotationsDirectory) {
        annotations = this.parseAnnotationSet(annotationsDirectory.classAnnotationsOffset);
      }
      this.bufferWrapper.logDebug(`Annotations for class ${signature}: ${stringify(annotations)}`);

      this.bufferWrapper.logDebug(`Finding methods for class: ${signature}`);
      let methods: Method[] = [];
      if (classDataOffset !== 0) {
        methods = this.parseMethodDefinitions(classDataOffset, annotationsDirectory);
      }
      this.bufferWrapper.logDebug(`Methods for class ${signature}: ${stringify(methods)}`);

      const def = {
        signature,
        sourceFileName,
        annotations,
        methods,
        accessFlags,
        superclass: undefined,
        interfaces: [],
      };
      classBySignature.set(signature, def);
      classDefs.push(def);
    }

    for (const [classIdx, superclassSignature] of pendingSuperclasses) {
      classDefs[classIdx].superclass = classBySignature.get(superclassSignature);
    }
    for (const [classIdx, signatures] of pendingInterfaces) {
      const def = classDefs[classIdx];
      for (const signature of signatures) {
        const maybeInterface = classBySignature.get(signature);
        if (maybeInterface) {
          def.interfaces.push(maybeInterface);
        }
      }
    }

    this.bufferWrapper.logGroupEnd();
    return classDefs;
  }

  // https://source.android.com/docs/core/runtime/dex-format#annotations-directory
  private parseAnnotationsDirectory(annotationsDirectoryOffset: number): AnnotationsDirectory | null | undefined {
    this.bufferWrapper.logGroup('parseAnnotationsDirectory');

    if (annotationsDirectoryOffset === 0) {
      this.bufferWrapper.logGroupEnd();
      return null;
    }

    const cursor = this.bufferWrapper.cursor;

    this.bufferWrapper.cursor = annotationsDirectoryOffset;

    const classAnnotationsOffset = this.bufferWrapper.readU32();
    const fieldsSize = this.bufferWrapper.readU32(); // fieldsSize
    const annotatedMethodsSize = this.bufferWrapper.readU32();
    const annotatedParametersSize = this.bufferWrapper.readU32();

    // Skip fields for now
    this.bufferWrapper.cursor += 8 * fieldsSize; // field_annotation is 8 bytes

    const methodAnnotations: MethodAnnotation[] = [];
    for (let i = 0; i < annotatedMethodsSize; i++) {
      const methodIndex = this.bufferWrapper.readU32();
      const annotationsOffset = this.bufferWrapper.readU32();
      methodAnnotations.push({ methodIndex, annotationsOffset });
    }

    const parameterAnnotations: ParameterAnnotation[] = [];
    for (let i = 0; i < annotatedParametersSize; i++) {
      const methodIndex = this.bufferWrapper.readU32();
      const annotationsOffset = this.bufferWrapper.readU32();
      parameterAnnotations.push({ methodIndex, annotationsOffset });
    }

    this.bufferWrapper.logGroupEnd();

    this.bufferWrapper.cursor = cursor;
    return {
      classAnnotationsOffset,
      methodAnnotations,
      parameterAnnotations,
    };
  }

  // https://source.android.com/docs/core/runtime/dex-format#class-data-item
  private parseMethodDefinitions(
    classDataOffset: number,
    annotationsDirectory: AnnotationsDirectory | null | undefined,
  ): Method[] {
    this.bufferWrapper.logGroup('parseMethodDefinitions');

    const methods: Method[] = [];

    if (classDataOffset === 0) {
      this.bufferWrapper.logGroupEnd();
      return methods;
    }

    this.bufferWrapper.cursor = classDataOffset;

    const staticFieldsSize = this.bufferWrapper.readUleb128();
    const instanceFieldsSize = this.bufferWrapper.readUleb128();
    const directMethodsSize = Number(this.bufferWrapper.readUleb128());
    const virtualMethodsSize = Number(this.bufferWrapper.readUleb128());

    // Skip static fields and instance fields
    for (let i = 0; i < staticFieldsSize; i++) {
      this.bufferWrapper.readUleb128(); // field index diff
      this.bufferWrapper.readUleb128(); // access flags
    }

    for (let i = 0; i < instanceFieldsSize; i++) {
      this.bufferWrapper.readUleb128(); // field index diff
      this.bufferWrapper.readUleb128(); // access flags
    }

    const directMethods = this.parseEncodedMethods(directMethodsSize, annotationsDirectory);
    const virtualMethods = this.parseEncodedMethods(virtualMethodsSize, annotationsDirectory);

    methods.push(...directMethods, ...virtualMethods);

    this.bufferWrapper.logGroupEnd();
    return methods;
  }

  // https://source.android.com/docs/core/runtime/dex-format#set-ref-list
  private parseAnnotationSetRefList(offset: number): Annotation[] {
    this.bufferWrapper.logGroup('parseAnnotationSetRefList');

    const annotations: Annotation[] = [];

    if (offset === 0) {
      this.bufferWrapper.logGroupEnd();
      return annotations;
    }

    const cursor = this.bufferWrapper.cursor;
    this.bufferWrapper.cursor = offset;

    const size = this.bufferWrapper.readU32();
    this.bufferWrapper.logDebug(`Annotation set ref list size: ${size}`);

    for (let parameterIndex = 0; parameterIndex < size; parameterIndex++) {
      const annotationSetOffset = this.bufferWrapper.readU32();
      if (annotationSetOffset !== 0) {
        const annotationSet = this.parseAnnotationSet(annotationSetOffset).map((annotation) => ({
          ...annotation,
          parameterIndex,
        }));
        annotations.push(...annotationSet);
      }
    }

    this.bufferWrapper.cursor = cursor;

    this.bufferWrapper.logGroupEnd();
    return annotations;
  }

  // https://source.android.com/docs/core/runtime/dex-format#annotation-set-item
  // https://source.android.com/docs/core/runtime/dex-format#annotation-off-item
  // https://source.android.com/docs/core/runtime/dex-format#annotation-item
  private parseAnnotationSet(offset: number): Annotation[] {
    this.bufferWrapper.logGroup('parseAnnotationSet');

    const annotations: Annotation[] = [];

    if (offset === 0) {
      this.bufferWrapper.logGroupEnd();
      return annotations;
    }

    const cursor = this.bufferWrapper.cursor;
    this.bufferWrapper.cursor = offset;

    const size = this.bufferWrapper.readU32();
    this.bufferWrapper.logDebug(`Annotation set size: ${size}`);

    for (let i = 0; i < size; i++) {
      this.bufferWrapper.cursor = offset + 4 + i * 4; // offset + size + (index * annotation_set_item size)
      this.bufferWrapper.cursor = this.bufferWrapper.readU32(); // annotation set item offset

      const visibility = this.bufferWrapper.readU8();
      this.bufferWrapper.logDebug(`Visibility: ${visibility.toString(16)}`);

      // Only check runtime visible annotations
      if (visibility !== AnnotationVisibility.RUNTIME) {
        continue;
      }

      const typeIdx = Number(this.bufferWrapper.readUleb128());

      const elementCount = this.bufferWrapper.readUleb128();
      this.bufferWrapper.logDebug(`elementCount: ${elementCount}`);
      const elements: { [key: string]: any } = {};

      for (let j = 0; j < elementCount; j++) {
        const elementNameIndex = Number(this.bufferWrapper.readUleb128());
        const elementName = this.getString(elementNameIndex);
        const value = this.parseEncodedValue();
        elements[elementName] = value;
        this.bufferWrapper.logDebug(`Element ${elementName}: ${value}`);
      }

      const typeName = this.getTypeName(typeIdx);
      this.bufferWrapper.logDebug(`typeName: ${typeName}`);

      annotations.push({
        typeName,
        elements,
      });
    }
    this.bufferWrapper.cursor = cursor;

    this.bufferWrapper.logGroupEnd();
    return annotations;
  }

  // https://source.android.com/docs/core/runtime/dex-format#value-formats
  private parseEncodedValue(): any {
    const encodedByte = this.bufferWrapper.readU8();
    const valueType = encodedByte & 0x1f;
    const valueArg = encodedByte >>> 5;

    this.bufferWrapper.logDebug(`Value type: ${valueType.toString(16)}`);

    switch (valueType) {
      case EncodedValueType.BYTE:
        this.bufferWrapper.logDebug(`VALUE_BYTE`);
        return this.bufferWrapper.readU8();
      case EncodedValueType.SHORT:
        this.bufferWrapper.logDebug(`VALUE_SHORT`);
        return this.bufferWrapper.readSizedInt(valueArg + 1);
      case EncodedValueType.CHAR:
        this.bufferWrapper.logDebug(`VALUE_CHAR`);
        return String.fromCharCode(this.bufferWrapper.readU16());
      case EncodedValueType.INT:
        this.bufferWrapper.logDebug(`VALUE_INT`);
        return this.bufferWrapper.readSizedInt(valueArg + 1);
      case EncodedValueType.LONG:
        this.bufferWrapper.logDebug(`VALUE_LONG`);
        return this.bufferWrapper.readSizedLong(valueArg + 1);
      case EncodedValueType.FLOAT:
        this.bufferWrapper.logDebug(`FLOAT`);
        return this.bufferWrapper.readSizedFloat(valueArg + 1);
      case EncodedValueType.DOUBLE:
        this.bufferWrapper.logDebug(`DOUBLE`);
        return this.bufferWrapper.readSizedDouble(valueArg + 1);
      case EncodedValueType.METHOD_TYPE: {
        this.bufferWrapper.logDebug(`METHOD_TYPE`);
        const protoIndex = this.bufferWrapper.readSizedUInt(valueArg + 1);
        return this.getProto(protoIndex);
      }
      case EncodedValueType.METHOD_HANDLE: {
        this.bufferWrapper.logDebug(`METHOD_HANDLE`);
        const handleType = this.bufferWrapper.readU16();
        this.bufferWrapper.readU16(); // unused
        const fieldOrMethodIndex = this.bufferWrapper.readU16();
        this.bufferWrapper.readU16(); // unused
        return { fieldOrMethodIndex, handleType };
      }
      case EncodedValueType.STRING: {
        this.bufferWrapper.logDebug(`VALUE_STRING`);
        const stringIndex = this.bufferWrapper.readSizedUInt(valueArg + 1);
        return this.getString(stringIndex);
      }
      case EncodedValueType.TYPE: {
        this.bufferWrapper.logDebug(`VALUE_TYPE`);
        const typeIndex = this.bufferWrapper.readSizedUInt(valueArg + 1);
        return this.getTypeName(typeIndex);
      }
      case EncodedValueType.FIELD: {
        this.bufferWrapper.logDebug(`VALUE_FIELD`);
        const fieldIndex = this.bufferWrapper.readSizedUInt(valueArg + 1);
        return this.getField(fieldIndex);
      }
      case EncodedValueType.METHOD: {
        this.bufferWrapper.logDebug(`METHOD`);
        const methodIndex = this.bufferWrapper.readSizedUInt(valueArg + 1);
        return this.getMethod(methodIndex);
      }
      case EncodedValueType.ENUM: {
        this.bufferWrapper.logDebug(`ENUM`);
        const enumFieldIndex = this.bufferWrapper.readSizedUInt(valueArg + 1);
        return this.getField(enumFieldIndex);
      }
      case EncodedValueType.ARRAY:
        this.bufferWrapper.logDebug(`VALUE_ARRAY`);
        return this.parseEncodedArray();
      case EncodedValueType.ANNOTATION:
        this.bufferWrapper.logDebug(`VALUE_ANNOTATION`);
        return this.parseEncodedAnnotation();
      case EncodedValueType.NULL:
        this.bufferWrapper.logDebug(`VALUE_NULL`);
        return null;
      case EncodedValueType.BOOLEAN:
        this.bufferWrapper.logDebug(`VALUE_BOOLEAN`);
        return valueArg !== 0;
      default:
        throw new Error(`Unsupported encoded value type: ${valueType.toString(16)}`);
    }
  }

  // https://source.android.com/docs/core/runtime/dex-format#encoded-array
  private parseEncodedArray(): any[] {
    this.bufferWrapper.logGroup('parseEncodedArray');
    const size = this.bufferWrapper.readUleb128();
    const values: any[] = [];

    for (let i = 0; i < size; i++) {
      values.push(this.parseEncodedValue());
    }

    this.bufferWrapper.logGroupEnd();
    return values;
  }

  // https://source.android.com/docs/core/runtime/dex-format#encoded-annotation
  private parseEncodedAnnotation(): Annotation {
    this.bufferWrapper.logGroup('parseEncodedAnnotation');

    const typeIndex = Number(this.bufferWrapper.readUleb128());
    const size = this.bufferWrapper.readUleb128();
    const annotation: Annotation = {
      typeName: this.getTypeName(typeIndex),
      elements: {},
    };
    for (let i = 0; i < size; i++) {
      const nameIndex = Number(this.bufferWrapper.readUleb128());
      const name = this.getString(nameIndex);
      annotation.elements[name] = this.parseEncodedValue();
    }

    this.bufferWrapper.logGroupEnd();
    return annotation;
  }

  private parseEncodedMethods(size: number, annotationsDirectory: AnnotationsDirectory | null | undefined): Method[] {
    this.bufferWrapper.logGroup('parseEncodedMethods');

    const methods: Method[] = [];

    let methodIndex = 0;
    for (let i = 0; i < size; i++) {
      const methodIdxDiff = Number(this.bufferWrapper.readUleb128());
      methodIndex += methodIdxDiff;
      const accessFlags = this.parseAccessFlags(Number(this.bufferWrapper.readUleb128()));
      const codeOffset = Number(this.bufferWrapper.readUleb128());

      let parameterNames: string[] = [];
      if (codeOffset !== 0) {
        parameterNames = this.getParameterNames(codeOffset);
      }

      this.bufferWrapper.logDebug(`Method index diff: ${methodIdxDiff}`);
      this.bufferWrapper.logDebug(`Method index: ${methodIndex}`);

      const method = this.getMethod(methodIndex);
      this.bufferWrapper.logDebug(`Method signature: ${stringify(method)}`);

      let annotations: Annotation[] = [];
      if (annotationsDirectory) {
        annotations = annotationsDirectory.methodAnnotations
          // eslint-disable-next-line @typescript-eslint/no-loop-func
          .filter((methodAnnotation) => methodAnnotation.methodIndex === methodIndex)
          .flatMap((methodAnnotation) => this.parseAnnotationSet(methodAnnotation.annotationsOffset));
      }
      this.bufferWrapper.logDebug(`annotations: ${stringify(annotations)}`);

      const parameters = this.getMethodParameters(
        method.prototype.parameters,
        parameterNames,
        annotationsDirectory,
        methodIndex,
      );

      methods.push({
        ...method,
        annotations,
        accessFlags,
        parameters,
      });
    }

    this.bufferWrapper.logGroupEnd();
    return methods;
  }

  private getMethodParameters(
    parameterTypes: string[],
    parameterNames: string[],
    annotationsDirectory: AnnotationsDirectory | null | undefined,
    methodIndex: number,
  ): Parameter[] {
    let parameterAnnotations: Annotation[] = [];
    if (annotationsDirectory) {
      const methodParameterAnnotations = annotationsDirectory.parameterAnnotations.find(
        (parameterAnnotation) => parameterAnnotation.methodIndex === methodIndex,
      );

      if (methodParameterAnnotations) {
        parameterAnnotations = this.parseAnnotationSetRefList(methodParameterAnnotations.annotationsOffset);
      }
    }

    let annotationIndex = 0;
    return parameterTypes.map((type, index) => {
      const paramAnnotations: Annotation[] = [];
      while (
        annotationIndex < parameterAnnotations.length &&
        parameterAnnotations[annotationIndex].parameterIndex === index
      ) {
        paramAnnotations.push(parameterAnnotations[annotationIndex]);
        annotationIndex++;
      }
      return {
        type,
        name: parameterNames[index],
        annotations: paramAnnotations,
      };
    });
  }

  private getParameterNames(codeOffset: number): string[] {
    this.bufferWrapper.logGroup('getParameterNames');
    const cursor = this.bufferWrapper.cursor;

    // Seen some cases where debug_info_item params are beyond bounds of string table in some cases,
    // so for now just fallback for safest handling
    try {
      this.bufferWrapper.cursor = codeOffset;

      this.bufferWrapper.readU16(); // registers_size
      this.bufferWrapper.readU16(); // ins_size
      this.bufferWrapper.readU16(); // outs_size
      this.bufferWrapper.readU16(); // tries_size
      const debugItemOff = this.bufferWrapper.readU32();
      // Skipping insns_size for now
      // Skipping insns for now
      // Skipping padding for now
      // Skipping tries for now
      // Skipping handlers for now

      // Parse debug_info_item
      this.bufferWrapper.cursor = debugItemOff;
      this.bufferWrapper.readUleb128(); // line_start
      const parametersSize = this.bufferWrapper.readUleb128();
      const parameterNames: string[] = [];

      this.bufferWrapper.logDebug(`Parameters size: ${parametersSize}`);

      // Skip for cases where params are beyond bounds of what we're looking for (composables & preview params)
      if (parametersSize <= 3) {
        for (let i = 0; i < parametersSize; i++) {
          const nameIdx = Number(this.bufferWrapper.readUleb128()) - 1;
          if (nameIdx !== NO_INDEX) {
            parameterNames.push(this.getString(nameIdx));
          } else {
            parameterNames.push('');
          }
        }
      }

      this.bufferWrapper.cursor = cursor;

      this.bufferWrapper.logGroupEnd();
      return parameterNames;
    } catch (error) {
      this.bufferWrapper.cursor = cursor;

      this.bufferWrapper.logGroupEnd();
      return [];
    }
  }

  // https://source.android.com/docs/core/runtime/dex-format#proto-id-item
  private getProto(protoIndex: number): Prototype {
    this.bufferWrapper.logGroup('getProto');
    const cursor = this.bufferWrapper.cursor;

    this.bufferWrapper.cursor = this.header.protoIdsOff + protoIndex * 12; // Each proto_id_item is 12 bytes

    const shortyIdx = this.bufferWrapper.readU32();
    const returnTypeIdx = this.bufferWrapper.readU32();
    const parametersOff = this.bufferWrapper.readU32();

    const shortyDescriptor = this.getString(shortyIdx);
    const returnType = this.getTypeName(returnTypeIdx);
    let parameters: string[] = [];
    if (parametersOff !== 0) {
      parameters = this.getTypeList(parametersOff);
    }

    this.bufferWrapper.logGroupEnd();

    this.bufferWrapper.cursor = cursor;
    return {
      shortyDescriptor,
      returnType,
      parameters,
    };
  }

  // https://source.android.com/docs/core/runtime/dex-format#type-list
  private getTypeList(typeListOffset: number): string[] {
    this.bufferWrapper.logGroup('getTypeList');
    const cursor = this.bufferWrapper.cursor;

    this.bufferWrapper.cursor = typeListOffset;

    const size = this.bufferWrapper.readU32();
    const types: string[] = [];
    for (let i = 0; i < size; i++) {
      const typeIndex = this.bufferWrapper.readU16();
      types.push(this.getTypeName(typeIndex));
    }

    this.bufferWrapper.cursor = cursor;

    this.bufferWrapper.logGroupEnd();
    return types;
  }

  // https://source.android.com/docs/core/runtime/dex-format#field-id-item
  private getField(fieldIndex: number): string {
    this.bufferWrapper.logGroup('getField');
    const cursor = this.bufferWrapper.cursor;

    this.bufferWrapper.cursor = this.header.fieldIdsOff + fieldIndex * 8; // Each field_id_item is 8 bytes

    const classIndex = this.bufferWrapper.readU16();
    const typeIndex = this.bufferWrapper.readU16();
    const nameIndex = this.bufferWrapper.readU32();

    const className = this.getTypeName(classIndex);
    const typeName = this.getTypeName(typeIndex);
    const name = this.getString(nameIndex);

    this.bufferWrapper.logDebug(`Class: ${className}`);
    this.bufferWrapper.logDebug(`Type: ${typeName}`);
    this.bufferWrapper.logDebug(`Name: ${name}`);

    this.bufferWrapper.cursor = cursor;

    this.bufferWrapper.logGroupEnd();
    return `${className}->${name}:${typeName}`;
  }

  // https://source.android.com/docs/core/runtime/dex-format#method-id-item
  private getMethod(methodIndex: number): Method {
    this.bufferWrapper.logGroup('getMethod');
    const cursor = this.bufferWrapper.cursor;

    this.bufferWrapper.cursor = this.header.methodIdsOff + methodIndex * 8; // Each method_id_item is 8 bytes

    const classIndex = this.bufferWrapper.readU16();
    const protoIndex = this.bufferWrapper.readU16();
    const nameIndex = this.bufferWrapper.readU32();

    const classSignature = this.getTypeName(classIndex);
    const prototype = this.getProto(protoIndex);
    const name = this.getString(nameIndex);

    this.bufferWrapper.cursor = cursor;

    this.bufferWrapper.logGroupEnd();
    return {
      classSignature,
      prototype,
      name,
    };
  }

  // https://source.android.com/docs/core/runtime/dex-format#type-id-item
  private getTypeName(index: number): string {
    this.bufferWrapper.logGroup('getTypeName');
    const cursor = this.bufferWrapper.cursor;

    this.bufferWrapper.cursor = this.header.typeIdsOff + index * 4; // Each type_id_item is 4 bytes

    const stringIndex = this.bufferWrapper.readU32();
    const string = this.getString(stringIndex);
    this.bufferWrapper.cursor = cursor;

    this.bufferWrapper.logGroupEnd();
    return string;
  }

  // https://source.android.com/docs/core/runtime/dex-format#string-item
  // https://source.android.com/docs/core/runtime/dex-format#string-data-item
  private getString(index: number): string {
    this.bufferWrapper.logGroup('getString');
    const cursor = this.bufferWrapper.cursor;

    this.bufferWrapper.cursor = this.header.stringIdsOff + index * 4; // Each string_id_item is 4 bytes
    this.bufferWrapper.cursor = this.bufferWrapper.readU32(); // string data offset

    const stringLength = Number(this.bufferWrapper.readUleb128());

    const string = this.bufferWrapper.readStringWithLength(stringLength);
    this.bufferWrapper.cursor = cursor;

    this.bufferWrapper.logDebug(`String: ${string}`);

    this.bufferWrapper.logGroupEnd();
    return string;
  }

  // https://source.android.com/docs/core/runtime/dex-format#access-flags
  private parseAccessFlags(accessFlags: number): AccessFlag[] {
    const flags: AccessFlag[] = [];

    Object.entries(AccessFlag).forEach(([_, value]) => {
      if (typeof value === 'number' && accessFlags & value) {
        flags.push(value);
      }
    });

    // Implement others in future as needed
    return flags;
  }
}
