//
//  File.swift
//
//
//  Created by Noah Martin on 1/29/21.
//

import Foundation

// MARK: - Metadata Values

// https://github.com/apple/swift/blob/f13167d9d162e69d1aac6ce022b19f6a80c62aba/include/swift/ABI/MetadataValues.h#L1203-L1234
enum ContextDescriptorKind: UInt8 {
  case Module = 0
  case Extension = 1
  case Anonymous = 2
  case `Protocol` = 3
  case OpaqueType = 4
  case Class = 16
  case Struct = 17
  case Enum = 18
}

// https://github.com/apple/swift/blob/f13167d9d162e69d1aac6ce022b19f6a80c62aba/include/swift/ABI/MetadataValues.h#L1237-L1312
struct ContextDescriptorFlags {
  init(rawFlags: UInt32) {
    self.rawFlags = rawFlags
  }

  var kind: ContextDescriptorKind? {
    let value = UInt8(rawFlags & 0x1F)
    return ContextDescriptorKind(rawValue: value)
  }

  var isGeneric: Bool {
    rawFlags & 0x80 != 0
  }

  var isUnique: Bool {
    rawFlags & 0x40 != 0
  }

  var kindSpecificFlags: UInt16 {
    UInt16(rawFlags >> 16 & 0xFFFF)
  }

  private let rawFlags: UInt32
}

// https://github.com/apple/swift/blob/main/include/swift/ABI/MetadataValues.h#L372-L398
enum TypeReferenceKind: UInt32 {
  case DirectTypeDescriptor = 0
  case IndirectTypeDescriptor = 1
  case DirectObjCClassName = 2
  case IndirectObjCClass = 3
}

// https://github.com/apple/swift/blob/main/include/swift/ABI/MetadataValues.h#L582-L687
struct ConformanceFlags {
  init(rawFlags: UInt32) {
    self.rawFlags = rawFlags
  }

  var kind: TypeReferenceKind? {
    let rawKind = (rawFlags & Self.TypeMetadataKindMask) >> Self.TypeMetadataKindShift
    return TypeReferenceKind(rawValue: rawKind)
  }

  var numConditionalRequirements: UInt32 {
    (rawFlags & Self.NumConditionalRequirementsMask) >> Self.NumConditionalRequirementsShift
  }

  var isRetroactive: Bool {
    (rawFlags & Self.IsRetroactiveMask) != 0
  }

  var hasResilientWitnesses: Bool {
    (rawFlags & Self.HasResilientWitnessesMask) != 0
  }

  var hasGenericWitnessTable: Bool {
    (rawFlags & Self.HasGenericWitnessTableMask) != 0
  }

  private static let TypeMetadataKindMask: UInt32 = 0x7 << Self.TypeMetadataKindShift
  private static let TypeMetadataKindShift = 3
  private static let IsRetroactiveMask: UInt32 = 0x01 << 6
  private static let NumConditionalRequirementsMask: UInt32 =
    0xFF << Self.NumConditionalRequirementsShift
  private static let NumConditionalRequirementsShift = 8
  private static let HasResilientWitnessesMask: UInt32 = 0x01 << 16
  private static let HasGenericWitnessTableMask: UInt32 = 0x01 << 17

  private let rawFlags: UInt32
}

// https://github.com/apple/swift/blob/main/include/swift/ABI/MetadataValues.h#L1562-L1574
enum GenericRequirementKind: UInt8 {
  case `Protocol` = 0
  case SameType = 1
  case BaseClass = 2
  case SameConformance = 3
  case Layout = 0x1F
}

// https://github.com/apple/swift/blob/main/include/swift/ABI/MetadataValues.h#L1576-L1624
struct GenericRequirementFlags {

  init(rawFlags: UInt32) {
    self.rawFlags = rawFlags
  }

  var kind: GenericRequirementKind? {
    let kind = UInt8(rawFlags & 0x1F)
    return GenericRequirementKind(rawValue: kind)
  }

  private let rawFlags: UInt32
}

struct ProtocolRequirementFlags {
  private let rawFlags: UInt32
}

struct MethodDescriptorFlags {
  enum Kind: UInt32 {
    case Method
    case Init
    case Getter
    case Setter
    case ModifyCoroutine
    case ReadCoroutine
  }

  var kind: Kind? {
    Kind(rawValue: rawFlags & 0x0F)
  }

  var isInstnace: Bool {
    (rawFlags & 0x10) == 1
  }

  private let rawFlags: UInt32
}

struct TypeContextDescriptorFlags {
  enum Flags: UInt16 {
    case Class_HasVTable = 15
  }

  var hasVTable: Bool {
    (rawFlags & 0x8000) != 0
  }

  var hasResilientSuperclass: Bool {
    (rawFlags & 0x1000) != 0
  }

  var hasForeignMetadataInitialization: Bool {
    (rawFlags & 0x3) == 2
  }

  var hasSingletonMetadataInitialization: Bool {
    (rawFlags & 0x3) == 1
  }

  var hasVTableOnly: Bool {
    rawFlags == 0x8000
  }

  var hasOverrideTable: Bool {
    (rawFlags & 0x2000) != 0
  }

  var hasCanonicalMetadataPrespecializations: Bool {
    (rawFlags & 0x4) != 0
  }

  let rawFlags: UInt16
}

struct GenericParamDescriptor {
  let value: UInt8
}

struct TargetSingletonMetadataInitialization {
  let initializationCache: Int32
  let incompleteMetadataOrResilientPattern: Int32
  let completionFunction: Int32
}

struct AnonymousContextDescriptorFlags {
  var hasMangledName: Bool {
    (rawFalgs & 0x1) != 0
  }

  let rawFalgs: UInt16
}

// MARK: - Metadata

// https://github.com/apple/swift/blob/main/include/swift/ABI/Metadata.h#L2472-L2643
struct ProtocolConformanceDescriptor {
  let protocolDescriptor: Int32
  var nominalTypeDescriptor: Int32
  let protocolWitnessTable: Int32
  let conformanceFlags: UInt32
}

// https://github.com/apple/swift/blob/main/include/swift/ABI/Metadata.h#L3139-L3222
struct ProtocolDescriptor {
  let flags: UInt32
  let parent: Int32
  let name: Int32
  let numRequirementsInSignature: UInt32
  let numRequirements: UInt32
  let associatedTypeNames: Int32
}

// https://github.com/apple/swift/blob/main/include/swift/ABI/Metadata.h#L2760-L2846
struct TargetGenericRequirementDescriptor {
  let flags: UInt32
  // The mangled name of the type that's constrained
  let param: RelativePointer

  /// Only valid if the requirement has SameType or BaseClass kind.
  let type: RelativePointer
}

struct TargetProtocolRequirement {
  let flags: ProtocolRequirementFlags
  let defaultImplementation: RelativePointer
}

struct TargetClassDescriptor {
  let flags: ContextDescriptorFlags
  let parent: Int32
  let name: Int32
  let accessFunction: Int32
  let fieldDescriptor: Int32
  let superclassType: Int32
  let metadataNegativeSizeInWords: UInt32
  let metadataPositiveSizeInWords: UInt32
  let numImmediateMembers: UInt32
  let numFields: UInt32
  let fieldOffsetVectorOffset: UInt32

  var typeFlags: TypeContextDescriptorFlags {
    TypeContextDescriptorFlags(rawFlags: flags.kindSpecificFlags)
  }

  var hasObjCResilientClassStub: Bool {
    if !typeFlags.hasResilientSuperclass {
      return false
    }
    preconditionFailure("Unimplemented")
  }
}

struct TargetVTableDescriptorHeader {
  let VTableOffset: UInt32
  let VTableSize: UInt32
}

struct TargetMethodDescriptor {
  let flags: MethodDescriptorFlags
  let impl: RelativePointer
}

struct StructDescriptor {
  let flags: ContextDescriptorFlags
  let parent: Int32
  let name: Int32
  let accessFunction: Int32
  let fieldDescriptor: Int32
  let numFields: UInt32
  let fieldOffsetVectorOffset: UInt32
}

struct EnumDescriptor {
  let flags: ContextDescriptorFlags
  let parent: Int32
  let name: Int32
  let accessFunction: Int32
  let fieldDescriptor: Int32
  let numPayloadCasesAndPayloadSizeOffset: UInt32
  let numEmptyCases: UInt32
}

struct TargetTypeGenericContextDescriptorHeader {
  var instantiationCache: Int32
  var defaultInstantiationPattern: Int32
  var base: TargetGenericContextDescriptorHeader
}

struct TargetGenericContextDescriptorHeader {
  var numberOfParams: UInt16
  var numberOfRequirements: UInt16
  var numberOfKeyArguments: UInt16
  var numberOfExtraArguments: UInt16
}

struct TargetModuleContextDescriptor {
  let flags: UInt32
  let parent: Int32
  let name: Int32
}

struct FieldDescriptor {
  let mangledTypeName: Int32
  let superclass: Int32
  let kind: UInt16
  let fieldRecordSize: UInt16
  let numFields: UInt32
}

struct FieldRecord {
  let flags: UInt32
  let mangledTypeName: Int32
  let fieldName: Int32
}

struct TargetResilientWitness {
  let targetRelativeProtocolRequirementPointer: Int32
  let witness: Int32
}

struct TargetGenericWitnessTable {
  let witnessTableSizeInWords: UInt16
  let witnessTablePrivateSizeInWordsAndRequiresInstantiation: UInt16
  let instantiator: Int32
  let privateData: Int32
}

struct TargetExtensionContextDescriptor {
  let flags: ContextDescriptorFlags
  let parent: Int32
  let extendedContext: Int32
}

struct TargetAnonymousContextDescriptor {
  let flags: ContextDescriptorFlags
  let parent: Int32
}

// MARK: - RelativePointer

// https://github.com/apple/swift/blob/a73a8087968f9111149073107c5242d83635107a/include/swift/Basic/RelativePointer.h

typealias RelativePointer = Int32

extension RelativePointer {

  // All addresses in file offsets
  func offset(from start: UInt, canBeIndirect: Bool = true) -> UInt? {
    if canBeIndirect && self % 2 == 1 {
      let offset = self & ~1
      // TODO: Use the result of this offset to mark the UInt64 in the binary which is the vm address of the pointee
      let result = UInt(Int64(start) + Int64(offset))
      //logger.debug("TODO: mark the indirect pointer as used \(result)")
      // The result would be outsite this binary
      return result
    } else {
      let result = Int64(start) + Int64(self)
      if result > 0 {
        return UInt(result)
      } else {
        return nil
      }
    }
  }
}
