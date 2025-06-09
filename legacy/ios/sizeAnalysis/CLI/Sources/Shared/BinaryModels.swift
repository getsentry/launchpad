//
//  File.swift
//
//
//  Created by Noah Martin on 12/3/20.
//

import Foundation
import ObjectiveC

public struct DisasembleResult {
  public init(
    size: Int?,
    nonSubroutineBranch: [Int],
    subroutineBranch: [Int],
    relativeAddresses: [Int]
  ) {
    self.size = size
    self.nonSubroutineBranch = nonSubroutineBranch
    self.subroutineBranch = subroutineBranch
    self.relativeAddresses = relativeAddresses
  }

  let size: Int?
  let nonSubroutineBranch: [Int]
  let subroutineBranch: [Int]
  let relativeAddresses: [Int]
}

public struct LoadCommand {
  let name: String
  let fileStart: UInt64
  let fileSize: UInt64
  let vmStart: UInt64
  let vmSize: UInt64
  var sections: [BinarySection]

  func contains(fileOffset: UInt) -> Bool {
    fileOffset >= fileStart && fileOffset < fileStart + fileSize
  }
}

public struct BinarySection {
  let name: String
  let size: UInt64
  let vmStart: UInt64
  let fileStart: UInt64

  func contains(fileOffset: UInt) -> Bool {
    fileOffset >= fileStart && fileOffset < fileStart + size
  }

  func contains(vmOffset: UInt) -> Bool {
    vmOffset >= vmStart && vmOffset < vmStart + size
  }
}

public struct ObjCClass {
  let isa: UInt64  //ObjCClass
  let superclass: UInt64  //ObjcClass
  let cache: UInt64
  let mask: UInt32
  let occupied: UInt32
  let taggedData: UInt64

  var dataPtr: UInt64 {
    let fastDataMask: UInt64 = 0x0000_7fff_ffff_fff8
    return taggedData & fastDataMask
  }

  var isSwift: Bool {
    let fastIsSwiftStable: UInt64 = 1 << 1
    let fastIsSwiftLegacy: UInt64 = 1 << 0
    return (taggedData & fastIsSwiftStable) != 0 || (taggedData & fastIsSwiftLegacy) != 0
  }
}

public struct RuntimeList<T> {
  let entsizeAndFlags: UInt32
  let count: UInt32
  let first: T
}

public struct RuntimeMethod {
  let selector: Selector
  let methodTypes: UInt64
  let imp: UInt64
}

public struct ClassRoT {
  let flags: UInt32
  let instanceStart: UInt32
  let instanceSize: UInt32
  let reserved: UInt32

  let ivarLayout: UInt64
  let name: UInt64
  let baseMethodList: UInt64
  let baseProtocols: UInt64
  let ivars: UInt64
  let weakIvarLayout: UInt64
  let baseProperties: UInt64
}

struct ObjcIVar: RawMemoryLoadable {

  static var initialValue: ObjcIVar {
    .init(offset: 0, name: 0, type: 0, alignment: 0, size: 0)
  }

  let offset: UInt64
  let name: UInt64
  let type: UInt64
  let alignment: UInt32
  let size: UInt32
}

struct ObjcCategory {
  let name: UInt64
  let cls: UInt64
  let instanceMethods: UInt64
  let classMethods: UInt64
  let protocols: UInt64
  let instanceProperties: UInt64
}

struct BaseProperty: RawMemoryLoadable {

  static var initialValue: BaseProperty {
    .init(name: 0, attributes: 0)
  }

  let name: UInt64
  let attributes: UInt64
}

protocol RawMemoryLoadable {
  static var initialValue: Self { get }
}

extension UInt64: RawMemoryLoadable {
  static var initialValue: UInt64 {
    return 0
  }
}

struct ObjcMethod {
  let name: UInt64
  let types: UInt64
  let impl: UInt64
}

struct ObjcRelativeMethod {
  let name: Int32
  let types: Int32
  let impl: Int32
}

struct ObjcProtocol: RawMemoryLoadable {

  static var initialValue: ObjcProtocol {
    .init(
      isa: 0,
      mangledName: 0,
      protocols: 0,
      instanceMethods: 0,
      classMethods: 0,
      optionalInstanceMethods: 0,
      optionalClassMethods: 0,
      instanceProperties: 0,
      size: 0,
      flags: 0,
      extendedMethodTypes: 0,
      demangledName: 0,
      classProperties: 0
    )
  }

  let isa: UInt64
  let mangledName: UInt64
  let protocols: UInt64
  let instanceMethods: UInt64
  let classMethods: UInt64
  let optionalInstanceMethods: UInt64
  let optionalClassMethods: UInt64
  let instanceProperties: UInt64
  let size: UInt32
  let flags: UInt32
  let extendedMethodTypes: UInt64
  let demangledName: UInt64
  let classProperties: UInt64
}

struct CFStringData {
  let vmStart: UInt
  let reference: UInt8
  let cString: CString
  let length: UInt8
}

struct CString {
  let string: String
  let vmStart: UInt64
  let size: UInt64
}

extension URL {
  public var isMachOBinary: Bool {
    guard !isSymLink else { return false }

    guard let handle = FileHandle(forReadingAtPath: path) else { return false }
    let fatHeader = handle.readData(ofLength: MemoryLayout<fat_header>.size) as NSData
    if fatHeader.length < MemoryLayout<fat_header>.size {
      return false
    }
    let bytes = fatHeader.bytes
    let headerType = bytes.load(as: fat_header.self)
    defer {
      bytes.deallocate()
    }
    if headerType.magic == FAT_MAGIC || headerType.magic == FAT_CIGAM {
      return true
    }

    try? handle.seek(toOffset: 0)
    let archHeader = handle.readData(ofLength: MemoryLayout<mach_header_64>.size) as NSData
    if archHeader.length < MemoryLayout<mach_header_64>.size {
      return false
    }
    let archBytes = archHeader.bytes
    defer {
      archBytes.deallocate()
    }
    let archHeaderType = archBytes.load(as: mach_header_64.self)
    return archHeaderType.magic == MH_MAGIC_64 || archHeaderType.magic == MH_CIGAM_64
      || archHeaderType.magic == MH_MAGIC || archHeaderType.magic == MH_CIGAM
  }

  public var isExecutable: Bool {
    guard let handle = FileHandle(forReadingAtPath: path) else { return false }

    try? handle.seek(toOffset: 0)
    let archHeader = handle.readData(ofLength: MemoryLayout<mach_header_64>.size) as NSData
    if archHeader.length < MemoryLayout<mach_header_64>.size {
      return false
    }
    let archBytes = archHeader.bytes
    defer {
      archBytes.deallocate()
    }
    let archHeaderType = archBytes.load(as: mach_header_64.self)

    return archHeaderType.filetype == MH_EXECUTE
  }

  // Returns the additional size added to the binary by signing with app store code signature format (sha1 + sha256 hashes)
  public func extraCodeSignatureSize() -> UInt {
    let process = Process()
    process.launchPath = "/usr/bin/xcrun"
    process.arguments = ["codesign", "-dvvv", path]
    let pipe = Pipe()
    process.standardError = pipe
    try! process.run()
    process.waitUntilExit()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    guard let output = String(data: data, encoding: .utf8) else { return 0 }

    let lines = output.components(separatedBy: "\n")
    if lines.contains(where: { $0.contains("object is not signed at all") }) {
      // If the binary isn't codesigned, estimate the number of hashes
      let fileSize = (try? resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
      let numberOfHashes = fileSize / (1024 * 4)
      return UInt(numberOfHashes * 104)
    }

    let codeDirectoryLine = lines.first { $0.starts(with: "CodeDirectory") }
    guard let hashChoicesLine = lines.first(where: { $0.starts(with: "Hash choices") }) else {
      return 0
    }
    // This could happen if the upload is taken directly from the app store, in that
    // case we don't want to add any extra size.
    guard hashChoicesLine.split(separator: "=")[1] == "sha256" else {
      // logger.warning("Not only sha256 signatures")
      return 0
    }

    let hashesString = codeDirectoryLine?.split(separator: " ").first {
      $0.starts(with: "hashes=")
    }?.split(separator: "=")[1].split(separator: "+").first
    // We haven't encountered a binary with codesign output that doesn't match this format yet
    // if we do don't add any extra code signature size and just report the size
    // of the upload.
    guard let hashesString = hashesString, let hashes = UInt(hashesString) else {
      logger.warning("Invalid codesign output")
      return 0
    }

    // 72 bytes for the size minus the existing sha256 hashes
    return hashes * 72
  }

  public var isSymLink: Bool {
    let vals = try? resourceValues(forKeys: [.isSymbolicLinkKey])
    if let isLink = vals?.isSymbolicLink,
      isLink
    {
      return isLink
    }
    return false
  }

  public var symlinkPath: String {
    return resolvingSymlinksInPath().absoluteString
  }
}

struct Name {
  init(
    tuple: (
      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8
    )
  ) {
    var tmp = tuple
    array = withUnsafeBytes(of: &tmp) { pointer in
      var result = [UInt8](pointer)
      result.append(0)
      return result
    }
  }

  init(
    tuple: (
      UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
      UInt8, UInt8, UInt8
    )
  ) {
    var tmp = tuple
    array = withUnsafeBytes(of: &tmp) { pointer in
      var result = [UInt8](pointer)
      result.append(0)
      return result
    }
  }

  var string: String {
    String(cString: array)
  }

  private let array: [UInt8]
}

func safelyLoad<T>(_ initial: inout T, startPtr: UnsafeRawPointer) {
  withUnsafeMutableBytes(of: &initial) { ptr in
    let buffer = UnsafeRawBufferPointer(start: startPtr, count: MemoryLayout<T>.size)
    ptr.copyMemory(from: UnsafeRawBufferPointer(.init(buffer)))
  }
}

// header of the LC_DYLD_CHAINED_FIXUPS payload
struct dyld_chained_fixups_header {
  let fixups_version: UInt32  // 0
  let starts_offset: UInt32  // offset of dyld_chained_starts_in_image in chain_data
  let imports_offset: UInt32  // offset of imports table in chain_data
  let symbols_offset: UInt32  // offset of symbol strings in chain_data
  let imports_count: UInt32  // number of imported symbol names
  let imports_format: UInt32  // DYLD_CHAINED_IMPORT*
  let symbols_format: UInt32  // 0 => uncompressed, 1 => zlib compressed
}
