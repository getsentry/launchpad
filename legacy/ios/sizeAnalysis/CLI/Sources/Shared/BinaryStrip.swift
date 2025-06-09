//
//  BinaryStrip.swift
//  AppSizeAnalyzer
//
//  Created by Noah Martin on 11/20/20.
//  Copyright © 2020 Tom Doron. All rights reserved.
//

import Foundation

final class BinaryStrip {

  // We validate that the URL is a binary
  static func thin(url: URL) throws {
    let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
    guard size > MemoryLayout<Shared.fat_header>.size else { return }

    guard let handle = FileHandle(forReadingAtPath: url.path) else { return }
    let fatHeader = handle.readData(ofLength: MemoryLayout<Shared.fat_header>.size) as NSData
    let header = fatHeader.bytes.assumingMemoryBound(to: Shared.fat_header.self)
    guard header.pointee.magic == FAT_MAGIC || header.pointee.magic == FAT_CIGAM else { return }

    var archName = "arm64"
    let archs = header.pointee.archs(from: handle)
    if url.appRelativePath.starts(with: "/Watch/") || archs.contains(CPU_TYPE_ARM64_32) {
      archName = "arm64_32"
    } else if !archs.contains(CPU_TYPE_ARM64) {
      archName = "x86_64"
    }

    var name = url.lastPathComponent
    name.append("Temp")
    let tempFile = url.deletingLastPathComponent().appendingPathComponent(name)
    try FileManager.default.copyItem(at: url, to: tempFile)
    let process = Process()
    process.launchPath = "/usr/bin/xcrun"
    process.arguments = ["lipo", "-thin", archName, url.path, "-output", tempFile.path]
    try process.run()
    process.waitUntilExit()
    try FileManager.default.removeItem(at: url)
    try FileManager.default.moveItem(at: tempFile, to: url)
  }

  static func stripBitcode(url: URL) throws {
    var name = url.lastPathComponent
    name.append("Temp")
    let tempFile = url.deletingLastPathComponent().appendingPathComponent(name)
    let process = Process()
    process.launchPath = "/usr/bin/xcrun"
    process.arguments = ["bitcode_strip", "-r", url.path, "-o", tempFile.path]
    try process.run()
    process.waitUntilExit()
    try FileManager.default.removeItem(at: url)
    try FileManager.default.moveItem(at: tempFile, to: url)
  }

  // URL must be a binary
  static func strip(url: URL, hasBitcode: Bool) throws -> UInt64? {
    try stripBitcode(url: url)

    var name = url.lastPathComponent
    name.append("Stripped")
    let tempFile = url.deletingLastPathComponent().appendingPathComponent(name)
    let process = Process()
    process.launchPath = "/usr/bin/xcrun"
    var arguments: [String]
    if let type = url.fileType, type == MH_DYLIB {
      arguments = ["strip", "-rSTx", url.path, "-no_code_signature_warning"]
    } else {
      arguments = ["strip", "-STx", url.path, "-no_code_signature_warning"]
    }
    if !hasBitcode {
      arguments.append(contentsOf: ["-o", tempFile.path])
    }
    process.arguments = arguments
    try process.run()
    process.waitUntilExit()
    if hasBitcode {
      return nil
    }
    defer {
      try? FileManager.default.removeItem(at: tempFile)
    }
    let newAttributes = try FileManager.default.attributesOfItem(atPath: tempFile.path)
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    guard let newSize = newAttributes[.size] as? UInt64, let size = attributes[.size] as? UInt64
    else {
      return nil
    }

    if newSize > size {
      return 0
    }

    return size - newSize
  }
}

extension URL {
  var fileType: UInt32? {
    guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
    let header = handle.readData(ofLength: MemoryLayout<MachO.mach_header_64>.size) as NSData
    if header.length < MemoryLayout<MachO.mach_header_64>.size {
      return nil
    }

    let machHeader = header.bytes.assumingMemoryBound(to: MachO.mach_header_64.self)
    return machHeader.pointee.filetype
  }

  var cpuType: Int32? {
    guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
    let header = handle.readData(ofLength: MemoryLayout<MachO.mach_header_64>.size) as NSData
    if header.length < MemoryLayout<MachO.mach_header_64>.size {
      return nil
    }

    let machHeader = header.bytes.assumingMemoryBound(to: MachO.mach_header_64.self)
    return machHeader.pointee.cputype
  }
}
