//
//  Analyzer.swift
//  AnalyzeCore
//
//  Created by Noah Martin on 11/24/20.
//  Copyright © 2020 Tom Doron. All rights reserved.
//

import Capstone
import Foundation
import Logging
import Zip

public final class Analyzer {
  public init(
    workingDirURL: URL,
    zipURL: URL,
    destinationURL: URL,
    s3BucketName: String,
    fileKey: String,
    previewsBucketName: String,
    previewsEnabled: Bool,
    uploadAllOptimizedImages: Bool,
    uploadAllOptimizedVideos: Bool,
    uploadAllPreviews: Bool,
    skipSwiftMetadataParsing: Bool,
    skipInstructionDisassembly: Bool,
    skipExtraAssetCatalogImageProcessing: Bool
  ) {
    self.workingDirURL = workingDirURL
    self.zipURL = zipURL
    self.destinationURL = destinationURL
    self.s3BucketName = s3BucketName
    self.fileKey = fileKey
    self.previewsBucketName = previewsBucketName
    self.previewsEnabled = previewsEnabled
    self.uploadAllOptimizedImages = uploadAllOptimizedImages
    self.uploadAllOptimizedVideos = uploadAllOptimizedVideos
    self.uploadAllPreviews = uploadAllPreviews
    self.skipSwiftMetadataParsing = skipSwiftMetadataParsing
    self.skipInstructionDisassembly = skipInstructionDisassembly
    self.skipExtraAssetCatalogImageProcessing = skipExtraAssetCatalogImageProcessing
  }

  private var architecture = Architecture.arm64
  private lazy var capstone = {
    try! Capstone(arch: self.architecture)
  }()

  public func run() throws -> Results {
    do {
      try Zip.unzipFile(
        zipURL,
        destination: destinationURL,
        overwrite: false,
        password: nil,
        permissions: 0o755
      )
    } catch {
      logger.error("Unzip error \(error)")
      throw error
    }

    let (itemURL, dsym) = try findAppURL()
    guard let enumerator = FileManager.default.enumerator(atPath: itemURL.path) else {
      throw Error.noFilesFound
    }

    for file in enumerator.allObjects {
      let fileString = file as! String
      let fileURL = itemURL.appendingPathComponent(fileString)

      if fileURL.isSwiftStandardDylib || fileURL.isIgnoredMobileProvision || fileURL.isXCTest
        || fileURL.isTestFramework || fileURL.isXCTestDylib
      {
        try? FileManager.default.removeItem(at: fileURL)
      } else if fileURL.path.hasSuffix(".car") {
        AssetUtil.process(file: fileURL)
        //AssetUtil.disect(file: fileURL)
      } else if fileURL.isMachOBinary {
        try? BinaryStrip.thin(url: fileURL)
        if let cpuType = fileURL.cpuType, cpuType == CPU_TYPE_X86_64 {
          // For simulator builds always strip symbols
          _ = try? BinaryStrip.strip(url: fileURL, hasBitcode: true)
          architecture = .x86
        }
      }
    }
    let compression = Compression(workingDirURL: workingDirURL)
    let results = try BundleAnalyzer(
      logger: logger,
      url: itemURL,
      dsym: dsym,
      s3BucketName: s3BucketName,
      s3Key: fileKey,
      previewsBucketName: previewsBucketName,
      previewsEnabled: previewsEnabled,
      imageOptimizing: compression,
      uploadAllOptimizedImages: uploadAllOptimizedImages,
      uploadAllOptimizedVideos: uploadAllOptimizedVideos,
      uploadAllPreviews: uploadAllPreviews,
      skipSwiftMetadataParsing: skipSwiftMetadataParsing,
      skipInstructionDisassembly: skipInstructionDisassembly,
      skipExtraAssetCatalogImageProcessing: skipExtraAssetCatalogImageProcessing
    ).generateResults(capstone: capstone)
    return results
  }

  private func applicationDirectoryURL(from plistDirectory: URL) throws -> URL {
    let plistURL = plistDirectory.appendingPathComponent("Info.plist")
    let plistData = try Data(contentsOf: plistURL)
    if let dictionary = try? PropertyListSerialization.propertyList(
      from: plistData,
      options: [],
      format: nil
    ) as? NSDictionary,
      let applicationPath = (dictionary["ApplicationProperties"] as? NSDictionary)?[
        "ApplicationPath"
      ] as? String
    {
      let appURL = plistDirectory.appendingPathComponent("Products").appendingPathComponent(
        applicationPath
      ).deletingLastPathComponent()
      return appURL
    }

    let applicationDefaultURL = plistDirectory.appendingPathComponent("Products/Applications")
    if FileManager.default.fileExists(atPath: applicationDefaultURL.path) {
      return applicationDefaultURL
    }
    throw Error.appNotFound
  }

  private func findAppURL() throws -> (URL, DSYMs) {
    let itemPath = try FileManager.default.contentsOfDirectory(atPath: destinationURL.path)
    if let appURL = itemPath.first(where: { $0.hasSuffix(".app") }) {
      return (destinationURL.appendingPathComponent(appURL), [:])
    } else if itemPath.contains(where: { $0.hasSuffix(".xcarchive") })
      || itemPath.contains("Info.plist")
    {
      // .xcarchives can be in a sub-folder, or the top level can be the .xcarchive
      let xcArchiveURL = itemPath.first(where: { $0.hasSuffix(".xcarchive") }) ?? "."
      let archiveURL = destinationURL.appendingPathComponent(xcArchiveURL)
      let dsymFolderURL = destinationURL.appendingPathComponent(xcArchiveURL)
        .appendingPathComponent("dSYMs")
      let dsyms = (try? findDsyms(from: dsymFolderURL)) ?? [:]
      if let applicationFolderURL = try? applicationDirectoryURL(from: archiveURL) {
        let itemPath = try FileManager.default.contentsOfDirectory(
          atPath: applicationFolderURL.path
        )
        if let appURL = itemPath.first(where: { $0.hasSuffix(".app") }) {
          return (applicationFolderURL.appendingPathComponent(appURL), dsyms)
        } else {
          throw Error.appNotFound
        }
      } else {
        // Find framework in archive
        let frameworksDirectory = archiveURL.appendingPathComponent("Products/Library/Frameworks")
        let itemPath = try FileManager.default.contentsOfDirectory(atPath: frameworksDirectory.path)
        if let appURL = itemPath.first(where: { $0.hasSuffix(".framework") }) {
          let frameworkURL = frameworksDirectory.appendingPathComponent(appURL)
          try? FileManager.default.removeItem(at: frameworkURL.appendingPathComponent("Modules"))
          try? FileManager.default.removeItem(at: frameworkURL.appendingPathComponent("Headers"))
          return (frameworkURL, dsyms)
        } else {
          throw Error.appNotFound
        }
      }
    } else if let frameworkURL = frameworkURL() {
      let dsyms = (try? findDsyms(from: destinationURL)) ?? [:]
      try? FileManager.default.removeItem(at: frameworkURL.appendingPathComponent("Modules"))
      try? FileManager.default.removeItem(at: frameworkURL.appendingPathComponent("Headers"))
      // See if this is a framework
      return (frameworkURL, dsyms)
    }
    let filteredPaths = itemPath.filter { !$0.starts(with: ".") && !$0.starts(with: "_") }
    throw Error.archiveNotFound(filteredPaths.first)
  }

  private enum Error: Swift.Error {
    // Param is the name of a file we did find in the .zip upload, if any
    case archiveNotFound(String?)
    case appNotFound
    case noFilesFound
  }

  private func frameworkURL() -> URL? {
    guard
      let frameworkName = try? FileManager.default.contentsOfDirectory(atPath: destinationURL.path)
        .first(where: { $0.hasSuffix(".framework") })
    else { return frameworkInXCFramework() }

    return destinationURL.appendingPathComponent(frameworkName)
  }

  private func frameworkInXCFramework() -> URL? {
    guard
      let xcframeworkName = try? FileManager.default.contentsOfDirectory(
        atPath: destinationURL.path
      ).first(where: { $0.hasSuffix(".xcframework") })
    else { return nil }

    do {
      let plistURL = destinationURL.appendingPathComponent(xcframeworkName).appendingPathComponent(
        "Info.plist"
      )
      let data = try PropertyListDecoder().decode(
        XCFrameworkInfo.self,
        from: try Data(contentsOf: plistURL)
      )
      if let library = data.AvailableLibraries.first(where: {
        $0.SupportedPlatformVariant == nil && $0.SupportedArchitectures.contains("arm64")
          && $0.SupportedPlatform == "ios"
      }) {
        let result = destinationURL.appendingPathComponent(xcframeworkName).appendingPathComponent(
          library.LibraryIdentifier
        ).appendingPathComponent(library.LibraryPath)
        return result
      }
    } catch {}
    return nil
  }

  struct XCFrameworkInfo: Decodable {
    let AvailableLibraries: [Library]

    struct Library: Decodable {
      let LibraryIdentifier: String
      let LibraryPath: String
      let SupportedPlatform: String
      let SupportedPlatformVariant: String?
      let SupportedArchitectures: [String]
    }
  }

  private func findDsyms(from url: URL) throws -> [String: URL] {
    var dsyms = [String: URL]()
    guard let dsymEnumerator = FileManager.default.enumerator(atPath: url.path) else {
      return dsyms
    }
    for file in dsymEnumerator {
      guard let fileString = file as? String else { continue }
      if fileString.contains("DWARF") {
        let fileURL = url.appendingPathComponent(fileString)
        let resourceValues = try fileURL.resourceValues(forKeys: [.isDirectoryKey])
        if !(resourceValues.isDirectory ?? true) {
          try BinaryStrip.thin(url: fileURL)
          if let uuid = fileURL.machOUUID() {
            dsyms[uuid] = fileURL
          }
        }
      }
    }
    return dsyms
  }

  private let workingDirURL: URL
  private let zipURL: URL
  private let destinationURL: URL
  private let s3BucketName: String
  private let fileKey: String
  private let previewsBucketName: String
  private let previewsEnabled: Bool
  private let uploadAllOptimizedImages: Bool
  private let uploadAllOptimizedVideos: Bool
  private let uploadAllPreviews: Bool
  private let skipSwiftMetadataParsing: Bool
  private let skipInstructionDisassembly: Bool
  private let skipExtraAssetCatalogImageProcessing: Bool
}

extension URL {
  var isSwiftStandardDylib: Bool {
    lastPathComponent.starts(with: "libswift") && pathExtension == "dylib"
  }

  var isXCTestDylib: Bool {
    lastPathComponent.starts(with: "libXCT") && pathExtension == "dylib"
  }

  var isXCTest: Bool {
    return pathExtension == "xctest" || lastPathComponent.hasSuffix(".xctest.dSYM")
  }

  var isTestFramework: Bool {
    return lastPathComponent == "XCTest.framework"
      || lastPathComponent == "XCTAutomationSupport.framework"
  }

  var isIgnoredMobileProvision: Bool {
    if pathComponents.last == "embedded.mobileprovision" {
      if let lastComponent = pathComponents.dropLast().last,
        lastComponent.hasSuffix(".app") || lastComponent.hasSuffix(".appex")
      {
        return true
      }
    }
    return false
  }
}
