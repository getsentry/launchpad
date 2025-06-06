//
//  AppBundle.swift
//  AppSizeAnalyzer
//
//  Created by Noah Martin on 11/10/20.
//

import CommonCrypto
import CoreGraphics
import Foundation

extension Data {
  func sha256() -> String {
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    self.withUnsafeBytes {
      _ = CC_SHA256($0.baseAddress, CC_LONG(self.count), &hash)
    }
    return hash.reduce("") { initial, value in
      initial + "\(value)"
    }
  }
}

public protocol File: Encodable {
  var size: UInt { get }
  var contentsSize: UInt { get }
  var name: String { get }
  var hashValue: String { get }
  var path: String { get }
}

extension URL {
  var relativePath: String {
    let prefix =
      pathComponents.firstIndex(where: { $0.hasSuffix(".app") })
      ?? pathComponents.firstIndex(where: { $0.hasSuffix(".framework") })
    if let appComponent = prefix, appComponent + 1 < pathComponents.count {
      let relativeComponents = pathComponents[(appComponent + 1)...]
      return relativeComponents.reduce("", { $0 + "/" + $1 })
    } else {
      return path
    }
  }

  public var appRelativePath: String {
    relativePath
  }
}

public struct AnyFile: File, Encodable, Equatable {
  init(url: URL) throws {
    relativePath = url.relativePath
    path = url.path
    name = url.lastPathComponent
    do {
      if try url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory ?? false {
        let enumerator = FileManager.default.enumerator(atPath: url.path)
        var hasher = Hasher()
        var size: UInt = 0
        var contentsSize: UInt = 0
        for file in enumerator?.allObjects ?? [] {
          if let fileString = file as? String {
            let fileURL = url.appendingPathComponent(fileString)
            let resourceValues = try fileURL.resourceValues(forKeys: [
              .isDirectoryKey, .totalFileAllocatedSizeKey, .fileSizeKey,
            ])
            let codeSignatureSize = fileURL.isMachOBinary ? url.extraCodeSignatureSize() : 0
            size += UInt(resourceValues.totalFileAllocatedSize ?? 0) + codeSignatureSize
            contentsSize += UInt(resourceValues.fileSize ?? 0) + codeSignatureSize
            if !(resourceValues.isDirectory ?? false) {
              let fileHash = try Data(contentsOf: fileURL).sha256()
              hasher.combine(fileHash)
            }
          }
        }
        value = size
        self.contentsSize = contentsSize
        hashValue = String(hasher.finalize())
      } else {
        var tempURL = url
        tempURL.removeCachedResourceValue(forKey: .totalFileAllocatedSizeKey)
        tempURL.removeCachedResourceValue(forKey: .fileSizeKey)
        let resourceValues = try tempURL.resourceValues(forKeys: [
          .totalFileAllocatedSizeKey, .fileSizeKey,
        ])
        let codeSignatureSize = url.isMachOBinary ? url.extraCodeSignatureSize() : 0
        value = UInt(resourceValues.totalFileAllocatedSize ?? 0) + codeSignatureSize
        contentsSize = UInt(resourceValues.fileSize ?? 0) + codeSignatureSize
        if url.isSymLink {
          hashValue = url.symlinkPath.data(using: .utf8)!.sha256()
        } else {
          let data = try Data(contentsOf: url)
          hashValue = data.sha256()
        }
      }
    } catch {
      logger.error("Error: \(error)")
      fatalError()
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(value, forKey: .value)
    try container.encode(name, forKey: .name)
    try container.encode(relativePath, forKey: .path)
  }

  private enum CodingKeys: String, CodingKey {
    case value
    case name
    case path
  }

  public var size: UInt {
    value
  }
  public var contentsSize: UInt
  public let path: String
  var value: UInt
  public let name: String
  public let hashValue: String
  let relativePath: String
}

public enum AssetType: Int {
  case image
  case icon
  case imageSet
}

public struct AssetCatalogEntry {
  public init(
    size: UInt,
    key: String? = nil,
    originalName: String? = nil,
    name: String,
    vector: Bool = false,
    width: Int? = nil,
    height: Int? = nil,
    filename: String? = nil,
    cgImage: CGImage? = nil,
    type: AssetType? = nil
  ) {
    self.size = size
    self.key = key
    self.originalName = originalName
    self.name = name
    self.vector = vector
    self.width = width
    self.height = height
    self.filename = filename
    self.cgImage = cgImage
    self.type = type
  }

  public let size: UInt
  let key: String?
  let originalName: String?
  let name: String
  let vector: Bool
  let width: Int?
  let height: Int?
  public let filename: String?
  public let cgImage: CGImage?
  let type: AssetType?

  var detailedName: String {
    if vector {
      return name + " (Vector)"
    }
    return name
  }

  func url(in catalog: AssetCatalog) -> URL {
    if let originalName = originalName {
      return catalog.url.appendingPathComponent(originalName + "/" + detailedName)
    }
    return catalog.url.appendingPathComponent(detailedName)
  }
}

public class Asset: Encodable {
  public init(
    size: UInt,
    key: String?,
    originalName: String?,
    name: String,
    vector: Bool,
    width: Int?,
    height: Int?,
    previewKey: String?
  ) {
    value = size
    self.key = key
    self.originalName = originalName
    self.name = name
    self.vector = vector
    self.width = width
    self.height = height
    self.previewKey = previewKey
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(value, forKey: .value)
    try container.encode(detailedName, forKey: .name)
    try container.encode(isDuplicate, forKey: .isDuplicate)
    try container.encode(moreUniqueName, forKey: .moreUniqueName)
    try container.encode(previewKey, forKey: .previewKey)
  }

  private enum CodingKeys: String, CodingKey {
    case value
    case name
    case isDuplicate
    case moreUniqueName
    case previewKey
  }

  var moreUniqueName: String {
    (originalName ?? name) + (vector ? "(Vector)" : "")
  }

  var detailedName: String {
    if vector {
      return name + " (Vector)"
    }
    return name
  }

  let key: String?
  let value: UInt
  private let originalName: String?
  private let name: String
  let vector: Bool
  let width: Int?
  let height: Int?
  var isDuplicate: Bool = false
  let previewKey: String?
}

final class AssetCatalog: File {
  init(url: URL) throws {
    self.url = url
    file = try AnyFile(url: url)
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    if assets.count > 0 {
      let assetSize = assets.map { $0.value }.reduce(0, +)
      let remainingSize = size - assetSize
      try container.encode(
        assets + [
          Asset(
            size: remainingSize,
            key: nil,
            originalName: nil,
            name: "Other",
            vector: false,
            width: nil,
            height: nil,
            previewKey: nil
          )
        ],
        forKey: .children
      )
    }
    try file.encode(to: encoder)
  }

  enum CodingKeys: String, CodingKey {
    case children
  }

  var assets = [Asset]()

  var size: UInt {
    file.size
  }

  var contentsSize: UInt {
    file.contentsSize
  }

  var name: String {
    file.name
  }

  var hashValue: String {
    file.hashValue
  }

  var path: String {
    file.path
  }

  let url: URL
  private let file: AnyFile
}

class Binary: File, Equatable {
  static func == (lhs: Binary, rhs: Binary) -> Bool {
    lhs.file == rhs.file
  }

  init(url: URL) throws {
    self.url = url
    file = try AnyFile(url: url)
  }

  func recalculateFileSize() throws {
    file = try AnyFile(url: url)
  }

  var treemap: BinaryTreemapElement?

  struct BinarySegment: Encodable {
    // The size
    let value: UInt64
    let name: String
    let children: [Section]?

    struct Section: Encodable {
      let name: String
      let value: UInt64
    }
  }

  func encode(to encoder: Encoder) throws {
    if let treemap = self.treemap {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(treemap.toJsonElement().children, forKey: .children)
      try file.encode(to: encoder)
    } else {
      try file.encode(to: encoder)
    }
  }

  enum CodingKeys: String, CodingKey {
    case children
  }

  let url: URL
  private var file: AnyFile

  var path: String {
    url.path
  }
  var name: String {
    file.name
  }
  var size: UInt {
    // TODO: Make sure bitcode is stripped
    return file.size
  }
  var contentsSize: UInt {
    size
  }
  var hashValue: String {
    file.hashValue
  }
}

enum FileType: Encodable {
  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(type, forKey: .type)
    try file.encode(to: container.superEncoder(forKey: .file))
  }

  case binary(Binary)
  case assetCatalog(AssetCatalog)
  case image(AnyFile)
  case strings(AnyFile)
  case folder(AnyFolder)
  case anyFile(AnyFile)
  case video(AnyFile)

  var file: File {
    switch self {
    case .binary(let binary):
      return binary
    case .assetCatalog(let catalog):
      return catalog
    case .image(let image):
      return image
    case .strings(let strings):
      return strings
    case .folder(let folder):
      return folder
    case .anyFile(let file):
      return file
    case .video(let file):
      return file
    }
  }

  var type: String {
    switch self {
    case .binary:
      return "binary"
    case .assetCatalog:
      return "assetCatalog"
    case .image:
      return "image"
    case .strings:
      return "strings"
    case .folder(let folder):
      return folder.type
    case .anyFile:
      return "anyFile"
    case .video:
      return "anyFile"
    }
  }

  enum CodingKeys: String, CodingKey {
    case type
    case file
  }

  init(url: URL) throws {
    let pathExtension = url.pathExtension
    let values = try url.resourceValues(forKeys: [.isDirectoryKey])
    if (values.isDirectory ?? false) && pathExtension != "mlmodelc" && pathExtension != "nib"
      && pathExtension != "storyboardc"
    {
      self = .folder(try FolderType.make(url: url))
      return
    }

    switch pathExtension {
    case "strings":
      self = .strings(try AnyFile(url: url))
      return
    case "png", "jpeg", "jpg", "heic", "heif":
      self = .image(try AnyFile(url: url))
      return
    case "car":
      self = .assetCatalog(try AssetCatalog(url: url))
      return
    case "mov", "mp4":
      self = .video(try AnyFile(url: url))
      return
    default:
      if url.isMachOBinary {
        self = .binary(try Binary(url: url))
        return
      } else {
        self = .anyFile(try AnyFile(url: url))
        return
      }
    }
  }
}

// MARK: - Folder

protocol Folder: File {
  var files: [File] { get }
}

extension Folder {
  public var size: UInt {
    files.map { $0.size }.reduce(0, +)
  }

  public var contentsSize: UInt {
    files.map { $0.contentsSize }.reduce(0, +)
  }

  public var hashValue: String {
    var hasher = Hasher()
    files.forEach { hasher.combine($0.hashValue) }
    return String(hasher.finalize())
  }
}

public struct AnyFolder: Folder {
  init(url: URL) throws {
    relativePath = url.relativePath
    path = url.path
    name = url.lastPathComponent
    isPackage = (try? url.resourceValues(forKeys: [.isPackageKey]).isPackage) ?? false
    if url.pathExtension == "lproj" {
      type = url.pathExtension
    } else {
      type = "folder"
    }
    do {
      contents = try FileManager.default.contentsOfDirectory(atPath: url.path).compactMap {
        let newURL = url.appendingPathComponent($0)

        return try FileType(url: newURL)
      }
    } catch {
      logger.error("Error: \(error)")
      fatalError()
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(relativePath, forKey: .path)
    try container.encode(size, forKey: .value)
    try container.encode(name, forKey: .name)
    try container.encode(contents, forKey: .children)
    try container.encode(isPackage, forKey: .isPackage)
  }

  enum CodingKeys: String, CodingKey {
    case path
    case value
    case name
    case children
    case isPackage
  }

  let relativePath: String
  public let path: String
  public let name: String
  let isPackage: Bool
  let contents: [FileType]
  var files: [File] {
    contents.map { $0.file as File }
  }
  var type: String
}

enum FolderType {
  static func make(url: URL) throws -> AnyFolder {
    switch url.pathExtension {
    case "app":
      return try AnyFolder(url: url)
    case "bundle":
      return try AnyFolder(url: url)
    default:
      return try AnyFolder(url: url)
    }
  }
}
