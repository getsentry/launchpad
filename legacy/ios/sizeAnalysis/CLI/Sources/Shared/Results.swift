//
//  File.swift
//
//
//  Created by Noah Martin on 11/18/20.
//

import Foundation

struct ObsoleteFramework: Encodable {
  init(record: ObsoleteFrameworkRecord, size: UInt64) {
    name = record.name
    self.size = size
    obsoletedVersion = record.obsoletedVersion
  }

  let name: String
  let size: UInt64
  let obsoletedVersion: Int
}

struct ObsoleteFrameworkRecord {
  let name: String
  // OS version major number
  let obsoletedVersion: Int
}

extension String {
  func trimmed() -> String? {
    let result = trimmingCharacters(in: .whitespacesAndNewlines)
    if result.count == 0 {
      return nil
    }
    return result
  }
}

public struct AppStoreSize: Encodable {
  let installSize: UInt
  let downloadSize: UInt?  // Nil for frameworks
}

public struct AnalyzedSizes: Encodable {
  let mainApp: AppStoreSize
}

struct BuildMetadata: Encodable {
  let buildVersion: String

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(buildVersion, forKey: .build_version)
  }

  enum CodingKeys: String, CodingKey {
    case build_version
  }
}

public enum ResultStatus: String, Encodable {
  case success = "SUCCESS"
  case error = "ERROR"
}

public enum SizeAnalysisResultErrorType: String, Encodable {
  case generic = "GENERIC"
}

public struct ErrorResults: Encodable {
  public let status = ResultStatus.error
  public let errorMessage: String
  public let errorType: SizeAnalysisResultErrorType

  public init(errorMessage: String, errorType: SizeAnalysisResultErrorType) {
    self.errorMessage = errorMessage
    self.errorType = errorType
  }
}

public struct Results {
  init(
    size: AnalyzedSizes,
    app: AnyFolder,
    plistData: PlistData,
    opportunities: [ResultError],
    diagnostics: [ResultDiagnostic],
    dylibs: [Dylibs],
    subproducts: [Subproduct],
    hasBitcode: Bool
  ) throws {
    emergeBuildMetadata = .init(buildVersion: Constants.sizeAnalysisVersion)
    self.size = size
    self.app = app
    self.opportunities = opportunities
    self.diagnostics = diagnostics
    self.dylibs = dylibs
    self.subproducts = subproducts
    self.hasBitcode = hasBitcode

    appId = plistData.appId
    appName = plistData.appName
    appVersion = plistData.appVersion
    appBuild = plistData.appBuild
    xcodeBuildVersion = plistData.xcodeBuildVersion
    platformBuildVersion = plistData.platformBuildVersion
    buildMachineBuildVersion = plistData.buildMachineBuildVersion

    var totalSavings: UInt = 0
    // This should contain relative paths
    var countedFilePaths = Set<String>()
    opportunities.forEach { resultError in
      switch resultError.type {
      case .InvalidFileName(let invalidFile):
        totalSavings += invalidFile.files.reduce(0, { acc, file in acc + file.size })
        var queue = invalidFile._files
        while !queue.isEmpty {
          let file = queue.removeFirst()
          let path = URL(fileURLWithPath: file.path).relativePath
          countedFilePaths.insert(path)
          if let folder = file as? Folder {
            queue.append(contentsOf: folder.files)
          }
        }
      default:
        break
      }
    }

    opportunities.forEach { resultError in
      switch resultError.type {
      case .DuplicateFiles(let duplicates):
        duplicates.forEach { duplicates in
          if let files = duplicates.files {
            var queue = files.dropFirst()
            while !queue.isEmpty {
              let file = queue.removeFirst()
              let path = URL(fileURLWithPath: file.path).relativePath
              if let folder = file as? Folder {
                queue.append(contentsOf: folder.files)
              } else {
                if !countedFilePaths.contains(path) {
                  totalSavings += file.size
                }
              }
              countedFilePaths.insert(path)
            }
          } else {
            duplicates.paths.dropFirst().forEach { path in
              if !countedFilePaths.contains(path) {
                totalSavings += duplicates.individualSize
                countedFilePaths.insert(path)
              }
            }
          }
        }
      default:
        break
      }
    }

    opportunities.forEach { resultError in
      switch resultError.type {
      case .RawImage(let rawImages):
        rawImages.groups.forEach { image in
          for file in image.images {
            if !countedFilePaths.contains(file.relativePath) {
              if let includedFile = image.includedFile,
                includedFile.relativePath != file.relativePath
              {
                countedFilePaths.insert(file.relativePath)
                totalSavings += file.size
              }
            }
          }
        }
      default:
        break
      }
    }

    opportunities.forEach { resultError in
      switch resultError.type {
      case .BinaryTrie(let trieDetails):
        trieDetails.forEach { detail in
          guard !countedFilePaths.contains(detail.url.relativePath) else { return }
          // Don't add to countedFilePaths, to allow for multiple binary issues to be reported
          totalSavings += detail.saveableSize
        }
      case .BinaryStrip(let strippedDetails):
        strippedDetails.forEach { detail in
          guard !countedFilePaths.contains(detail.url.relativePath) else { return }
          // Don't add to countedFilePaths, to allow for multiple binary issues to be reported
          totalSavings += UInt(detail.saveableSize)
        }
      case .CommentsInStrings(let commentsInStrings):
        commentsInStrings.forEach { commentInStrings in
          let relativePath = URL(fileURLWithPath: commentInStrings.path).relativePath
          guard !countedFilePaths.contains(relativePath) else { return }

          countedFilePaths.insert(relativePath)
          totalSavings += commentInStrings.saveableSize
        }
      case .OptimizeImages(let optimizeImages), .OptimizeAlternateIcons(let optimizeImages):
        optimizeImages.forEach { image in
          guard !countedFilePaths.contains(image.path) else {
            return
          }

          countedFilePaths.insert(image.path)
          totalSavings += image.maxSaveable
        }
      case .OptimizeAudio(let optimizeAudio):
        optimizeAudio.forEach { audio in
          guard !countedFilePaths.contains(audio.path) else {
            return
          }

          countedFilePaths.insert(audio.path)
          totalSavings += audio.saveableSize
        }
      case .OptimizeVideos(let optimizeVideos):
        optimizeVideos.forEach { video in
          guard !countedFilePaths.contains(video.path) else {
            return
          }

          countedFilePaths.insert(video.path)
          totalSavings += video.savings.installSizeSavings
        }
      case .RawImage, .InvalidFileName, .DuplicateFiles:
        break
      }
    }
    self.totalSavings = totalSavings
  }

  let emergeBuildMetadata: BuildMetadata
  public let size: AnalyzedSizes
  public let app: AnyFolder
  public let appId: String
  public let appName: String
  public let appVersion: String
  public let appBuild: String
  public let xcodeBuildVersion: String
  public let platformBuildVersion: String
  public let buildMachineBuildVersion: String
  public let opportunities: [ResultError]
  public let diagnostics: [ResultDiagnostic]
  public let totalSavings: UInt
  public let dylibs: [Dylibs]
  public let status = ResultStatus.success
  public let subproducts: [Subproduct]
  public let hasBitcode: Bool
}

public struct ResultError: Encodable, Comparable {
  public static func < (lhs: ResultError, rhs: ResultError) -> Bool {
    lhs.potentialSavings < rhs.potentialSavings
  }

  init(trieDetails: [ResultErrorType.TrieDetails]) {
    potentialSavings = UInt64(trieDetails.map { $0.saveableSize }.reduce(0, +))
    type = .BinaryTrie(trieDetails.sorted(by: { $0.saveableSize > $1.saveableSize }))
    fixItScript = nil
  }

  init(duplicates: [ResultErrorType.Duplicates]) {
    let filteredDuplicates = duplicates.filter { $0.saveableSize > 0 }
    potentialSavings = UInt64(filteredDuplicates.map { $0.saveableSize }.reduce(0, +))
    type = .DuplicateFiles(filteredDuplicates.sorted(by: >))
    fixItScript = nil
  }

  init(optimizeImages: OptimizeImages, s3BucketName: String, s3Key: String) {
    potentialSavings = UInt64(optimizeImages.map { $0.maxSaveable }.reduce(0, +))
    type = .OptimizeImages(optimizeImages)
    fixItScript = nil
  }

  init(optimizeAlternateIcons: OptimizeImages, s3BucketName: String, s3Key: String) {
    potentialSavings = UInt64(optimizeAlternateIcons.map { $0.maxSaveable }.reduce(0, +))
    type = .OptimizeAlternateIcons(optimizeAlternateIcons)
    fixItScript = nil
  }

  init(optimizeAudio: [OptimizeAudio], s3BucketName: String, s3Key: String) {
    potentialSavings = UInt64(optimizeAudio.map { $0.saveableSize }.reduce(0, +))
    type = .OptimizeAudio(optimizeAudio)
    fixItScript = nil
  }

  init(optimizeVideos: [OptimizeVideo], s3BucketName: String, s3Key: String) {
    potentialSavings = UInt64(optimizeVideos.map { $0.savings.installSizeSavings }.reduce(0, +))
    type = .OptimizeVideos(optimizeVideos)
    fixItScript = nil
  }

  init(strings: [CommentsInStrings]) {
    potentialSavings = UInt64(strings.map { $0.saveableSize }.reduce(0, +))
    type = .CommentsInStrings(strings.sorted(by: { $0.saveableSize > $1.saveableSize }))
    fixItScript = nil
  }

  init(rawImage: ResultErrorType.RawImages) {
    let groups = rawImage.groups.filter { $0.saveableSize != nil }
    let usedRawImages = ResultErrorType.RawImages(groups: groups)
    potentialSavings = UInt64(groups.compactMap { $0.saveableSize }.reduce(0, +))
    type = .RawImage(usedRawImages)
    fixItScript = nil
  }

  init?(invalidFiles: ResultErrorType.InvalidFile) {
    potentialSavings = UInt64(invalidFiles.files.map { $0.size }.reduce(0, +))
    if potentialSavings <= 0 {
      return nil
    }
    type = .InvalidFileName(invalidFiles)
    fixItScript = nil
  }

  init(binaryStrip: [ResultErrorType.StrippedDetails]) {
    potentialSavings = binaryStrip.map { $0.saveableSize }.reduce(0, +)
    type = .BinaryStrip(binaryStrip.sorted(by: { $0.saveableSize > $1.saveableSize }))
    var scriptContents =
      "#!/bin/sh\nAPP_PATH=\"$(dirname \"${TARGET_BUILD_DIR}/${FRAMEWORKS_FOLDER_PATH}\")\"\n"
    for strip in binaryStrip {
      scriptContents +=
        "strip -rSTx -no_code_signature_warning \"${APP_PATH}\(strip.url.relativePath)\"\n"
    }
    fixItScript = scriptContents
  }

  let potentialSavings: UInt64
  let type: ResultErrorType
  let fixItScript: String?
}

public struct ResultDiagnostic: Encodable {
  let type: ResultDiagnosticType

  func shrink() -> Self {
    switch type {
    case .LooseImages:
      return self
    case .LargeStrings:
      return ResultDiagnostic(
        objcType: objcType,
        otherString: otherString.map { $0.shrink() },
        onlyTopStrings: true
      )
        ?? self
    case .ObsoleteFrameworks:
      return self
    case .UnusedProtocols:
      return self
    case .SmallFiles:
      return self
    case .LocalizedStrings:
      return self
    case .PreviewProviders:
      return self
    case .StaticInits:
      return self
    }
  }

  init?(looseImages: ResultErrorType.RawImages) {
    self.looseImages = looseImages.groups.filter { $0.saveableSize == nil }.flatMap { $0.images }
    if self.looseImages.isEmpty {
      return nil
    }
    objcType = []
    otherString = []
    unusedProtocols = []
    previewProviderProtocols = []
    otherStringCount = nil
    smallFiles = nil
    frameworks = []
    localizedStrings = nil

    type = .LooseImages
  }

  init?(localizedStringsTotalSize: Int, localizedStringsFileCount: Int) {
    guard localizedStringsTotalSize > 100 * 1000 else { return nil }

    looseImages = []
    objcType = []
    otherString = []
    unusedProtocols = []
    previewProviderProtocols = []
    otherStringCount = nil
    smallFiles = nil
    frameworks = []

    localizedStrings = LocalizedStrings(
      fileCount: localizedStringsFileCount,
      totalFileSize: localizedStringsTotalSize
    )
    type = .LocalizedStrings
  }

  init?(objcType: [LargeString], otherString: [LargeString], onlyTopStrings: Bool = false) {
    guard (objcType + otherString).count > 0 else { return nil }
    looseImages = []
    self.objcType = objcType.sorted(by: { $0.size > $1.size })
    let sortedStrings = otherString.sorted(by: { $0.size > $1.size })
    if onlyTopStrings {
      self.otherString = Array(sortedStrings.prefix(10))
    } else {
      self.otherString = sortedStrings
    }
    unusedProtocols = []
    previewProviderProtocols = []
    otherStringCount = otherString.count
    smallFiles = nil
    frameworks = []
    localizedStrings = nil

    type = .LargeStrings
  }

  init?(smallFiles: [File], allFiles: [File]) {
    guard smallFiles.count > 100 || allFiles.count > 100 else { return nil }

    var extensionCounts = [String: Int]()
    let extensions = allFiles.map { URL(fileURLWithPath: $0.path).pathExtension }.filter {
      !$0.isEmpty
    }
    for ext in extensions {
      extensionCounts[ext] = (extensionCounts[ext] ?? 0) + 1
    }
    let orderedKeys = extensionCounts.keys.sorted {
      extensionCounts[$0] ?? 0 > extensionCounts[$1] ?? 0
    }
    let firstType = orderedKeys.first.map {
      SmallFiles.SmallFileType(type: $0, count: extensionCounts[$0] ?? 0)
    }
    let secondType =
      orderedKeys.count > 1
      ? SmallFiles.SmallFileType(type: orderedKeys[1], count: extensionCounts[orderedKeys[1]] ?? 0)
      : nil
    self.smallFiles = SmallFiles(
      totalCount: allFiles.count,
      smallCount: smallFiles.count,
      smallFilesContentSize: UInt64(smallFiles.map { $0.contentsSize }.reduce(0, +)),
      firstType: firstType,
      secondType: secondType
    )
    looseImages = []
    objcType = []
    otherString = []
    unusedProtocols = []
    previewProviderProtocols = []
    otherStringCount = nil
    frameworks = []
    localizedStrings = nil

    type = .SmallFiles
  }

  init?(frameworks: [ObsoleteFramework]) {
    guard frameworks.count > 0 else { return nil }

    looseImages = []
    objcType = []
    otherString = []
    unusedProtocols = []
    previewProviderProtocols = []
    otherStringCount = nil
    smallFiles = nil
    localizedStrings = nil
    self.frameworks = frameworks

    type = .ObsoleteFrameworks
  }

  init(protocols: [ModuleProtocols]) {
    looseImages = []
    objcType = []
    otherString = []
    frameworks = []
    unusedProtocols = protocols
    previewProviderProtocols = []
    otherStringCount = nil
    smallFiles = nil
    localizedStrings = nil

    type = .UnusedProtocols
  }

  init?(previewProviders: [ModuleProtocols]) {
    if previewProviders.isEmpty {
      return nil
    }

    previewProviderProtocols = previewProviders
    looseImages = []
    objcType = []
    otherString = []
    frameworks = []
    unusedProtocols = []
    otherStringCount = nil
    smallFiles = nil
    localizedStrings = nil

    type = .PreviewProviders
  }

  init?(staticInitializers: [StaticInits]) {
    previewProviderProtocols = []
    looseImages = []
    objcType = []
    otherString = []
    frameworks = []
    unusedProtocols = []
    otherStringCount = nil
    smallFiles = nil
    localizedStrings = nil
    staticInits = staticInitializers

    type = .StaticInits
  }

  struct ModuleProtocols: Encodable {
    init(moduleName: String, protocols: [String]) {
      self.moduleName = moduleName
      self.protocols = protocols
    }

    init(moduleName: String, protocols: Set<String>) {
      self.moduleName = moduleName
      self.protocols = Array(protocols)
    }

    let moduleName: String
    let protocols: [String]
  }

  let looseImages: [AnyFile]
  let objcType: [LargeString]
  let otherString: [LargeString]
  let smallFiles: SmallFiles?
  let frameworks: [ObsoleteFramework]
  let otherStringCount: Int?
  let unusedProtocols: [ModuleProtocols]
  let previewProviderProtocols: [ModuleProtocols]
  let localizedStrings: LocalizedStrings?
  var staticInits: [StaticInits] = []

  enum ResultDiagnosticType: String, Encodable {
    case LocalizedStrings
    case LooseImages
    case LargeStrings
    case SmallFiles
    case ObsoleteFrameworks
    case UnusedProtocols
    case PreviewProviders
    case StaticInits
  }
}

public struct LocalizedStrings: Encodable {
  let fileCount: Int
  let totalFileSize: Int
}

public struct SmallFiles: Encodable {
  let totalCount: Int
  let smallCount: Int
  let smallFilesContentSize: UInt64
  let firstType: SmallFileType?
  let secondType: SmallFileType?

  struct SmallFileType: Encodable {
    let type: String
    let count: Int
  }
}

public struct LargeString: Encodable {
  init(cString: CString, binaryName: String) {
    string = cString.string
    size = cString.size
    self.binaryName = binaryName
  }

  init(string: String, size: UInt64, binaryName: String) {
    self.string = string
    self.size = size
    self.binaryName = binaryName
  }

  func shrink() -> LargeString {
    return LargeString(string: String(string.prefix(2000)), size: size, binaryName: binaryName)
  }

  let string: String
  let size: UInt64
  let binaryName: String
}

public struct StaticInits: Encodable, Equatable {
  let binaryName: String
  let binaryPath: String
  let staticInitializers: [String]
}

public struct Dylibs: Encodable, Equatable {
  let binaryName: String
  let binaryPath: String
  let dylibs: [DylibInfo]
}

struct DylibInfo: Encodable, Equatable {
  let path: String
  // True if the dynamic library is found, false if dyld will not be able to find it
  let found: Bool
}

class OptimizeAudio: Encodable, Equatable {
  static func == (lhs: OptimizeAudio, rhs: OptimizeAudio) -> Bool {
    lhs.path == rhs.path && lhs.saveableSize == rhs.saveableSize
  }

  init(
    hash: String,
    path: String,
    optimizedFileURL: URL?,
    saveableSize: UInt,
    awsPath: String? = nil
  ) {
    self.hash = hash
    self.path = path
    self.optimizedFileURL = optimizedFileURL
    self.saveableSize = saveableSize
    self.awsPath = awsPath
  }

  let hash: String
  let path: String
  let optimizedFileURL: URL?
  let saveableSize: UInt
  var awsPath: String?

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(path, forKey: .path)
    try container.encode(saveableSize, forKey: .saveableSize)
    try container.encode(awsPath, forKey: .awsPath)
  }

  enum CodingKeys: String, CodingKey {
    case path
    case saveableSize
    case awsPath
  }
}

struct CommentsInStrings: Encodable, Equatable {
  let path: String
  let saveableSize: UInt

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(URL(fileURLWithPath: path).relativePath, forKey: .path)
    try container.encode(saveableSize, forKey: .saveableSize)
  }

  enum CodingKeys: String, CodingKey {
    case path
    case saveableSize
  }
}

enum ResultErrorType: Encodable, Equatable {
  case BinaryTrie([TrieDetails])
  case DuplicateFiles([Duplicates])
  case OptimizeImages(OptimizeImages)
  case OptimizeAudio([OptimizeAudio])
  case RawImage(RawImages)
  case InvalidFileName(InvalidFile)
  case BinaryStrip([StrippedDetails])
  case CommentsInStrings([CommentsInStrings])
  case OptimizeAlternateIcons(OptimizeImages)
  case OptimizeVideos([OptimizeVideo])

  struct Duplicates: Encodable, Comparable {
    static func == (lhs: ResultErrorType.Duplicates, rhs: ResultErrorType.Duplicates) -> Bool {
      lhs.individualSize == rhs.individualSize && lhs.paths == rhs.paths
    }

    static func < (lhs: ResultErrorType.Duplicates, rhs: ResultErrorType.Duplicates) -> Bool {
      lhs.saveableSize < rhs.saveableSize
    }

    func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(saveableSize, forKey: .saveableSize)
      try container.encode(paths, forKey: .paths)
    }

    enum CodingKeys: String, CodingKey {
      case saveableSize
      case paths
    }

    let individualSize: UInt
    let paths: [String]
    let files: [File]?
    var saveableSize: UInt {
      individualSize * UInt(paths.count - 1)
    }
  }

  struct RawImages: Encodable, Equatable {
    init(groups: [RawImageGroup]) {
      self.groups = groups.sorted(by: >)
    }
    let groups: [RawImageGroup]
  }

  struct RawImageGroup: Encodable, Comparable {
    let images: [AnyFile]

    static func < (lhs: ResultErrorType.RawImageGroup, rhs: ResultErrorType.RawImageGroup) -> Bool {
      lhs.saveableSize ?? 0 < rhs.saveableSize ?? 0
    }

    func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encodeIfPresent(saveableSize, forKey: .saveableSize)
      try container.encode(paths, forKey: .paths)
    }

    enum CodingKeys: String, CodingKey {
      case saveableSize
      case paths
    }

    // The file that won't be deleted after fixing this opportunity
    var includedFile: AnyFile? {
      guard images.count > 1 else {
        return nil
      }

      return images.min { file1, file2 in
        file1.size < file2.size
      }
    }

    var saveableSize: UInt? {
      guard images.count > 1 else {
        return nil
      }

      let totalSize = images.reduce(0) { $0 + $1.size }
      guard let minSize = includedFile?.size else {
        return 0
      }

      return totalSize - minSize
    }

    var paths: [String] {
      images.map { $0.relativePath }
    }
  }

  struct InvalidFile: Encodable, Equatable {
    static func == (lhs: ResultErrorType.InvalidFile, rhs: ResultErrorType.InvalidFile) -> Bool {
      lhs.files == rhs.files
    }

    func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(files, forKey: .files)
    }

    init(files: [File]) {
      _files = files
      let sortedFiles = files.sorted(by: { lhs, rhs in
        lhs.size > rhs.size
      })
      self.files = sortedFiles.map { SomeFile(file: $0) }
    }

    struct SomeFile: Encodable, Equatable {
      init(file: File) {
        self.path = URL(fileURLWithPath: file.path).relativePath
        self.value = file.size
        self.name = file.name
      }

      let path: String
      let value: UInt
      let name: String

      var size: UInt {
        value
      }
    }

    enum CodingKeys: String, CodingKey {
      case files
    }

    let files: [SomeFile]
    var _files: [File]
  }

  struct TrieDetails: Encodable, Equatable {
    let saveableSize: UInt
    let url: URL

    func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(saveableSize, forKey: .saveableSize)
      try container.encode(url.relativePath, forKey: .path)
    }

    private enum CodingKeys: String, CodingKey {
      case saveableSize
      case path
    }
  }

  struct StrippedDetails: Encodable, Equatable {
    let saveableSize: UInt64
    let url: URL

    func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(saveableSize, forKey: .saveableSize)
      try container.encode(url.relativePath, forKey: .path)
    }

    private enum CodingKeys: String, CodingKey {
      case saveableSize
      case path
    }
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(type, forKey: .type)
    try details?.encode(to: container.superEncoder(forKey: .details))
  }

  var type: String {
    switch self {
    case .DuplicateFiles:
      return "duplicateFiles"
    case .OptimizeImages:
      return "optimizeImages"
    case .OptimizeAudio:
      return "optimizeAudio"
    case .InvalidFileName:
      return "invalidFileName"
    case .RawImage:
      return "rawImage"
    case .CommentsInStrings:
      return "commentsInStrings"
    case .BinaryStrip:
      return "binaryStrip"
    case .BinaryTrie:
      return "binaryTrie"
    case .OptimizeAlternateIcons:
      return "optimizeAlternateIcons"
    case .OptimizeVideos:
      return "optimizeVideos"
    }
  }

  var details: Encodable? {
    switch self {
    case .DuplicateFiles(let files):
      return files
    case .OptimizeImages(let optimize):
      return optimize
    case .OptimizeAudio(let optimize):
      return optimize
    case .RawImage(let files):
      return files
    case .CommentsInStrings(let strings):
      return strings
    case .InvalidFileName(let file):
      return file
    case .BinaryStrip(let file):
      return file
    case .BinaryTrie(let file):
      return file
    case .OptimizeAlternateIcons(let optimize):
      return optimize
    case .OptimizeVideos(let optimize):
      return optimize
    }
  }

  enum CodingKeys: String, CodingKey {
    case type
    case details
  }
}

typealias OptimizeImages = [OptimizeImage]

class OptimizeImage: Encodable, Comparable {
  static func < (lhs: OptimizeImage, rhs: OptimizeImage) -> Bool {
    lhs.maxSaveable < rhs.maxSaveable
  }

  init(
    hash: String?,
    inFormatSavings: UInt?,
    newFormatSavings: UInt?,
    originalSize: UInt,
    path: String,
    optimizedFileURL: URL?,
    awsPath: String? = nil
  ) {
    self.hash = hash
    self.inFormatSavings = inFormatSavings
    self.newFormatSavings = newFormatSavings
    self.originalSize = originalSize
    self.path = path
    self.optimizedFileURL = optimizedFileURL
    self.awsPath = awsPath
  }

  static func == (lhs: OptimizeImage, rhs: OptimizeImage) -> Bool {
    return lhs.path == rhs.path && lhs.originalSize == rhs.originalSize
      && lhs.inFormatSavings == rhs.inFormatSavings && lhs.newFormatSavings == rhs.newFormatSavings
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(inFormatSavings, forKey: .inFormatSavings)
    try container.encode(newFormatSavings, forKey: .newFormatSavings)
    try container.encode(originalSize, forKey: .originalSize)
    try container.encode(path, forKey: .path)
    try container.encode(awsPath, forKey: .awsPath)
  }

  enum CodingKeys: String, CodingKey {
    case inFormatSavings
    case newFormatSavings
    case originalSize
    case path
    case awsPath
  }

  let hash: String?
  let inFormatSavings: UInt?
  let newFormatSavings: UInt?
  var maxSaveable: UInt {
    max(inFormatSavings ?? 0, newFormatSavings ?? 0)
  }
  let originalSize: UInt
  let path: String
  let optimizedFileURL: URL?
  var awsPath: String?
}
