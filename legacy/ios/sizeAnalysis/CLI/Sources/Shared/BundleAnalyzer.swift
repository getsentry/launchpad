//
//  BundleAnalyzer.swift
//  AppSizeAnalyzer
//
//  Created by Noah Martin on 11/10/20.
//

import AVFoundation
import CwlDemangle
import Foundation
import Capstone
import Logging

extension BinaryTreemapElement {

  func size(of components: [String]) -> Int {
    if components.count == 0 {
      return Int(size)
    }
    return children[components[0]]?.size(of: Array(components.dropFirst())) ?? 0
  }
}

public final class BundleAnalyzer {
  public init(
    logger: Logger,
    url: URL,
    dsym: DSYMs,
    s3BucketName: String,
    s3Key: String,
    previewsBucketName: String,
    previewsEnabled: Bool,
    imageOptimizing: ImageOptimizing,
    uploadAllOptimizedImages: Bool,
    uploadAllOptimizedVideos: Bool,
    uploadAllPreviews: Bool,
    skipSwiftMetadataParsing: Bool,
    skipInstructionDisassembly: Bool,
    skipExtraAssetCatalogImageProcessing: Bool
  ) throws {
    self.logger = logger
    self.dsym = dsym
    self.s3BucketName = s3BucketName
    self.s3Key = s3Key
    self.previewsBucketName = previewsBucketName
    self.previewsEnabled = previewsEnabled
    self.imageOptimizing = imageOptimizing
    self.uploadAllOptimizedImages = uploadAllOptimizedImages
    self.uploadAllOptimizedVideos = uploadAllOptimizedVideos
    self.uploadAllPreviews = uploadAllPreviews
    self.skipSwiftMetadataParsing = skipSwiftMetadataParsing
    self.skipInstructionDisassembly = skipInstructionDisassembly
    self.skipExtraAssetCatalogImageProcessing = skipExtraAssetCatalogImageProcessing
    bundle = try FileType(url: url)

    guard case let .folder(folder) = bundle else {
      throw Error.invalidFileType
    }

    let rootURL = URL(fileURLWithPath: folder.path)
    plistData = try PlistData(appRoot: rootURL)
  }

  var imageOptimizing: ImageOptimizing
  var cache = MediaCache.shared
  var plistData: PlistData
  var appId: String {
    plistData.appId
  }
  let s3Client = AWSS3Client()
  var userId: String? {
    s3Key.split(separator: "/").first.map { String($0) }
  }
  var errors = [KeyInApp: [ResultErrorType.Duplicates]]()
  let dsym: DSYMs
  let s3BucketName: String
  // TODO: This should be an env-scoped value passed from the lambda, not hardcoded name
  let optimizedBucketName = "optimized-images-emerge"
  let previewsBucketName: String
  let previewsEnabled: Bool
  let uploadAllOptimizedImages: Bool
  let uploadAllOptimizedVideos: Bool
  let uploadAllPreviews: Bool
  let skipSwiftMetadataParsing: Bool
  let skipInstructionDisassembly: Bool
  let skipExtraAssetCatalogImageProcessing: Bool
  let s3Key: String
  var invalidFileNames = [File]()
  var fileNameErrors: ResultError? {
    ResultError(invalidFiles: ResultErrorType.InvalidFile(files: invalidFileNames))
  }

  public func generateResults(
    capstone: Capstone
  ) throws -> Results {
    guard case let .folder(folder) = bundle else {
      throw Error.invalidFileType
    }

    let rootURL = URL(fileURLWithPath: folder.path)
    var executable = rootURL.appendingPathComponent(plistData.executableName)
    if !FileManager.default.fileExists(atPath: executable.path) {
      executable = rootURL.appendingPathComponent("Contents/MacOS").appendingPathComponent(
        plistData.executableName
      )
    }
    var hasBitcode = false

    invalidFileNames = folder.invalidFileNames

    duplicateFileCheck(folder)

    let minStrippedSavings = 1024 * 2  // 2kb
    let binaries = folder.binaries
    var binaryStrips = [ResultErrorType.StrippedDetails]()
    var binaryTries = [ResultErrorType.TrieDetails]()
    var largeObjcStrings = [LargeString]()
    var largeOtherStrings = [LargeString]()
    var protocols = Set<String>()
    var protocolConformed = Set<String>()
    var previewProviders = [(String, String)]()
    var dylbs = [Dylibs]()
    var staticInits = [StaticInits]()

    time("\(appId) binary") {
      for i in binaries.indices {
        let binary = binaries[i]
        let binaryHasBitcode = (try? checkForBitcode(url: binary.url)) ?? false
        hasBitcode = hasBitcode || binaryHasBitcode
        try? BinaryStrip.stripBitcode(url: binary.url)
        // Since we stripped the bitcode segment we need to determine the new file size
        try? binary.recalculateFileSize()
        let plistData = try? PlistData(appRoot: binary.url.deletingLastPathComponent())
        var isThirdParty = false
        if let plistData = plistData, ThirdPartyFrameworkBundleID(bundleID: plistData.appId) != nil
        {
          isThirdParty = true
        }
        if !isThirdParty {
          let separator = BinarySeparator(
            url: binary.url,
            dsym: dsym,
            appId: plistData?.appId ?? "",
            capstone: capstone,
            skipSwiftMetadataParsing: skipSwiftMetadataParsing,
            skipInstructionDisassembly: skipInstructionDisassembly,
            skipExtraAssetCatalogImageProcessing: skipExtraAssetCatalogImageProcessing
          )
          let headerSize = separator.processLoadCommands()
          if headerSize > 0 {
            time("\(appId) binary \(binary.url)") {
              separator.parseObjcObjects()
            }
            separator.findStrings()
            let binaryFileSize =
              (try? binary.url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize
              ?? Int(binary.size)
            binary.treemap = separator.treemapElements(totalSize: UInt(binaryFileSize))
            let dylibInfo = separator.dylibs.map { dylibLoadCommand in
              // If the upload is not an app, dylibs are always found
              guard binary.url.pathComponents.first(where: { $0.hasSuffix(".app") }) != nil else {
                return DylibInfo(path: dylibLoadCommand.path, found: true)
              }
              if dylibLoadCommand.weak {
                // Weak imports are always considered found because the app can launch without them
                return DylibInfo(path: dylibLoadCommand.path, found: true)
              }
              if dylibLoadCommand.path.starts(with: "/") {
                // Assume system libraries can be found
                return DylibInfo(path: dylibLoadCommand.path, found: true)
              }
              let components = dylibLoadCommand.path.split(separator: "/")
              if components.filter({ $0.hasSuffix(".framework") }).count == 1 {
                var appUrl = binary.url
                while !appUrl.lastPathComponent.isEmpty && appUrl.lastPathComponent != "/"
                  && !appUrl.lastPathComponent.hasSuffix(".app")
                {
                  appUrl = appUrl.deletingLastPathComponent()
                }
                var frameworkPath = components.suffix(2).joined(separator: "/")
                if binary.url.path().contains(".app/Contents/") {
                  appUrl = appUrl.appendingPathComponent("Contents")
                  frameworkPath = components.suffix(4).joined(separator: "/")
                }
                let frameworkUrl = appUrl.appending(path: "Frameworks/\(frameworkPath)")
                let found = FileManager.default.fileExists(
                  atPath: frameworkUrl.path(percentEncoded: false)
                )
                if !found {
                  logger.warning("Error finding framework \(frameworkUrl)")
                }
                return DylibInfo(path: dylibLoadCommand.path, found: found)
              }
              // Default to found
              return DylibInfo(path: dylibLoadCommand.path, found: true)
            }
            let staticInitializers = dyldInfo(binaryPath: binary.url.path(percentEncoded: false))
            staticInits.append(
              StaticInits(
                binaryName: binary.name,
                binaryPath: binary.url.appRelativePath,
                staticInitializers: staticInitializers
              )
            )
            dylbs.append(
              Dylibs(
                binaryName: binary.name,
                binaryPath: binary.url.appRelativePath,
                dylibs: dylibInfo
              )
            )
            protocols.formUnion(separator.protocols)
            protocolConformed.formUnion(separator.protocolConformed)
            largeObjcStrings.append(
              contentsOf: separator.objcTypeStrings.values.map {
                LargeString(string: $0, size: UInt64($0.count), binaryName: binary.name)
              }.filter { $0.size > 1000 }
            )
            largeOtherStrings.append(
              contentsOf: separator.largeOtherStrings.map {
                LargeString(cString: $0, binaryName: binary.name)
              }
            )
            previewProviders.append(contentsOf: separator.previewProviders)
            let relativePath = binary.url.relativePath
            // Tries for dylibs shouldn't be stripped, and it's unclear if it's safe to strip tries for the watch app
            if !relativePath.starts(with: "/Watch/") && binary.url.isExecutable {
              separator.classRangeMap.forEachRange { start, size, tag in
                switch tag {
                case .dyld(let dyldType):
                  switch dyldType {
                  case .exports:
                    if size > Constants.minimumExportsSize {
                      binaryTries.append(
                        ResultErrorType.TrieDetails(saveableSize: size, url: binary.url)
                      )
                    }
                  default: break
                  }
                default: break
                }
              }
            }
          }
        }
        // Strip the binary and measure how much could be saved (Skipping Watch apps)
        if !binary.url.appRelativePath.starts(with: "/Watch/") {
          let strippedSavings = (try? BinaryStrip.strip(url: binary.url, hasBitcode: false)) ?? 0
          if strippedSavings > minStrippedSavings {
            binaryStrips.append(.init(saveableSize: strippedSavings, url: binary.url))
          }
        }
      }
    }
    let binaryTriesError: ResultError?
    if !binaryTries.isEmpty {
      binaryTriesError = .init(trieDetails: binaryTries)
    } else {
      binaryTriesError = nil
    }

    let unconformed = protocols.subtracting(protocolConformed)
    let binaryStripError: ResultError?
    if !binaryStrips.isEmpty {
      binaryStripError = .init(binaryStrip: binaryStrips)
    } else {
      binaryStripError = nil
    }

    let appStoreInstallSize = try FileManager.default.appStoreSizeOfDirectory(at: rootURL)

    var optimizeImagesArray = [OptimizeImage]()
    var optimizeIconsArray = [OptimizeImage]()
    var optimizedImagesCacheEntry = [String: CachedOptimizedMediaResults.OptimizedImage]()
    let rawImages = folder.rawImages
    let rawImageErrors = ResultError(rawImage: .init(groups: rawImages))
    let imagesCache = ImagesCache(
      userId: userId,
      appId: plistData.appId,
      imageOptimizing: imageOptimizing,
      supportsHEIC: plistData.supportsHEIC
    )

    time("\(appId) InitialImages") {
      let allImages = folder.images
      for image in allImages {
        // HACK for reddit animated png
        guard image.name != "starburst.png" && image.name != "starburst@2x.png" else { continue }

        let saveableSize = imagesCache.readOptimizedImageCache(
          image.hashValue,
          originalSize: image.size,
          path: image.relativePath
        ) {
          imageOptimizing.optimize(file: image, supportsHEIC: imagesCache.supportsHEIC)
        }
        optimizedImagesCacheEntry[image.hashValue] =
          .init(
            hash: image.hashValue,
            optimizeResults: .init(
              inFormatSavings: saveableSize.inFormatSavings,
              modernFormatSavings: saveableSize.newFormatSavings
            ),
            url: saveableSize.awsPath
          )
        if max(saveableSize.inFormatSavings ?? 0, saveableSize.newFormatSavings ?? 0) > 0 {
          optimizeImagesArray.append(saveableSize)
        }
      }
    }

    var assetMap = [KeyInApp: [(UInt, String)]]()
    let previewAssetHelper = PreviewAssetHelper(previewsEnabled, uploadAllPreviews)

    time("\(appId) AssetCatalogs") {
      var duplicateAssetMap = [KeyInApp: Bool]()
      var catalogsAssets = [String: [AssetCatalogEntry]]()

      // Pre process asset catalogs
      for catalog in folder.assetCatalogs {
        guard catalogsAssets[catalog.hashValue] == nil else { continue }

        let assets = AssetUtil.disect(
          file: catalog.url
        )
        catalogsAssets[catalog.hashValue] = assets
      }

      if !skipExtraAssetCatalogImageProcessing {
        // Search biggest images for previews
        let assetsToUpload = folder.assetCatalogs.flatMap { catalogsAssets[$0.hashValue]! }.sorted(
          by: {
            $0.size > $1.size
          })
        for asset in assetsToUpload {
          // Keys are SHA256 in AssetCatalogReader, safe to assume there is no unwanted colission
          guard let assetKey = asset.key,
            let cgImage = asset.cgImage
          else {
            continue
          }

          previewAssetHelper.addNewImage(assetKey: assetKey, cgImage: cgImage)

          if previewAssetHelper.shouldStopAddingAssets() {
            // We have already added the max number of images, exit
            break
          }
        }
      }

      let iconsWithCatalogs = folder.assetCatalogs.compactMap { catalog in
        catalogsAssets[catalog.hashValue]?.compactMap { asset in
          asset.type == .icon ? (catalog, asset) : nil
        }
      }.flatMap { $0 }
      // Ignore this filter for the main icon which needs to render on the AppStore
      for (catalog, icon) in iconsWithCatalogs where icon.originalName != plistData.primaryIconName
      {
        if let saveableSize = imagesCache.readOptimizedIcon(icon, catalog: catalog) {
          if max(saveableSize.inFormatSavings ?? 0, saveableSize.newFormatSavings ?? 0) > 0 {
            optimizeIconsArray.append(saveableSize)
          }
        }
      }

      // Analyze assets
      var alreadyAnalyzedCatalogs = [String: Bool]()
      for catalog in folder.assetCatalogs {
        guard alreadyAnalyzedCatalogs[catalog.hashValue] == nil,
          let assets = catalogsAssets[catalog.hashValue]
        else { continue }

        alreadyAnalyzedCatalogs[catalog.hashValue] = true

        // Create the duplicate image map
        for asset in assets {
          guard let key = asset.key else { continue }
          let keyInApp = KeyInApp(key: key, path: catalog.path)
          var existingArray = assetMap[keyInApp] ?? []
          let path = asset.url(in: catalog).relativePath
          existingArray.append((asset.size, path))
          assetMap[keyInApp] = existingArray
        }

        // Determine savings from image optimization, ignore icons
        for asset in assets where asset.type != .icon {
          if let key = asset.key,
            let saveableSize = imagesCache.readOptimizedImageCache(asset, catalog: catalog)
          {
            optimizedImagesCacheEntry[key] =
              .init(
                hash: key,
                optimizeResults: .init(
                  inFormatSavings: saveableSize.inFormatSavings,
                  modernFormatSavings: saveableSize.newFormatSavings
                ),
                url: saveableSize.awsPath
              )
            if max(saveableSize.inFormatSavings ?? 0, saveableSize.newFormatSavings ?? 0) > 0 {
              optimizeImagesArray.append(saveableSize)
            }
          }
        }

        // Mark images in catalog as duplicate for visualization
        let markedDuplicateAssets = assets.map { assetCatalogEntry -> Asset in
          var previewKey: String? = nil
          if let assetKey = assetCatalogEntry.key {
            previewKey = previewAssetHelper.getPreviewKeyFor(assetKey: assetKey)
          }

          let asset = Asset(
            size: assetCatalogEntry.size,
            key: assetCatalogEntry.key,
            originalName: assetCatalogEntry.originalName,
            name: assetCatalogEntry.name,
            vector: assetCatalogEntry.vector,
            width: assetCatalogEntry.width,
            height: assetCatalogEntry.height,
            previewKey: previewKey
          )
          guard let key = asset.key else { return asset }

          let keyInApp = KeyInApp(key: key, path: catalog.path)
          if duplicateAssetMap[keyInApp] != nil {
            asset.isDuplicate = true
          } else {
            duplicateAssetMap[keyInApp] = true
          }
          return asset
        }

        catalog.assets = markedDuplicateAssets
      }
    }

    for (key, value) in assetMap {
      if let size = value.first {
        // Add a duplicate error
        var existingErrors = (errors[key] ?? [])
        let duplicateError = ResultErrorType.Duplicates(
          individualSize: size.0,
          paths: value.map { $0.1 },
          files: nil
        )
        existingErrors.append(duplicateError)
        errors[key] = existingErrors
      }
    }

    let duplicateError = ResultError(duplicates: errors.values.flatMap { $0 })

    let strings = folder.strings
    var stringOpportunities = [CommentsInStrings]()
    var totalSavingsCount: UInt = 0
    for string in strings {
      if string.size == 0 {
        continue
      }

      let fileURL = URL(fileURLWithPath: string.path)
      let lastComponent = fileURL.deletingPathExtension().lastPathComponent
      let newFileURL = fileURL.deletingLastPathComponent().appendingPathComponent(
        "\(lastComponent)-Test"
      )
      guard let stringDictionary = NSDictionary(contentsOf: URL(fileURLWithPath: string.path))
      else {
        continue
      }
      var newString = ""
      for (key, value) in stringDictionary {
        newString.append("\"\(key)\"=\"\(value)\"\n")
      }
      do {
        try newString.write(to: newFileURL, atomically: true, encoding: .utf8)
        if let newTotalSize = try newFileURL.resourceValues(forKeys: [.totalFileAllocatedSizeKey])
          .totalFileAllocatedSize, newTotalSize <= string.value
        {
          let sizeDiff = string.value - UInt(newTotalSize)
          totalSavingsCount += sizeDiff
          if sizeDiff > 0 {
            stringOpportunities.append(.init(path: string.path, saveableSize: sizeDiff))
          }
        }
      } catch {
        logger.error("Got an error \(error)")
      }
      try? FileManager.default.removeItem(at: newFileURL)
    }
    let stringErrors = ResultError(strings: stringOpportunities)

    time("\(appId) PreviewAssetsUpload") {
      guard
        previewsEnabled
      else {
        logger.info("Skipping preview assets uploads")
        return
      }

      let uploadS3Key = s3Key.components(separatedBy: "/").last!

      for previewAssetPath in Array(previewAssetHelper.previewAssets.values) {
        _ = try? s3Client.upload(
          bucket: previewsBucketName,
          key: uploadS3Key,
          localFile: previewAssetPath
        )
      }
    }

    time("\(appId) ImageUpload") {
      optimizeImagesArray.sort(by: >)
      let imagesArrayToUpload =
        uploadAllOptimizedImages ? optimizeImagesArray : Array(optimizeImagesArray.prefix(20))
      for image in imagesArrayToUpload {
        if let optimizedURL = image.optimizedFileURL, image.awsPath == nil {
          let awsPath = try? s3Client.upload(
            bucket: optimizedBucketName,
            key: s3Key,
            localFile: optimizedURL
          )
          image.awsPath = awsPath
          if let cacheEntry = optimizedImagesCacheEntry[image.hash ?? ""] {
            optimizedImagesCacheEntry[image.hash ?? ""] =
              CachedOptimizedMediaResults.OptimizedImage(
                hash: cacheEntry.hash,
                optimizeResults: cacheEntry.optimizeResults,
                url: awsPath
              )
          }
        }
      }
    }
    let optimizeImageError: ResultError?
    if !optimizeImagesArray.isEmpty {
      optimizeImageError = .init(
        optimizeImages: optimizeImagesArray,
        s3BucketName: optimizedBucketName,
        s3Key: s3Key
      )
    } else {
      optimizeImageError = nil
    }

    var optimizedVideos = [OptimizeVideo]()
    let videoCompressor = VideoCompressor()
    time("\(appId) VideoCompress") {
      // Disable Video Compression unless we enable with from backend flags
      guard uploadAllOptimizedVideos else {
        return
      }

      for videoFile in folder.videos {
        // Ignore small videos...
        guard videoFile.value > 1_000_000 else { continue }

        let videoURL = URL(fileURLWithPath: videoFile.path)
        let result = try? videoCompressor.getSavings(
          for: videoURL,
          supportsHEVC: plistData.supportsHEIC
        )

        if let result = result {
          let optimizedVideo = OptimizeVideo(
            hash: videoFile.hashValue,
            savings: result.savings,
            encoding: result.encoding,
            originalSize: videoFile.size,
            path: videoFile.relativePath,
            optimizedFileURL: result.fileURL
          )
          optimizedVideos.append(optimizedVideo)
        }
      }
    }
    optimizedVideos.sort(by: { $0.savings > $1.savings })
    time("\(appId) VideoUpload") {
      for video in optimizedVideos {
        if let fileURL = video.optimizedFileURL, video.awsUri == nil {
          let awsUri = try? s3Client.upload(
            bucket: optimizedBucketName,
            key: s3Key,
            localFile: fileURL
          )
          video.awsUri = awsUri
        }
      }
    }

    let optimizedVideosError = ResultError(
      optimizeVideos: optimizedVideos,
      s3BucketName: optimizedBucketName,
      s3Key: s3Key
    )

    var optimizedAudioCacheEntry = [String: CachedOptimizedMediaResults.OptimizedAudio]()
    var optimizeAudioErrors = [OptimizeAudio]()
    time("\(appId) AudioCompress") {
      for audioFile in folder.audio {
        guard audioFile.value > 10000 else { continue }

        let results = readOptimizedAudioCache(audioFile)
        optimizedAudioCacheEntry[audioFile.hashValue] = .init(
          hash: audioFile.hashValue,
          savings: results.saveableSize,
          url: results.awsPath
        )
        if results.saveableSize > 0 {
          optimizeAudioErrors.append(results)
        }
      }
    }
    optimizeAudioErrors.sort(by: { $0.saveableSize > $1.saveableSize })
    time("\(appId) AudioUpload") {
      for audio in optimizeAudioErrors.prefix(10) {
        if let fileURL = audio.optimizedFileURL, audio.awsPath == nil {
          let awsPath = try? s3Client.upload(
            bucket: optimizedBucketName,
            key: s3Key,
            localFile: fileURL
          )
          if let cacheEntry = optimizedAudioCacheEntry[audio.hash] {
            optimizedAudioCacheEntry[audio.hash] =
              CachedOptimizedMediaResults.OptimizedAudio(
                hash: cacheEntry.hash,
                savings: cacheEntry.savings,
                url: cacheEntry.url
              )
          }
          audio.awsPath = awsPath
        }
      }
    }
    let optimizeAudio = ResultError(
      optimizeAudio: optimizeAudioErrors,
      s3BucketName: optimizedBucketName,
      s3Key: s3Key
    )

    time("\(appId) IconsUpload") {
      optimizeIconsArray.sort(by: >)
      let iconsArrayToUpload =
        uploadAllOptimizedImages ? optimizeIconsArray : Array(optimizeIconsArray.prefix(20))
      for image in iconsArrayToUpload {
        if let optimizedURL = image.optimizedFileURL, image.awsPath == nil {
          let awsPath = try? s3Client.upload(
            bucket: optimizedBucketName,
            key: s3Key,
            localFile: optimizedURL
          )
          image.awsPath = awsPath
        }
      }
    }
    let optimizeIconsError: ResultError?
    if !optimizeIconsArray.isEmpty {
      optimizeIconsError = .init(
        optimizeAlternateIcons: optimizeIconsArray,
        s3BucketName: optimizedBucketName,
        s3Key: s3Key
      )
    } else {
      optimizeIconsError = nil
    }

    // Uncomment this to generate the updated media cache
    //    if let userId = userId {
    //      let cacheResults = CachedOptimizedMediaResults(
    //        userId: String(userId),
    //        appId: plistData.appId,
    //        optimizedImages: Array(optimizedImagesCacheEntry.values),
    //        optimizedAudio: Array(optimizedAudioCacheEntry.values))
    //      let encoder = JSONEncoder()
    //      encoder.outputFormatting = .prettyPrinted
    //      let data = try encoder.encode(cacheResults)
    //      logger.debug(String(data: data, encoding: .utf8)!)
    //    }

    let localizedStringsTotalSize = folder.simpleLocalizedStrings.map { Int($0.contentsSize) }
      .reduce(0, +)
    let localizedStringsFileCount = folder.simpleLocalizedStrings.count

    var swiftUIPreviewModules = [String: Set<String>]()
    previewProviders.forEach {
      swiftUIPreviewModules[$0.0] = Set((swiftUIPreviewModules[$0.0] ?? []) + [$0.1])
    }
    let swiftUIDiagnostic = ResultDiagnostic(
      previewProviders: swiftUIPreviewModules.keys.map {
        ResultDiagnostic.ModuleProtocols(moduleName: $0, protocols: swiftUIPreviewModules[$0]!)
      }
    )
    let stringsDiagnostic = ResultDiagnostic(
      objcType: largeObjcStrings,
      otherString: largeOtherStrings
    )
    let smallFilesDiagnostic = ResultDiagnostic(
      smallFiles: folder.smallFiles,
      allFiles: folder.allFiles
    )
    let localizedStringsDiagnostic = ResultDiagnostic(
      localizedStringsTotalSize: localizedStringsTotalSize,
      localizedStringsFileCount: localizedStringsFileCount
    )
    let staticInitsDiagnostic = ResultDiagnostic(staticInitializers: staticInits)

    var obsoleteFrameworks = [ObsoleteFramework]()
    if let minOSMajorVersion = Int(plistData.minOS.components(separatedBy: ".").first ?? "0") {
      let obsoleteFrameworkMap = Dictionary(
        uniqueKeysWithValues: Self.obsoleteFrameworks.map { ($0.name, $0) }
      )
      for framework in folder.frameworks {
        if let result = obsoleteFrameworkMap[framework.name],
          minOSMajorVersion >= result.obsoletedVersion
        {
          obsoleteFrameworks.append(.init(record: result, size: UInt64(framework.size)))
        }
      }
    }
    var moduleToProtocols = [String: [String]]()
    unconformed.forEach {
      let components = $0.split(separator: ".")

      guard let module = components.first else { return }

      let protocolName = components.dropFirst().joined(separator: ".")

      moduleToProtocols[String(module)] = (moduleToProtocols[String(module)] ?? []) + [protocolName]
    }
    var diagnosticProtocols = moduleToProtocols.keys.map {
      ResultDiagnostic.ModuleProtocols(moduleName: $0, protocols: moduleToProtocols[$0]!)
    }
    diagnosticProtocols.sort { $0.protocols.count > $1.protocols.count }
    let unconformedProtocols = ResultDiagnostic(protocols: diagnosticProtocols)

    let wholeAppDownloadSize: UInt = time("\(appId) DownloadSize") {
      calculateDownloadSizeForBundle(rootURL) ?? 0
    }

    var subproducts: [Subproduct] = []

    time("\(appId) WatchApp Size Analysis") {
      if let watchProduct = WatchAppSubproductHelper.createSubproduct(rootURL) {
        subproducts.append(watchProduct)
      }
    }

    return try .init(
      size: .init(
        mainApp: .init(installSize: appStoreInstallSize, downloadSize: wholeAppDownloadSize)
      ),
      app: folder,
      plistData: plistData,
      opportunities: [
        fileNameErrors, optimizeImageError, duplicateError, rawImageErrors, binaryTriesError,
        binaryStripError, stringErrors, optimizeAudio, optimizeIconsError, optimizedVideosError,
      ].compactMap { $0 }.sorted(by: >),
      // Keep unconformedProtocols at end of diagnostics due to https://github.com/EmergeTools/emerge/pull/182#discussion_r738684014
      diagnostics: [
        localizedStringsDiagnostic, stringsDiagnostic, smallFilesDiagnostic,
        ResultDiagnostic(frameworks: obsoleteFrameworks), unconformedProtocols, swiftUIDiagnostic,
        staticInitsDiagnostic,
      ].compactMap { $0 },
      dylibs: dylbs,
      subproducts: subproducts,
      hasBitcode: hasBitcode
    )
  }

  private func readOptimizedAudioCache(_ audio: AnyFile) -> OptimizeAudio {
    let saveableSize: UInt
    let fileURL: URL?
    let uploadURL: String?
    let audioFilePath = URL(fileURLWithPath: audio.path)
    if let userId = userId,
      let cacheResult = cache.get(userId: userId, appId: plistData.appId),
      let audioResult = cacheResult.audio[audio.hashValue]
    {
      saveableSize = audioResult.savings ?? 0
      fileURL = nil
      uploadURL = audioResult.url
    } else {
      let results = try? AudioCompressor.getSavings(for: audioFilePath)
      saveableSize = results?.0 ?? 0
      fileURL = results?.1
      uploadURL = nil
    }
    return .init(
      hash: audio.hashValue,
      path: audioFilePath.relativePath,
      optimizedFileURL: fileURL,
      saveableSize: saveableSize,
      awsPath: uploadURL
    )
  }

  private func duplicateFileCheck(_ folder: Folder) {
    let allFilesMap = generateAllFilesMap(input: folder).filter { key, value in value.count > 1 }
    let allFoldersMap = generateAllFoldersMap(input: folder).filter { key, value in value.count > 1
    }
    var allFilesMapKey = [KeyInApp: [File]]()
    for (key, value) in allFilesMap {
      for file in value {
        let keyInApp = KeyInApp(key: key, path: file.path)
        allFilesMapKey[keyInApp] = (allFilesMapKey[keyInApp] ?? []) + [file]
      }
    }
    allFilesMapKey = allFilesMapKey.filter { _, fileArray in
      let isAppIntentVersionFile =
        fileArray.filter { file in
          file.path.contains(".lproj/nlu.appintents/") && file.name.hasSuffix(".version")
        }.count == fileArray.count
      return fileArray.count > 1 && !isAppIntentVersionFile
    }
    var allFoldersMapKey = [KeyInApp: [Folder]]()
    for (key, value) in allFoldersMap {
      for folder in value {
        let keyInApp = KeyInApp(key: key, path: folder.path)
        allFoldersMapKey[keyInApp] = (allFoldersMapKey[keyInApp] ?? []) + [folder]
      }
    }
    allFoldersMapKey = allFoldersMapKey.filter({ _, folderArray in
      folderArray.count > 1
    })
    let solution = folder.solutionV3(fileMap: allFilesMapKey, folderMap: allFoldersMapKey)
    for (key, value) in solution {
      if value.count > 1 {
        if !(value.first?.path ?? "").contains("SC_Info") {
          errors[key] = [
            .init(
              individualSize: value.first!.size,
              paths: value.map { URL(fileURLWithPath: $0.path).relativePath },
              files: value
            )
          ]
        }
      }
    }
  }

  private func generateAllFoldersMap(input: Folder) -> [String: [Folder]] {
    var map = [String: [Folder]]()
    var duplicateCheckQueue = [File]()
    duplicateCheckQueue.append(contentsOf: input.files)
    while !duplicateCheckQueue.isEmpty {
      let file = duplicateCheckQueue.removeFirst()
      if let folder = file as? Folder {
        var initial = map[file.hashValue] ?? []
        initial.append(folder)
        map[file.hashValue] = initial
        duplicateCheckQueue.append(contentsOf: folder.files)
      }
    }
    return map
  }

  private func generateAllFilesMap(input: Folder) -> [String: [File]] {
    var map = [String: [File]]()
    var duplicateCheckQueue = [File]()
    duplicateCheckQueue.append(contentsOf: input.files)
    while !duplicateCheckQueue.isEmpty {
      let file = duplicateCheckQueue.removeFirst()
      if let folder = file as? Folder {
        duplicateCheckQueue.append(contentsOf: folder.files)
      } else {
        var initial = map[file.hashValue] ?? []
        initial.append(file)
        map[file.hashValue] = initial
      }
    }
    return map
  }

  private func checkForBitcode(url: URL) throws -> Bool {
    var hasBitcode = false
    let data = try NSData(contentsOf: url, options: .alwaysMapped)
    data.bytes.processLoadComands { command, pointer in
      if command.cmd == LC_SEGMENT_64 {
        let segment = pointer.load(as: segment_command_64.self)
        if Name(tuple: segment.segname).string == "__LLVM" {
          hasBitcode = true
          return false
        }
      }
      return true
    }
    return hasBitcode
  }

  private enum Error: Swift.Error {
    case invalidFileType
  }

  private let logger: Logger
  private let bundle: FileType
  static let invalidFileNames = [
    "^README",
    "^CHANGELOG",
    "^AUTHORS",
    "^CONTRIBUTING",
    "^*\\.sh$",
    "^*\\.mobileprovision$",
    "^*\\.bazel$",
    "^*\\.xcconfig$",
    "^*\\.swiftmodule$",
    "^module.modulemap$",
    "^*\\.bcsymbolmap$",
    "^exported_symbols$",
    "^*\\.pch$",
    "^*\\.xctestplan",
  ]

  static let invalidFilePaths = [
    "^*.framework/Headers*",
    "^*.framework/PrivateHeaders*",
  ]

  static let obsoleteFrameworks: [ObsoleteFrameworkRecord] = [
    .init(name: "ISO8601DateFormatter.framework", obsoletedVersion: 10)
  ]
}

extension Folder {
  var binaries: [Binary] {
    files.flatMap { file -> [Binary] in
      if let folder = file as? Folder {
        return folder.binaries
      }
      if let binary = file as? Binary {
        return [binary]
      }
      return []
    }
  }

  // Strings files of the form <bundle path>/*.lproj/Localizable.strings
  var simpleLocalizedStrings: [File] {
    var stringsFiles: [File] = []
    for file in files {
      if file.path.hasSuffix(".lproj"), let folder = file as? Folder {
        for stringsFile in folder.files {
          if stringsFile.path.hasSuffix("/Localizable.strings") {
            stringsFiles.append(stringsFile)
          }
        }
      }
    }
    return stringsFiles
  }

  var assetCatalogs: [AssetCatalog] {
    var results = [AssetCatalog]()
    var allFiles: [File] = files
    while !allFiles.isEmpty {
      let file = allFiles.removeFirst()
      if let folder = file as? Folder {
        allFiles.append(contentsOf: folder.files)
      }
      if let catalog = file as? AssetCatalog {
        results.append(catalog)
      }
    }
    return results
  }

  var invalidFileNames: [File] {
    files.flatMap { file -> [File] in
      for invalidName in BundleAnalyzer.invalidFileNames {
        if file.name.range(of: invalidName, options: .regularExpression) != nil {
          return [file]
        }
      }
      for invalidPath in BundleAnalyzer.invalidFilePaths {
        if file.path.range(of: invalidPath, options: .regularExpression) != nil {
          return [file]
        }
      }
      if let folder = file as? Folder {
        return folder.invalidFileNames
      }
      return []
    }
  }
}

extension AnyFolder {

  var audio: [AnyFile] {
    contents.flatMap { fileType -> [AnyFile] in
      switch fileType {
      case .folder(let folder):
        return folder.audio
      case .image:
        return []
      case .strings:
        return []
      case .anyFile(let file):
        if file.path.hasSuffix(".caf") || file.path.hasSuffix(".wav") || file.path.hasSuffix(".mp3")
        {
          return [file]
        }
        return []
      case .assetCatalog:
        return []
      case .binary:
        return []
      case .video:
        return []
      }
    }
  }

  // All images not in asset catalogs
  var images: [AnyFile] {
    contents.flatMap { fileType -> [AnyFile] in
      switch fileType {
      case .folder(let folder):
        return folder.images
      case .image(let image):
        return [image]
      case .strings:
        return []
      case .anyFile:
        return []
      case .assetCatalog:
        return []
      case .binary:
        return []
      case .video:
        return []
      }
    }
  }

  // All nib
  var nibs: [AnyFile] {
    contents.flatMap { fileType -> [AnyFile] in
      switch fileType {
      case .anyFile(let file):
        if file.path.hasSuffix(".nib") {
          return [file]
        } else {
          return []
        }
      case .folder(let folder):
        return folder.nibs
      default:
        return []
      }
    }
  }

  // All strings
  var strings: [AnyFile] {
    contents.flatMap { fileType -> [AnyFile] in
      switch fileType {
      case .folder(let folder):
        return folder.strings
      case .image:
        return []
      case .strings(let strings):
        return [strings]
      case .anyFile:
        return []
      case .assetCatalog:
        return []
      case .binary:
        return []
      case .video:
        return []
      }
    }
  }

  var videos: [AnyFile] {
    contents.flatMap { fileType -> [AnyFile] in
      switch fileType {
      case .folder(let folder):
        return folder.videos
      case .image:
        return []
      case .strings:
        return []
      case .anyFile:
        return []
      case .assetCatalog:
        return []
      case .binary:
        return []
      case .video(let video):
        return [video]
      }
    }
  }

  // The images not in asset catalogs that should be moved
  var rawImages: [ResultErrorType.RawImageGroup] {
    let subfolders = contents.flatMap { file -> [ResultErrorType.RawImageGroup] in
      if case let .folder(folder) = file, !folder.name.hasSuffix(".stickerpack") {
        return folder.rawImages
      }
      return []
    }

    let imageFiles = contents.compactMap { file -> AnyFile? in
      if case let .image(image) = file {
        guard !image.name.starts(with: "AppIcon") && !image.name.starts(with: "iMessage App Icon")
        else { return nil }

        return image
      }
      return nil
    }

    var imageGroups = [String: [AnyFile]]()
    for image in imageFiles {
      let simpleName = image.name.canonicalImageName()
      var files = imageGroups[simpleName] ?? []
      files.append(image)
      imageGroups[simpleName] = files
    }
    let rawImages = imageGroups.values.map { ResultErrorType.RawImageGroup(images: $0) }
    return rawImages + subfolders
  }
}

extension String {
  func canonicalImageName() -> String {
    guard let endIndex = lastIndex(of: "@") ?? lastIndex(of: "~") else {
      return URL(fileURLWithPath: self).deletingPathExtension().lastPathComponent
    }
    return String(self[startIndex..<endIndex])
  }
}

// When we calculate duplicates we need to
struct KeyInApp: Hashable {
  init(key: String, path: String) {
    self.key = key
    if let lastApp = path.range(of: ".app/", options: .backwards) {
      appPath = String(path[path.startIndex..<lastApp.upperBound])
    } else {
      // For framework uploads
      appPath = ""
    }
  }
  let key: String
  let appPath: String

}

extension Folder {

  var smallFiles: [File] {
    let fileMin = 4096
    var files = [File]()
    for file in self.files {
      if let folder = file as? Folder {
        files.append(contentsOf: folder.smallFiles)
      } else {
        if file.contentsSize < fileMin {
          files.append(file)
        }
      }
    }
    return files
  }

  var allFiles: [File] {
    var files = [File]()
    for file in self.files {
      if let folder = file as? Folder {
        files.append(contentsOf: folder.allFiles)
      } else {
        files.append(file)
      }
    }
    return files
  }

  var frameworks: [Folder] {
    var frameworks = [Folder]()
    for file in self.files {
      if let folder = file as? Folder {
        if folder.name.hasSuffix(".framework") {
          frameworks.append(folder)
        } else {
          frameworks.append(contentsOf: folder.frameworks)
        }
      }
    }
    return frameworks
  }

  // FileMap should only contain the files that have duplicates (every value has count > 1)
  // FolderMap should only contain the folders that have duplicates (every value has count > 1)
  func solutionV3(fileMap: [KeyInApp: [File]], folderMap: [KeyInApp: [Folder]])
    -> DuplicateCollection
  {
    var result = fileMap
    var resultFolders = folderMap
    for (_, value) in folderMap {
      for folder in value {
        for file in folder.files {
          let k = KeyInApp(key: file.hashValue, path: file.path)
          if file as? Folder != nil {
            resultFolders[k] = resultFolders[k]?.filter { $0.path != file.path }
          } else {
            result[k] = result[k]?.filter { $0.path != file.path }
          }
        }
      }
    }
    for (key, value) in resultFolders {
      result[key] = value
    }
    return result
  }

  // FileMap should only contain the files that have duplicates (every value has count > 1)
  // FolderMap should only contain the folders that have duplicates (every value has count > 1)
  func solutionV2(fileMap: [KeyInApp: [File]], folderMap: [KeyInApp: [Folder]])
    -> DuplicateCollection
  {
    var resultMap = fileMap
    for (key, value) in folderMap {
      // Check if grouping this entire folder together would reduce the number of duplicates
      var newMap = resultMap
      for folder in value {
        for file in folder.allFiles {
          let keyInApp = KeyInApp(key: file.hashValue, path: file.path)
          let newDuplicates = newMap[keyInApp]?.filter { $0.path != file.path } ?? []
          if newDuplicates.count == 0 {
            newMap[keyInApp] = nil
          } else {
            newMap[keyInApp] = newDuplicates
          }
        }
      }
      newMap[key] = value
      if newMap.values.allSatisfy({ $0.count > 1 }) && newMap.keys.count < resultMap.keys.count {
        // Then it's ok to merge into this folder
        resultMap = newMap
      }
    }
    return resultMap
  }
}

typealias DuplicateCollection = [KeyInApp: [File]]
