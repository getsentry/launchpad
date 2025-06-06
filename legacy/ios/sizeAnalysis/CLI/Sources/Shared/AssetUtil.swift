//
//  AssetUtil.swift
//  AppSizeAnalyzer
//
//  Created by Noah Martin on 11/19/20.
//  Copyright © 2020 Tom Doron. All rights reserved.
//

import AppKit
import Foundation
import ObjcSupport

typealias objectiveCMethodImp = @convention(c) (AnyObject, Selector, UnsafeRawPointer) -> Unmanaged<
  AnyObject
>?

private class PackedAsset {
  var packedSize: UInt
  var packedItemSizes: [UInt] = []

  init(packedSize: UInt, packedItemSizes: [UInt]) {
    self.packedSize = packedSize
    self.packedItemSizes = packedItemSizes
  }
}

final class AssetUtil {
  static func process(file: URL) {
    let process = Process()
    process.launchPath = "/usr/bin/xcrun"
    process.arguments = [
      "assetutil", "-i", "phone", "-s", "3", "-p", "P3", "-M", "4", "-g", "MTL6,1", "-r", "13.0",
      file.path,
    ]
    process.standardOutput = nil
    process.standardError = nil
    try? process.run()
    process.waitUntilExit()
  }

  static func disect(file: URL) -> [AssetCatalogEntry] {
    var assets: [AssetCatalogEntry] = []
    var colorLength: UInt = 0
    var colorCount: Int = 0
    var packedAssets: [String: PackedAsset] = [:]

    let (structuredThemeStore, assetKeys) = initializeCatalog(from: file)

    for key in assetKeys {
      let keyList = unsafeBitCast(
        key.perform(Selector(("keyList"))),
        to: UnsafeMutableRawPointer.self
      )
      let rendition = createRendition(from: structuredThemeStore, keyList)

      let data = rendition.value(forKey: "_srcData") as! Data
      let length = UInt(data.count)
      let className = rendition.perform(Selector(("className"))).takeUnretainedValue() as! String
      let keyValue = getKeyValue(from: rendition, className, data)
      let renditionTypeName =
        rendition.perform(Selector(("name"))).takeUnretainedValue() as! String

      if renditionTypeName.hasPrefix("ZZZZPacked") {
        guard let keyValue = keyValue else { continue }
        let packedAsset = packedAssets[
          keyValue,
          default: PackedAsset(packedSize: length, packedItemSizes: [])
        ]
        packedAsset.packedSize = length
        packedAssets[keyValue] = packedAsset
        continue
      }

      if handleReferenceKey(
        rendition,
        structuredThemeStore,
        Selector(("renditionWithKey:")),
        &packedAssets,
        renditionTypeName,
        length
      ) {
        continue
      }

      if className == "_CUIThemeColorRendition" {
        colorCount += 1
        colorLength += length
        continue
      }

      let (name, originalName) = resolveRenditionName(
        structuredThemeStore,
        keyList,
        renditionTypeName
      )

      let type = rendition.getUInt(forKey: "type") ?? 0

      let isVector = type == 9
      let (width, height, unslicedImage) = resolveImageDimensions(rendition, isVector)
      let assetType = determineAssetType(key)

      let asset = AssetCatalogEntry(
        size: length,
        key: keyValue,
        originalName: originalName,
        name: name!,
        vector: isVector,
        width: width,
        height: height,
        filename: renditionTypeName,
        cgImage: unslicedImage,
        type: assetType
      )
      assets.append(asset)
    }

    return createFinalAssets(assets, packedAssets, colorCount, colorLength)
  }

  private static func initializeCatalog(from file: URL) -> (
    themeStore: NSObject, assetKeys: [NSObject]
  ) {
    let catalogClass: NSObject.Type = NSClassFromString("CUICatalog")! as! NSObject.Type
    var catalog: NSObject =
      catalogClass.perform(Selector(("alloc"))).takeRetainedValue() as! NSObject
    catalog =
      catalog.perform(Selector(("initWithURL:error:")), with: file as NSURL, with: nil)
      .takeRetainedValue() as! NSObject
    let structuredThemeStore =
      catalog.perform(Selector(("_themeStore"))).takeRetainedValue() as! NSObject
    let assetStorage = structuredThemeStore.perform(Selector(("themeStore"))).takeRetainedValue()
    let assetKeys =
      assetStorage.perform(Selector(("allAssetKeys"))).takeRetainedValue() as! [NSObject]
    return (structuredThemeStore, assetKeys)
  }

  private static func createRendition(from themeStore: NSObject, _ keyList: UnsafeMutableRawPointer)
    -> NSObject
  {
    let renditionWithKeySelector = Selector(("renditionWithKey:"))
    let renditionWithKeyMethod = themeStore.method(for: renditionWithKeySelector)!
    let renditionWithKeyImp = unsafeBitCast(renditionWithKeyMethod, to: objectiveCMethodImp.self)
    return renditionWithKeyImp(themeStore, renditionWithKeySelector, keyList)!.takeRetainedValue()
      as! NSObject
  }

  private static func getKeyValue(from rendition: NSObject, _ className: String, _ data: Data)
    -> String?
  {
    if let unslicedImage = rendition.perform(Selector(("unslicedImage"))) {
      let image = unslicedImage.takeUnretainedValue() as! CGImage
      return (image.dataProvider?.data as? Data)?.sha256()
    } else if className == "_CUIThemePDFRendition" {
      return data.sha256()
    }
    return nil
  }

  private static func handleReferenceKey(
    _ rendition: NSObject,
    _ themeStore: NSObject,
    _ renditionWithKeySelector: Selector,
    _ packedAssets: inout [String: PackedAsset],
    _ renditionTypeName: String,
    _ length: UInt
  ) -> Bool {
    let referenceKey = safeValueForKey(rendition, "_referenceKey")
    guard let referenceKey = referenceKey as? NSObject else { return false }

    let referenceKeyList = unsafeBitCast(
      referenceKey.perform(Selector(("keyList"))),
      to: UnsafeMutableRawPointer.self
    )
    let referenceRendition = createRendition(from: themeStore, referenceKeyList)

    if let result = referenceRendition.perform(Selector(("unslicedImage"))) {
      let image = result.takeUnretainedValue() as! CGImage
      guard let referencedKeyValue = (image.dataProvider?.data as? Data)?.sha256() else {
        return true
      }
      let packedAsset = packedAssets[
        referencedKeyValue,
        default: PackedAsset(packedSize: 0, packedItemSizes: [])
      ]
      packedAsset.packedItemSizes.append(length)
      packedAssets[referencedKeyValue] = packedAsset
    }
    return true
  }

  private static func determineAssetType(_ key: NSObject) -> AssetType {
    let themeElement = key.getUInt(forKey: "themeElement") ?? 0
    let themePart = key.getUInt(forKey: "themePart") ?? 0

    if (themeElement == 85 && themePart == 220) {
      return .icon
    } else if (themeElement == 9) {
      return .imageSet
    }
    return .image
  }

  private static func resolveRenditionName(
    _ structuredThemeStore: NSObject,
    _ keyList: UnsafeMutableRawPointer,
    _ renditionTypeName: String
  ) -> (name: String?, originalName: String?) {
    let renditionNameForKeyListSelector = Selector(("renditionNameForKeyList:"))
    let renditionNameForKeyListMethod = structuredThemeStore.method(
      for: renditionNameForKeyListSelector
    )!
    let renditionNameForKeyList = unsafeBitCast(
      renditionNameForKeyListMethod,
      to: objectiveCMethodImp.self
    )

    var renditionName: String? = nil
    if let result = renditionNameForKeyList(
      structuredThemeStore,
      renditionNameForKeyListSelector,
      keyList
    ) {
      renditionName = result.takeUnretainedValue() as? String
    }

    let name = renditionTypeName == "CoreStructuredImage" ? renditionName : renditionTypeName
    return (name, renditionName)
  }

  private static func resolveImageDimensions(_ rendition: NSObject, _ isVector: Bool) -> (
    width: Int?, height: Int?, image: CGImage?
  ) {
    var unslicedImage: CGImage?
    if let result = rendition.perform(Selector(("unslicedImage"))) {
      unslicedImage = (result.takeUnretainedValue() as! CGImage)
    }

    var width: Int?
    var height: Int?
    if !isVector {
      width = unslicedImage?.width
      height = unslicedImage?.height
    }

    return (width, height, unslicedImage)
  }

  private static func createFinalAssets(
    _ assets: [AssetCatalogEntry],
    _ packedAssets: [String: PackedAsset],
    _ colorCount: Int,
    _ colorLength: UInt
  ) -> [AssetCatalogEntry] {
    var assets = assets
    if colorCount > 0 {
      let asset = AssetCatalogEntry(
        size: colorLength,
        name: "\(colorCount) Color\(colorCount > 1 ? "s" : "")"
      )
      assets.append(asset)
    }

    for packedAsset in packedAssets.values {
      let asset = AssetCatalogEntry(
        size: packedAsset.packedSize + packedAsset.packedItemSizes.reduce(0) { $0 + $1 },
        name: "Packed Asset"
      )
      assets.append(asset)
    }

    return assets.sorted { $0.size < $1.size }
  }
}

extension Compression: ImageOptimizing {
  public func optimize(file: AnyFile, supportsHEIC: Bool) -> OptimizationResult {
    var canUseHeic = supportsHEIC
    if file.path.contains(".stickerpack") {
      canUseHeic = false
    }
    if let originalSize = try? URL(fileURLWithPath: file.path).resourceValues(forKeys: [
      .fileSizeKey
    ]).fileSize {
      return
        (try? savings(
          for: URL(fileURLWithPath: file.path),
          size: UInt(originalSize),
          supportsHeic: canUseHeic
        ))
        ?? nil
    } else {
      return nil
    }
  }

  public func optimize(image: AssetCatalogEntry, supportsHEIC: Bool) -> OptimizationResult {
    guard let cgImage = image.cgImage else { return nil }

    return try? savings(
      for: image.filename ?? "",
      size: image.size,
      cgImage: cgImage,
      supportsHeic: supportsHEIC
    )
  }

  public func optimizeIcon(image: AssetCatalogEntry, supportsHEIC: Bool) -> OptimizationResult {
    guard let cgImage = image.cgImage else { return nil }

    return try? iconSavings(
      for: image.filename ?? "",
      size: image.size,
      cgImage: cgImage,
      supportsHeic: supportsHEIC
    )
  }
}

private extension NSObject {
  func getUInt(forKey key: String) -> UInt? {
    if let result = self.perform(Selector(key)) {
      return UInt(bitPattern: result.toOpaque())
    }
    return nil
  }
}
