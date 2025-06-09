//
//  ImagesCache.swift
//
//
//  Created by Itay Brenner on 10/10/23.
//

import Foundation

class ImagesCache {
  var cache = MediaCache.shared
  let userId: String?
  let appId: String
  let imageOptimizing: ImageOptimizing
  let supportsHEIC: Bool

  init(userId: String?, appId: String, imageOptimizing: ImageOptimizing, supportsHEIC: Bool) {
    self.userId = userId
    self.appId = appId
    self.imageOptimizing = imageOptimizing
    self.supportsHEIC = supportsHEIC
  }

  func readOptimizedImageCache(
    _ key: String,
    originalSize: UInt,
    path: String,
    cacheMiss: () -> ImageOptimizing.OptimizationResult
  ) -> OptimizeImage {
    let inFormatSavings: UInt?
    let modernFormatSavings: UInt?
    let fileURL: URL?
    let uploadedURL: String?
    if let userId = userId,
      let cacheResult = cache.get(userId: userId, appId: appId),
      let imageResult = cacheResult.images[key]
    {
      inFormatSavings = imageResult.optimizeResults.inFormatSavings
      modernFormatSavings = imageResult.optimizeResults.modernFormatSavings
      fileURL = nil
      uploadedURL = imageResult.url
    } else {
      let (resultInFormat, resultModernFormat, url) = cacheMiss() ?? (nil, nil, nil)
      inFormatSavings = resultInFormat
      modernFormatSavings = resultModernFormat
      fileURL = url
      uploadedURL = nil
    }

    return
      .init(
        hash: key,
        inFormatSavings: inFormatSavings,
        newFormatSavings: modernFormatSavings,
        originalSize: originalSize,
        path: path,
        optimizedFileURL: fileURL,
        awsPath: uploadedURL
      )
  }

  func readOptimizedImageCache(_ image: AssetCatalogEntry, catalog: AssetCatalog)
    -> OptimizeImage?
  {
    guard let key = image.key else { return nil }

    return readOptimizedImageCache(
      key,
      originalSize: image.size,
      path: image.url(in: catalog).relativePath
    ) {
      imageOptimizing.optimize(image: image, supportsHEIC: supportsHEIC)
    }
  }

  func readOptimizedIcon(_ image: AssetCatalogEntry, catalog: AssetCatalog)
    -> OptimizeImage?
  {
    guard let key = image.key else { return nil }

    return readOptimizedImageCache(
      "emergeicon_\(key)",
      originalSize: image.size,
      path: image.url(in: catalog).relativePath
    ) {
      imageOptimizing.optimizeIcon(image: image, supportsHEIC: supportsHEIC)
    }
  }
}
