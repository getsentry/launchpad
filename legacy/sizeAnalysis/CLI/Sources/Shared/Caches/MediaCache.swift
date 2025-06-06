//
//  File.swift
//
//
//  Created by Noah Martin on 4/26/21.
//

import Foundation

public final class MediaCache: Sendable {
  public func get(userId: String, appId: String) -> OptimizedResourceCache? {
    if let cache = cacheMap[userId]?[appId] {
      let images = cache.optimizedImages.map { ($0.hash, $0) }
      let audio = cache.optimizedAudio.map { ($0.hash, $0) }

      return OptimizedResourceCache(
        images: Dictionary(images, uniquingKeysWith: { lhs, _ in lhs }),
        audio: Dictionary(audio, uniquingKeysWith: { lhs, _ in lhs })
      )
    }
    return nil
  }

  public static let shared: MediaCache = {
    var cacheMap = [String: [String: CachedOptimizedMediaResults]]()
    for data in [spotifyCache, amexCache, dropboxCache, dropboxEMMCache] {
      cacheMap[data.userId] = cacheMap[data.userId] ?? [:]
      cacheMap[data.userId]?[data.appId] = data
    }
    return MediaCache(cacheMap: cacheMap)
  }()

  init(cacheMap: [String: [String: CachedOptimizedMediaResults]]) {
    self.cacheMap = cacheMap
  }

  let cacheMap: [String: [String: CachedOptimizedMediaResults]]
}

public struct OptimizedResourceCache {
  public let images: [String: CachedOptimizedMediaResults.OptimizedImage]
  public let audio: [String: CachedOptimizedMediaResults.OptimizedAudio]
}
