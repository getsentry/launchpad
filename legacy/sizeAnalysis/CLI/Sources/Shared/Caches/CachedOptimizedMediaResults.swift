//
//  File.swift
//
//
//  Created by Itay Brenner on 10/10/23.
//

import Foundation

public struct CachedOptimizedMediaResults: Codable, Sendable {
  let userId: String
  let appId: String
  let optimizedImages: [OptimizedImage]
  let optimizedAudio: [OptimizedAudio]

  public struct OptimizedImage: Codable, Sendable {
    public struct OptimizedImageResults: Codable, Sendable {
      public let inFormatSavings: UInt?
      public let modernFormatSavings: UInt?

      public init(inFormatSavings: UInt?, modernFormatSavings: UInt?) {
        self.inFormatSavings = inFormatSavings
        self.modernFormatSavings = modernFormatSavings
      }
    }

    public let hash: String
    public let optimizeResults: OptimizedImageResults
    public let url: String?

    public init(hash: String, optimizeResults: OptimizedImageResults, url: String? = nil) {
      self.hash = hash
      self.optimizeResults = optimizeResults
      self.url = url
    }
  }

  public struct OptimizedAudio: Codable, Sendable {
    public let hash: String
    public let savings: UInt?
    public let url: String?

    public init(hash: String, savings: UInt?, url: String? = nil) {
      self.hash = hash
      self.savings = savings
      self.url = url
    }
  }
}
