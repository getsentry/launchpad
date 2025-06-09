//
//  OptimizeVideo.swift
//
//
//  Created by Itay Brenner on 21/8/24.
//

import Foundation

class OptimizeVideo: Encodable, Comparable {
  let hash: String?
  let savings: Savings
  let encoding: VideoEncoding
  let originalSize: UInt
  let path: String
  let optimizedFileURL: URL?
  var awsUri: String?

  static func < (lhs: OptimizeVideo, rhs: OptimizeVideo) -> Bool {
    lhs.savings < rhs.savings
  }

  init(
    hash: String?,
    savings: UInt,
    encoding: VideoEncoding,
    originalSize: UInt,
    path: String,
    optimizedFileURL: URL?,
    awsUri: String? = nil
  ) {
    self.hash = hash
    self.savings = Savings(installSizeSavings: savings)
    self.encoding = encoding
    self.originalSize = originalSize
    self.path = path
    self.optimizedFileURL = optimizedFileURL
    self.awsUri = awsUri
  }

  static func == (lhs: OptimizeVideo, rhs: OptimizeVideo) -> Bool {
    return lhs.path == rhs.path
      && lhs.originalSize == rhs.originalSize
      && lhs.savings == rhs.savings
      && lhs.encoding == rhs.encoding
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(savings, forKey: .savings)
    try container.encode(encoding.rawValue, forKey: .encoding)
    try container.encode(originalSize, forKey: .originalSize)
    try container.encode(path, forKey: .path)
    try container.encode(awsUri, forKey: .awsUri)
  }

  enum CodingKeys: String, CodingKey {
    case savings
    case encoding
    case originalSize
    case path
    case awsUri
  }
}
