//
//  File.swift
//
//
//  Created by Itay Brenner on 27/8/24.
//

import Foundation

// Common saving model shared with Android
struct Savings: Encodable, Comparable {
  let installSizeSavings: UInt
  // We don't support download saving on iOS but needed for the model
  let downloadSizeSavings: Int = -1

  static func < (lhs: Savings, rhs: Savings) -> Bool {
    lhs.installSizeSavings < rhs.installSizeSavings
  }

  static func == (lhs: Savings, rhs: Savings) -> Bool {
    return lhs.installSizeSavings == rhs.installSizeSavings
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(installSizeSavings, forKey: .installSizeSavings)
    try container.encode(downloadSizeSavings, forKey: .downloadSizeSavings)
  }

  enum CodingKeys: String, CodingKey {
    case installSizeSavings
    case downloadSizeSavings
  }
}
