//
//  File.swift
//
//
//  Created by Itay Brenner on 2/2/24.
//

import Foundation

public struct Subproduct: Encodable {
  public enum ProductType: String, Encodable {
    case watch = "Watch"
  }

  let productType: ProductType
  let installSize: UInt
  let downloadSize: UInt
  let identifier: String
  let displayName: String
}
