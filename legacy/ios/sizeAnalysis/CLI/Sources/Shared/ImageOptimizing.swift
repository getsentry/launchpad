//
//  File.swift
//
//
//  Created by Noah Martin on 4/28/21.
//

import Foundation

public protocol ImageOptimizing {
  typealias OptimizationResult = (
    inFormatSavings: UInt?, modernFormatSavings: UInt?, optimizedURL: URL?
  )?

  func optimize(file: AnyFile, supportsHEIC: Bool) -> OptimizationResult

  func optimize(image: AssetCatalogEntry, supportsHEIC: Bool) -> OptimizationResult

  func optimizeIcon(image: AssetCatalogEntry, supportsHEIC: Bool) -> OptimizationResult
}
