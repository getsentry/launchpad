//
//  Parameters.swift
//  AppSizeAnalyzer
//
//  Created by Itay Brenner on 16/10/23.
//  Copyright © 2023 Emerge Tools. All rights reserved.
//
import Foundation

struct Parameters: Codable {
  let s3UploadBucket: String?
  let resultsBucket: String?
  let previewsBucketName: String?
  let uploadUrl: String?
  let uploadId: String?
  let userId: String?
  let appPath: String?
  let s3Key: String?
  let output: String?
  let workingDir: String?
  let previewsEnabled: Bool?
  let uploadAllPreviews: Bool?
  let uploadAllOptimizedImages: Bool?
  let uploadAllOptimizedVideos: Bool?
  let skipSwiftMetadataParsing: Bool?
  let skipInstructionDisassembly: Bool?
  let skipExtraAssetCatalogImageProcessing: Bool?
}
