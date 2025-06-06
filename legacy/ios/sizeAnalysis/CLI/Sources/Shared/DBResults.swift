//
//  File.swift
//
//
//  Created by Noah Martin on 11/24/20.
//

import Compression
import Foundation

public final class DBResults {
  public init(s3BucketName: String, userID: String, s3Client: AWSS3Client) {
    self.s3BucketName = s3BucketName
    self.userID = userID
    self.s3Client = s3Client
  }

  private let s3BucketName: String
  private let userID: String
  private let s3Client: AWSS3Client

  public struct Result: Encodable {

    public func encode(to encoder: Encoder) throws {
      let jsonEncoder = JSONEncoder()
      let appData = try jsonEncoder.encode(results.app).compress()
      let opportunitiesData = try jsonEncoder.encode(results.opportunities).compress()
      var diagnosticsData = try jsonEncoder.encode(results.diagnostics).compress()
      if diagnosticsData.count > 1_000_000 {
        diagnosticsData = try jsonEncoder.encode(results.diagnostics.map { $0.shrink() }).compress()
      }
      logger.info(
        "appData \(appData.count) apportunitiesData \(opportunitiesData.count) diagnosticsData \(diagnosticsData.count)"
      )

      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(uploadId, forKey: .upload_id)
      try container.encode(results.size, forKey: .app_store_file_sizes)
      try container.encode(results.appId, forKey: .app_id)
      try container.encode(results.appName, forKey: .app_name)
      try container.encode(results.appVersion, forKey: .app_version)
      try container.encode(results.appBuild, forKey: .app_build)
      try container.encode(results.totalSavings, forKey: .total_savings)
      try container.encode(results.emergeBuildMetadata, forKey: .emerge_build_metadata)
      try container.encode(opportunitiesData, forKey: .opportunities)
      try container.encode(diagnosticsData, forKey: .diagnostics)
      try container.encode(appData, forKey: .app)
      try container.encode(results.size.mainApp.installSize, forKey: .app_size)
      try container.encode(results.size.mainApp.downloadSize, forKey: .download_size)
      try container.encode(results.xcodeBuildVersion, forKey: .xcode_build_version)
      try container.encode(results.platformBuildVersion, forKey: .platform_build_version)
      try container.encode(results.buildMachineBuildVersion, forKey: .build_machine_build_version)
      try container.encode(results.dylibs, forKey: .dylibs)
      try container.encode(results.status, forKey: .status)
      try container.encode(results.subproducts, forKey: .subproducts)
      try container.encode(results.hasBitcode, forKey: .has_bitcode)
    }

    public init(uploadId: String, results: Results) {
      self.uploadId = uploadId
      self.results = results
    }

    let uploadId: String
    let results: Results

    enum CodingKeys: String, CodingKey {
      case upload_id
      case app_store_file_sizes
      case app_id
      case app_name
      case app_version
      case app_build
      case total_savings
      case emerge_build_metadata
      case app
      case opportunities
      case diagnostics
      case app_size
      case download_size
      case xcode_build_version
      case platform_build_version
      case build_machine_build_version
      case dylibs
      case status
      case subproducts
      case has_bitcode
    }
  }

  public func save(workingDirURL: URL, uploadId: String, results: Results) throws {
    let data = try JSONEncoder().encode(Result(uploadId: uploadId, results: results))
    try uploadResultsData(workingDirURL: workingDirURL, uploadId: uploadId, data: data)
  }

  public func save(workingDirURL: URL, uploadId: String, errorResults: ErrorResults) throws {
    let data = try JSONEncoder().encode(errorResults)
    try uploadResultsData(workingDirURL: workingDirURL, uploadId: uploadId, data: data)
  }

  private func uploadResultsData(workingDirURL: URL, uploadId: String, data: Data) throws {
    let directory = workingDirURL.appendingPathComponent(userID)
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: true,
      attributes: nil
    )
    let url = directory.appendingPathComponent("\(uploadId).json")
    defer {
      if FileManager.default.fileExists(atPath: url.path) {
        try? FileManager.default.removeItem(at: url)
      }
    }
    try data.write(to: url)
    _ = try s3Client.upload(bucket: s3BucketName, key: userID, localFile: url)
  }
}

extension Data {
  func compress() -> String {
    let destinationBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
    let dataArray = [UInt8](self)
    let compressedSize = compression_encode_buffer(
      destinationBuffer,
      count,
      dataArray,
      count,
      nil,
      COMPRESSION_ZLIB
    )
    let compressedData = NSData(bytesNoCopy: destinationBuffer, length: compressedSize) as Data
    return compressedData.base64EncodedString()
  }
}
