//
//  main.swift
//  AppSizeAnalyzer
//
//  Created by Noah Martin on 11/9/20.
//

import ArgumentParser
import CwlDemangle
import Foundation
import Shared

struct Analyze: ParsableCommand {
  @Option(help: "The name of the S3 that stores uploads")
  var s3UploadBucket: String?

  @Option(help: "The name of the S3 that stores analysis results")
  var s3AnalysisResultsBucket: String?

  @Option(help: "The name of the S3 that stores previews")
  var previewsBucketName: String?

  @Option(help: "The url of the upload")
  var uploadUrl: String?

  @Option(help: "The upload id")
  var uploadId: String?

  @Option(help: "The user id")
  var userId: String?

  @Option(help: "The app bundle")
  var appPath: String?

  @Option(help: "The s3 key")
  var s3Key: String?

  @Option(help: "The json result path")
  var output: String?

  @Option(help: "Directory to use for files")
  var workingDir: String?

  @Option(help: "Path to params json")
  var params: String?

  @Option(help: "Upload all optimized images after processing")
  var uploadAllOptimizedImages: Bool?

  @Option(help: "Upload all optimized videos after processing")
  var uploadAllOptimizedVideos: Bool?

  @Option(help: "Upload all preview images")
  var uploadAllPreviews: Bool?

  @Option(help: "Skip extra parsing of swift metadata")
  var skipSwiftMetadataParsing: Bool?

  @Option(help: "Skip instruction disassembly powered by capstone")
  var skipInstructionDisassembly: Bool?

  @Option(help: "Skip extra asset catalog image processing")
  var skipExtraAssetCatalogImageProcessing: Bool?

  mutating func run() throws {
    let parameters = buildParameters()

    let zipURL: URL
    let unzippedURL: URL
    let fileKey: String
    let uploadID: String?
    let userID: String?
    let s3Client = AWSS3Client()
    let resultsBucket = parameters.resultsBucket ?? "emerge-analysis-results-dev"
    let workingDirPath = parameters.workingDir ?? NSTemporaryDirectory()
    let workingDirUrl = URL(fileURLWithPath: workingDirPath, isDirectory: true)
    if let appPath = parameters.appPath {
      if parameters.output == nil {
        throw Error.invalidParams
      }
      unzippedURL = URL(fileURLWithPath: "/tmp/\(UUID().uuidString)")
      zipURL = URL(fileURLWithPath: appPath)
      fileKey = "localTest"
      userID = nil
      uploadID = nil
    } else if let s3Key = parameters.s3Key {
      var baseFileKey = s3Key
      baseFileKey.removeLast(4)
      userID = String(baseFileKey.split(separator: "/").first ?? "")
      uploadID = String(baseFileKey.split(separator: "/").last ?? "")
      logger[metadataKey: "request-id"] = "\(uploadID ?? "")"
      fileKey = baseFileKey
      let bucketName = parameters.s3UploadBucket ?? "emerge-uploads-prod"
      if let uploadID {
        try? markBuildDequeued(
          uploadId: uploadID,
          bucket: resultsBucket,
          workingDirUrl: workingDirUrl,
          s3Client: s3Client
        )
      }
      let uuidName = UUID().uuidString
      let fileName = "\(uuidName).zip"
      let tmpURL = workingDirUrl.appendingPathComponent(fileName)
      if let error = s3Client.download(bucket: bucketName, key: s3Key, resultURL: tmpURL) {
        throw error
      }
      zipURL = tmpURL
      unzippedURL = workingDirUrl.appendingPathComponent(uuidName)
    } else if let url = parameters.uploadUrl, let uploadId = parameters.uploadId,
      let userId = parameters.userId
    {
      uploadID = uploadId
      logger[metadataKey: "request-id"] = "\(uploadID ?? "")"
      userID = userId
      fileKey = "\(userId)/\(uploadId).zip"
      try? markBuildDequeued(
        uploadId: uploadId,
        bucket: resultsBucket,
        workingDirUrl: workingDirUrl,
        s3Client: s3Client
      )
      let process = Process()
      let uuidName = UUID().uuidString
      let fileName = "\(uuidName).zip"
      let tmpURL = workingDirUrl.appendingPathComponent(fileName)
      process.launchPath = "/usr/bin/curl"
      process.arguments = [url, "--output", tmpURL.path]
      try process.run()
      process.waitUntilExit()
      zipURL = tmpURL
      unzippedURL = workingDirUrl.appendingPathComponent(uuidName)
    } else {
      throw Error.invalidParams
    }

    do {
      try processBuild(
        workingDirURL: workingDirUrl,
        zipURL: zipURL,
        unzippedURL: unzippedURL,
        fileKey: fileKey,
        userID: userID,
        uploadID: uploadID,
        downloader: s3Client,
        parameters: parameters
      )
    } catch {
      try handleProcessingError(
        workingDirURL: workingDirUrl,
        downloader: s3Client,
        parameters: parameters,
        uploadID: uploadID,
        userID: userID,
        error: error
      )
      throw error
    }
  }

  func getHostname() -> String {
    var hostname = [CChar](repeating: 0, count: Int(MAXHOSTNAMELEN))
    gethostname(&hostname, Int(MAXHOSTNAMELEN))
    return String(cString: hostname)
  }

  func markBuildDequeued(
    uploadId: String,
    bucket: String,
    workingDirUrl: URL,
    s3Client: AWSS3Client
  ) throws {
    let jsonDict: [String: String] = ["hostname": getHostname()]
    let jsonData = try JSONSerialization.data(withJSONObject: jsonDict, options: [])
    let jsonFileURL = workingDirUrl.appendingPathComponent("dequeued.json")
    try jsonData.write(to: jsonFileURL)
    _ = try s3Client.upload(bucket: bucket, key: uploadId, localFile: jsonFileURL)
  }

  func processBuild(
    workingDirURL: URL,
    zipURL: URL,
    unzippedURL: URL,
    fileKey: String,
    userID: String?,
    uploadID: String?,
    downloader: AWSS3Client,
    parameters: Parameters
  ) throws {
    let resultsBucket = parameters.resultsBucket ?? "emerge-analysis-results-dev"
    let previewsBucketName = parameters.previewsBucketName ?? "emerge-previews-dev"
    let previewsEnabled = parameters.previewsEnabled ?? false
    let uploadAllOptimizedImages = parameters.uploadAllOptimizedImages ?? false
    let uploadAllOptimizedVideos = parameters.uploadAllOptimizedVideos ?? false
    let uploadAllPreviews = parameters.uploadAllPreviews ?? false
    let skipSwiftMetadataParsing = parameters.skipSwiftMetadataParsing ?? false
    let skipInstructionDisassembly = parameters.skipInstructionDisassembly ?? false
    let skipExtraAssetCatalogImageProcessing =
      parameters.skipExtraAssetCatalogImageProcessing ?? false

    let analyzer = Analyzer(
      workingDirURL: workingDirURL,
      zipURL: zipURL,
      destinationURL: unzippedURL,
      s3BucketName: resultsBucket,
      fileKey: fileKey,
      previewsBucketName: previewsBucketName,
      previewsEnabled: previewsEnabled,
      uploadAllOptimizedImages: uploadAllOptimizedImages,
      uploadAllOptimizedVideos: uploadAllOptimizedVideos,
      uploadAllPreviews: uploadAllPreviews,
      skipSwiftMetadataParsing: skipSwiftMetadataParsing,
      skipInstructionDisassembly: skipInstructionDisassembly,
      skipExtraAssetCatalogImageProcessing: skipExtraAssetCatalogImageProcessing
    )
    defer {
      if parameters.appPath == nil {
        try? FileManager.default.removeItem(at: zipURL)
        if FileManager.default.fileExists(atPath: unzippedURL.path) {
          try? FileManager.default.removeItem(at: unzippedURL)
        }
      } else {
        if FileManager.default.fileExists(atPath: unzippedURL.path) {
          try? FileManager.default.removeItem(at: unzippedURL)
        }
      }
    }
    let results = try analyzer.run()
    if let output = parameters.output {
      let encoder = JSONEncoder()
      encoder.outputFormatting = .prettyPrinted
      let resultData = try encoder.encode(DBResults.Result(uploadId: "", results: results))
      let outputURL = URL(fileURLWithPath: output)
      try resultData.write(to: outputURL)
    } else if let userID = userID, let uploadID = uploadID {
      let dbResults = DBResults(s3BucketName: resultsBucket, userID: userID, s3Client: downloader)
      try dbResults.save(workingDirURL: workingDirURL, uploadId: uploadID, results: results)
      logger.info("App name: \(results.appName)")
    }
  }

  func handleProcessingError(
    workingDirURL: URL,
    downloader: AWSS3Client,
    parameters: Parameters,
    uploadID: String?,
    userID: String?,
    error: Swift.Error
  ) throws {
    let errorResult = ErrorResults(errorMessage: error.localizedDescription, errorType: .generic)

    if let output = parameters.output {
      let encoder = JSONEncoder()
      encoder.outputFormatting = .prettyPrinted
      let resultData = try encoder.encode(errorResult)
      let outputURL = URL(fileURLWithPath: output)
      try resultData.write(to: outputURL)
    } else if let userID = userID, let uploadID = uploadID {
      let resultsBucket = parameters.resultsBucket ?? "emerge-analysis-results-dev"
      let dbResults = DBResults(s3BucketName: resultsBucket, userID: userID, s3Client: downloader)
      try dbResults.save(
        workingDirURL: workingDirURL,
        uploadId: uploadID,
        errorResults: errorResult
      )
    }

    logger.error("Error: \(errorResult)")
  }

  enum Error: Swift.Error {
    case invalidParams
  }

  func buildParameters() -> Parameters {
    do {
      guard let paramsPath = params else {
        throw Error.invalidParams
      }
      let url = URL(fileURLWithPath: paramsPath)
      let data = try Data(contentsOf: url)
      return try parse(json: data)
    } catch {
      return Parameters(
        s3UploadBucket: s3UploadBucket,
        resultsBucket: s3AnalysisResultsBucket,
        previewsBucketName: previewsBucketName,
        uploadUrl: uploadUrl,
        uploadId: uploadId,
        userId: userId,
        appPath: appPath,
        s3Key: s3Key,
        output: output,
        workingDir: workingDir,
        previewsEnabled: false,
        uploadAllPreviews: uploadAllPreviews,
        uploadAllOptimizedImages: uploadAllOptimizedImages,
        uploadAllOptimizedVideos: uploadAllOptimizedVideos,
        skipSwiftMetadataParsing: skipSwiftMetadataParsing,
        skipInstructionDisassembly: skipInstructionDisassembly,
        skipExtraAssetCatalogImageProcessing: skipExtraAssetCatalogImageProcessing
      )
    }
  }

  func parse(json: Data) throws -> Parameters {
    let decoder = JSONDecoder()

    return try decoder.decode(Parameters.self, from: json)
  }
}

let startTime = ProcessInfo.processInfo.systemUptime
Analyze.main()
let endTime = ProcessInfo.processInfo.systemUptime
logger.info("Total Time: \(endTime - startTime)")
