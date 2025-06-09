//
//  File.swift
//
//
//  Created by Noah Martin on 11/17/20.
//

import Foundation

public final class AWSS3Client {

  public init() {
    if FileManager.default.fileExists(atPath: intelLaunchPath) {
      launchPath = intelLaunchPath
    } else {
      launchPath = appleSiliconLaunchPath
    }
  }

  let intelLaunchPath = "/usr/local/bin/s5cmd"
  let appleSiliconLaunchPath = "/opt/homebrew/bin/s5cmd"

  let launchPath: String

  public func download(
    bucket: String,
    key: String,
    resultURL: URL
  ) -> Swift.Error? {
    let process = Process()
    process.launchPath = launchPath
    let awsPath = "s3://\(bucket)/\(key)"
    process.arguments = ["--numworkers", "128", "cp", "\(awsPath)", resultURL.path]
    do {
      try process.run()
    } catch {
      return error
    }
    process.waitUntilExit()
    return nil
  }

  public func upload(
    bucket: String,
    key: String,
    localFile: URL
  ) throws -> String? {
    let process = Process()
    let fileName = localFile.lastPathComponent
    process.launchPath = launchPath
    let awsPath = "s3://\(bucket)/\(key)/\(fileName)"
    process.arguments = ["--numworkers", "128", "cp", localFile.path, "\(awsPath)"]
    try process.run()
    process.waitUntilExit()
    return "https://\(bucket).s3.us-west-1.amazonaws.com/\(key)/\(fileName)"
  }

}
