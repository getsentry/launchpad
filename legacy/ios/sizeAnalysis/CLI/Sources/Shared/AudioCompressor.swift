//
//  File.swift
//
//
//  Created by Noah Martin on 12/22/20.
//

import Foundation

final class AudioCompressor {
  static func getSavings(for url: URL) throws -> (UInt, URL)? {
    guard let originalFileSize = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize else {
      return nil
    }

    let newFileName = url.deletingPathExtension().lastPathComponent.appending("-Converted.caf")
    let newFileURL = url.deletingLastPathComponent().appendingPathComponent(newFileName)
    let process = Process()
    process.launchPath = "/usr/bin/afconvert"
    process.arguments = ["-d", "aac", "-f", "caff", "-b", "128000", url.path, newFileURL.path]
    try process.run()
    process.waitUntilExit()
    guard let newFileSize = try newFileURL.resourceValues(forKeys: [.fileSizeKey]).fileSize else {
      return nil
    }

    let sizeDiff = originalFileSize - newFileSize
    if sizeDiff > 0 {
      return (UInt(sizeDiff), newFileURL)
    } else {
      return nil
    }
  }
}
