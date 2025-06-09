//
//  VideoCompression.swift
//
//
//  Created by Itay Brenner on 20/8/24.
//

import AVFoundation
import AVKit
import Foundation

struct VideoCompressionResult {
  var savings: UInt
  var fileURL: URL
  var encoding: VideoEncoding
}

final class VideoCompressor {
  let tempFolder: URL

  init() {
    let tempDirectoryURL = FileManager.default.temporaryDirectory
    tempFolder = tempDirectoryURL.appendingPathComponent(UUID().uuidString)
    try? FileManager.default.createDirectory(at: tempFolder, withIntermediateDirectories: true)
  }

  deinit {
    cleanTempFiles()
  }

  func getSavings(for url: URL, supportsHEVC: Bool, quality: VideoQuality = .high) throws
    -> VideoCompressionResult?
  {
    let asset = AVAsset(url: url)
    guard let videoTrack = asset.tracks(withMediaType: .video).first else {
      return nil
    }
    let currentBitrate = videoTrack.estimatedDataRate
    let targetBitrate = currentBitrate * quality.rawValue

    var jobsArray: [(VideoEncoding, URL)] = [
      (.h264, pathFor(originalURL: url, encoding: .h264))
    ]
    if supportsHEVC {
      jobsArray.append((.hevc, pathFor(originalURL: url, encoding: .hevc)))
    }

    let videos = jobsArray.map { (encoding, destinationURL) in
      return VideoCompressionUtil.Video(
        source: url,
        destination: destinationURL,
        configuration: .init(
          videoBitrate: Int(targetBitrate),
          videoEncoding: encoding
        )
      )
    }

    let compressionUtil = VideoCompressionUtil()
    var results: [VideoCompressionResult] = []
    let group = DispatchGroup()
    let queue = DispatchQueue.global(qos: .userInitiated)
    // Needed because main thread is blocked by the group wait
    let resultQueue = DispatchQueue(label: "resultQueue")

    for video in videos {
      group.enter()
      queue.async {
        if let compressedVideo = try? compressionUtil.compressVideo(video) {
          resultQueue.sync {
            results.append(compressedVideo)
          }
        }
        group.leave()
      }
    }
    group.wait()

    let sortedResults = results.sorted { result1, result2 in
      result1.savings > result2.savings
    }

    return sortedResults.first
  }

  func pathFor(originalURL: URL, encoding: VideoEncoding) -> URL {
    let extensionForEncoding =
      switch encoding {
      case .h264: "mp4"
      case .hevc: "mov"
      }
    let newFileName = originalURL.deletingPathExtension().lastPathComponent.appending(
      "-\(encoding).\(extensionForEncoding)"
    )
    return tempFolder.appendingPathComponent(newFileName)
  }

  public func cleanTempFiles() {
    try? FileManager.default.removeItem(at: tempFolder)
  }
}
