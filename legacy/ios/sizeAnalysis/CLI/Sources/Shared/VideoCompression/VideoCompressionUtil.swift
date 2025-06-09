//
//  VideoCompressionUtil.swift
//
//
//  Created by Itay Brenner on 20/8/24.
//

import AVFoundation
import Foundation

struct VideoCompressionUtil {
  struct Video {
    struct Configuration {
      let videoBitrate: Int
      let videoEncoding: VideoEncoding

      init(
        videoBitrate: Int,
        videoEncoding: VideoEncoding = .h264
      ) {
        self.videoBitrate = videoBitrate
        self.videoEncoding = videoEncoding
      }
    }

    let source: URL
    let destination: URL
    let configuration: Configuration
    init(
      source: URL,
      destination: URL,
      configuration: Configuration
    ) {
      self.source = source
      self.destination = destination
      self.configuration = configuration
    }
  }

  func compressVideo(_ video: Video) throws -> VideoCompressionResult? {
    let process = Process()

    process.launchPath = "/opt/homebrew/bin/ffmpeg"

    let codec =
      switch video.configuration.videoEncoding {
      case .hevc: "hevc_videotoolbox"
      case .h264: "h264_videotoolbox"
      }

    let targetBitrate = video.configuration.videoBitrate
    var arguments = [
      "-hide_banner", "-loglevel", "error", "-hwaccel", "videotoolbox", "-i", video.source.path,
      "-c:v", codec, "-b:v", "\(targetBitrate)",
    ]
    if video.configuration.videoEncoding == .hevc {
      arguments.append(contentsOf: ["-tag:v", "hvc1"])
    }
    arguments.append(video.destination.path)

    process.arguments = arguments
    try process.run()
    process.waitUntilExit()

    guard let originalFileSize = try video.source.resourceValues(forKeys: [.fileSizeKey]).fileSize,
      let newFileSize = try video.destination.resourceValues(forKeys: [.fileSizeKey]).fileSize
    else {
      return nil
    }

    let sizeDiff = originalFileSize - newFileSize
    if sizeDiff > 0 {
      return VideoCompressionResult(
        savings: UInt(sizeDiff),
        fileURL: video.destination,
        encoding: .hevc
      )
    } else {
      return nil
    }
  }
}
