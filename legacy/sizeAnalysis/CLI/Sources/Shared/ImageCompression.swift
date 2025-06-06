//
//  ImageCompression.swift
//  AnalyzeCore
//
//  Created by Noah Martin on 11/26/20.
//  Copyright © 2020 Tom Doron. All rights reserved.
//

import AVFoundation
import Accelerate
import AppKit
import Foundation

public typealias CompressionAmount = (
  inFormatSavings: UInt?, modernFormatSavings: UInt?, optimizedURL: URL?
)

public final class Compression {
  static let IPHONE_3_ICON_SIZE = 180
  static let ICON_STORE_SIZE = 1024

  public init(workingDirURL: URL) {
    self.workingDirURL = workingDirURL
    self.workingDirURLForIcons = workingDirURL.appending(path: "Icons")
    if FileManager.default.fileExists(atPath: intelLaunchPath + "node") {
      launchPath = intelLaunchPath
    } else {
      launchPath = appleSiliconLaunchPath
    }
  }

  let intelLaunchPath = "/usr/local/bin/"
  let appleSiliconLaunchPath = "/opt/homebrew/bin/"

  let workingDirURL: URL
  let workingDirURLForIcons: URL
  let launchPath: String

  public func savings(for imageName: String, size: UInt, cgImage: CGImage, supportsHeic: Bool)
    throws -> CompressionAmount
  {
    return try autoreleasepool {
      try savings(
        for: imageName,
        size: size,
        supportsHeic: supportsHeic,
        workingDirURL: workingDirURL
      ) {
        cgImage
      }
    }
  }

  public func iconSavings(for imageName: String, size: UInt, cgImage: CGImage, supportsHeic: Bool)
    throws -> CompressionAmount
  {
    return try autoreleasepool {
      try savings(
        for: imageName,
        size: size,
        supportsHeic: supportsHeic,
        workingDirURL: workingDirURLForIcons
      ) {
        // Resize imaghe to 180px and increase it again for AppStore
        guard let smallImage = cgImage.reduceSize(Compression.IPHONE_3_ICON_SIZE),
          let fullSize = smallImage.increaseSize(Compression.ICON_STORE_SIZE)
        else {
          throw Error.failedToResize
        }

        return fullSize
      }
    }
  }

  private enum Error: Swift.Error {
    case missingImage
    case cgImageNoData
    case failedToResize
  }

  public func savings(for url: URL, size: UInt, supportsHeic: Bool) throws -> CompressionAmount {
    try savings(
      for: url.lastPathComponent,
      size: size,
      supportsHeic: supportsHeic,
      workingDirURL: workingDirURL
    ) {
      let data = try Data(contentsOf: url)
      guard let image = NSImage(data: data) else {
        throw Error.missingImage
      }
      var imageRect = CGRect(x: 0, y: 0, width: image.size.width, height: image.size.height)
      guard let cgImage = image.cgImage(forProposedRect: &imageRect, context: nil, hints: nil)
      else {
        throw Error.missingImage
      }
      return cgImage
    }
  }

  private func imageMin(url: URL) throws {
    let process = Process()
    process.launchPath = "\(launchPath)node"
    process.arguments = [
      "\(launchPath)imagemin", url.path, "--out-dir", url.deletingLastPathComponent().path, "-p",
      "pngquant",
    ]
    process.standardOutput = nil
    process.standardInput = nil
    try process.run()
    process.waitUntilExit()
  }

  private let pathName = UUID().uuidString

  private static let minImageSavings: UInt = 1024 * 4  // 4kb

  private func savings(
    for imageName: String,
    size: UInt,
    supportsHeic: Bool,
    workingDirURL: URL,
    cgImageProvider: () throws -> CGImage
  ) throws -> CompressionAmount {
    let minJpgSize: UInt = 1024 * 10  // 10kb
    let minPngSize: UInt = 1024 * 40  // 40kb
    let tmpDirectory = workingDirURL.appendingPathComponent(pathName)
    try? FileManager.default.createDirectory(
      at: tmpDirectory,
      withIntermediateDirectories: true,
      attributes: nil
    )
    let tmpURL = tmpDirectory.appendingPathComponent(imageName)
    if imageName.hasSuffix(".png") && size > minPngSize {
      // Call external program
      let cgImage = try cgImageProvider()
      let modernFormatSavings: UInt?
      if supportsHeic {
        (modernFormatSavings, _) =
          try Self.savings(cgImage: cgImage, initialSize: size, type: .heic) ?? (nil, nil)
      } else {
        modernFormatSavings = nil
      }

      if cgImage.isNoAlpha {
        let jpgURL = tmpURL.deletingPathExtension().appendingPathExtension("jpg")
        if let (savingsAsJpg, data) = try Self.savings(
          cgImage: cgImage,
          initialSize: size,
          type: .jpg
        ) {
          try data.write(to: jpgURL)
          return (savingsAsJpg, modernFormatSavings, jpgURL)
        }
      }

      if let destination = CGImageDestinationCreateWithURL(tmpURL as CFURL, kUTTypePNG, 1, nil) {
        CGImageDestinationAddImage(destination, cgImage, nil)
        CGImageDestinationFinalize(destination)
        try imageMin(url: tmpURL)
        if let minFileSize = try tmpURL.resourceValues(forKeys: [.fileSizeKey]).fileSize,
          minFileSize < size
        {
          let savings = size - UInt(minFileSize)
          if savings > Self.minImageSavings {
            return (savings, modernFormatSavings, tmpURL)
          }
        }
      }
      return (nil, modernFormatSavings, nil)
    } else if size > minJpgSize
      && (imageName.hasSuffix(".jpg") || imageName.hasSuffix(".jpeg")
        || imageName.hasSuffix(".heic"))
    {
      let cgImage = try cgImageProvider()

      let format: AVFileType
      let inFormatCompressionSavings: UInt?
      let savedURL: URL?
      if imageName.hasSuffix(".heic") {
        format = .heic
        (inFormatCompressionSavings, _) =
          try Self.savings(cgImage: cgImage, initialSize: size, type: .heic) ?? (nil, nil)
        savedURL = nil
      } else {
        format = .jpg
        if let (savings, data) = try Self.savings(cgImage: cgImage, initialSize: size, type: .jpg) {
          inFormatCompressionSavings = savings
          try data.write(to: tmpURL)
          savedURL = tmpURL
        } else {
          inFormatCompressionSavings = nil
          savedURL = nil
        }
      }

      if format == .jpg && supportsHeic {
        let (modernFormatSavings, _) =
          try Self.savings(cgImage: cgImage, initialSize: size, type: .heic) ?? (nil, nil)
        return (inFormatCompressionSavings, modernFormatSavings, savedURL)
      } else {
        return (inFormatCompressionSavings, nil, savedURL)
      }
    }
    return (nil, nil, nil)
  }

  private static func savings(cgImage: CGImage, initialSize: UInt, type: AVFileType) throws -> (
    UInt, Data
  )? {
    let compressedData = try cgImage.compressedData(compressionQuality: 0.85, type: type)

    if compressedData.count > 0 && compressedData.count < initialSize {
      let savings = initialSize - UInt(compressedData.count)
      if savings > minImageSavings {
        return (savings, compressedData)
      }
    }
    return nil
  }
}

enum Error: Swift.Error {
  case missingImage
  case compressionFailed
  case heicNotSupported
  case couldNotFinalize
}

extension CGImage {
  func compressedData(compressionQuality: Double, type: AVFileType) throws -> Data {
    // 1
    let data = NSMutableData()
    guard
      let imageDestination =
        CGImageDestinationCreateWithData(
          data,
          type as CFString,
          1,
          nil
        )
    else {
      throw Error.heicNotSupported
    }

    // 3
    let options: NSDictionary = [
      kCGImageDestinationLossyCompressionQuality: compressionQuality
    ]

    // 4
    CGImageDestinationAddImage(imageDestination, self, options)
    guard CGImageDestinationFinalize(imageDestination) else {
      throw Error.couldNotFinalize
    }

    return data as Data
  }
}

extension CGImage {
  var isNoAlpha: Bool {
    guard alphaInfo == CGImageAlphaInfo.premultipliedFirst else { return false }

    do {
      var vImage = try vImage_Buffer(cgImage: self)
      var histogramBinZero = [vImagePixelCount](repeating: 0, count: 256)
      var histogramBinOne = [vImagePixelCount](repeating: 0, count: 256)
      var histogramBinTwo = [vImagePixelCount](repeating: 0, count: 256)
      var histogramBinThree = [vImagePixelCount](repeating: 0, count: 256)
      histogramBinZero.withUnsafeMutableBufferPointer { zeroPtr in
        histogramBinOne.withUnsafeMutableBufferPointer { onePtr in
          histogramBinTwo.withUnsafeMutableBufferPointer { twoPtr in
            histogramBinThree.withUnsafeMutableBufferPointer { threePtr in

              var histogramBins = [
                zeroPtr.baseAddress, onePtr.baseAddress,
                twoPtr.baseAddress, threePtr.baseAddress,
              ]

              histogramBins.withUnsafeMutableBufferPointer { histogramBinsPtr in
                let error = vImageHistogramCalculation_ARGB8888(
                  &vImage,
                  histogramBinsPtr.baseAddress!,
                  vImage_Flags(kvImageNoFlags)
                )

                if error != kvImageNoError {
                  logger.error("Error calculating histogram: \(error)")
                }
              }
            }
          }
        }
      }
      return histogramBinThree[255] == width * height
    } catch {
      logger.error("vImage error \(error)")
      return false
    }
  }
}
