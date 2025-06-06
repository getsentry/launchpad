//
//  CGImage+PNG.swift
//
//
//  Created by Itay Brenner on 10/10/23.
//

import AVFoundation
import Foundation

extension CGImage {
  var png: Data? {
    guard let mutableData = CFDataCreateMutable(nil, 0),
      let destination = CGImageDestinationCreateWithData(
        mutableData,
        "public.png" as CFString,
        1,
        nil
      )
    else { return nil }
    CGImageDestinationAddImage(destination, self, nil)
    guard CGImageDestinationFinalize(destination) else { return nil }

    return mutableData as Data
  }

  public func reduceSize(_ newWidth: Int) -> CGImage? {
    return resize(newWidth, allowBigger: false)
  }

  public func increaseSize(_ newWidth: Int) -> CGImage? {
    return resize(newWidth, allowBigger: true)
  }

  public func resize(_ newWidth: Int, allowBigger: Bool = false) -> CGImage? {
    // Ensuring row bytes is multiple of 16 for alignment
    let bytesPerRow = (Int(newWidth) * 4 + 15) & ~15

    var workingImage: CGImage = self
    if bitsPerComponent > 8 {
      // We are using extended colorspace
      guard let imageWithNormalSpace = self.copy(colorSpace: CGColorSpaceCreateDeviceRGB()) else {
        return nil
      }
      workingImage = imageWithNormalSpace
    }

    guard newWidth < width || allowBigger else {
      return self
    }

    let ratio: Float = Float(width) / Float(newWidth)

    let newHeight = Int(Float(height) / ratio)

    guard let colorSpace = workingImage.colorSpace else { return nil }
    guard
      let context = CGContext(
        data: nil,
        width: newWidth,
        height: newHeight,
        bitsPerComponent: workingImage.bitsPerComponent,
        // The `bytesPerRow` and `bitmapInfo` are a bit tricky, not all combinations work with the bitsPerComponent and bytesPerRow
        // Right now I left the original one `workingImage.bitmapInfo`, but these 2 also provided good results:
        // - CGImageAlphaInfo.premultipliedLast: use the last bit for the alpha channel information
        // - CGBitmapInfo.byteOrder32Big: use 32 bits and Big Endian
        bytesPerRow: bytesPerRow,
        space: colorSpace,
        bitmapInfo: workingImage.bitmapInfo.rawValue
      )
    else { return nil }

    context.interpolationQuality = .high
    context.draw(workingImage, in: CGRect(x: 0, y: 0, width: newWidth, height: newHeight))

    return context.makeImage()
  }
}
