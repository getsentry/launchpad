//
//  PreviewAssetHelper.swift
//
//
//  Created by Itay Brenner on 30/1/24.
//

import AVFoundation
import Foundation

final class PreviewAssetHelper {
  let tempFolder: URL
  let previewsEnabled: Bool
  var previewAssets = [String: URL]()
  let uploadAllPreviews: Bool

  static let maxPreviewImagesToUpload = 10
  static let uploadImageSize = 400

  init(_ previewsEnabled: Bool, _ uploadAllPreviews: Bool) {
    self.previewsEnabled = previewsEnabled
    self.uploadAllPreviews = uploadAllPreviews

    let tempDirectoryURL = FileManager.default.temporaryDirectory
    tempFolder = tempDirectoryURL.appendingPathComponent(UUID().uuidString)
    try? FileManager.default.createDirectory(at: tempFolder, withIntermediateDirectories: true)
  }

  deinit {
    deleteTempFolder()
  }

  func getPreviewKeyFor(assetKey: String) -> String? {
    guard let previewAsset = previewAssets[assetKey] else {
      return nil
    }

    return previewAsset.lastPathComponent
  }

  func shouldStopAddingAssets() -> Bool {
    guard self.previewsEnabled else {
      return true
    }
    guard !uploadAllPreviews else {
      return false
    }

    return previewAssets.keys.count >= PreviewAssetHelper.maxPreviewImagesToUpload
  }

  @discardableResult
  func addNewImage(assetKey: String, cgImage: CGImage) -> Bool {
    guard self.previewsEnabled else {
      return false
    }

    let filePath = pathFor(key: assetKey)
    guard save(cgImage, to: filePath) else {
      return false
    }

    previewAssets[assetKey] = filePath

    return true
  }

  func deleteTempFolder() {
    try? FileManager.default.removeItem(at: tempFolder)
  }

  private func save(_ cgImage: CGImage, to: URL) -> Bool {
    return autoreleasepool {
      guard let resizedImage = cgImage.reduceSize(PreviewAssetHelper.uploadImageSize),
        let imageData = resizedImage.png
      else {
        return false
      }

      do {
        try imageData.write(to: to)
      } catch {
        return false
      }

      return true
    }
  }

  private func pathFor(key: String) -> URL {
    return tempFolder.appendingPathComponent("\(key).png")
  }
}
