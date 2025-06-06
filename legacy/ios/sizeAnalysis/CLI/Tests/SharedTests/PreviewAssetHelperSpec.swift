//
//  PreviewAssetHelperTest.swift
//
//
//  Created by Itay Brenner on 8/2/24.
//

import AppKit
import Foundation
import Nimble
import Quick

@testable import Shared

class PreviewAssetHelperSpec: QuickSpec {
  override class func spec() {
    describe("addNewImage") {
      it("returns false when trying to add and previews are disabled") {
        let previewsHelper = PreviewAssetHelper(false, false)
        let image = getImage()
        let assetKey = "someKey"

        let result = previewsHelper.addNewImage(assetKey: assetKey, cgImage: image)

        expect(result).to(beFalse())
      }

      it("returns true when trying to add and previews are enabled") {
        let previewsHelper = PreviewAssetHelper(true, false)
        let image = getImage()
        let assetKey = "someKey"

        let result = previewsHelper.addNewImage(assetKey: assetKey, cgImage: image)

        expect(result).to(beTrue())
      }

      it("returns false when it fails to save image") {
        let previewsHelper = PreviewAssetHelper(true, false)
        let image = getImage()
        let assetKey = "someKey"
        try FileManager.default.removeItem(atPath: previewsHelper.tempFolder.path())

        let result = previewsHelper.addNewImage(assetKey: assetKey, cgImage: image)

        expect(result).to(beFalse())
      }
    }

    describe("shouldStopAddingAssets") {
      it("returns true when previews are disabled") {
        let previewsHelper = PreviewAssetHelper(false, false)

        let result = previewsHelper.shouldStopAddingAssets()

        expect(result).to(beTrue())
      }

      it("returns false when previews are enabled and item count is 0") {
        let previewsHelper = PreviewAssetHelper(true, false)

        let result = previewsHelper.shouldStopAddingAssets()

        expect(result).to(beFalse())
      }

      it("returns false when previews are enabled and item count is max - 1") {
        let previewsHelper = PreviewAssetHelper(true, false)

        let image = getImage()
        for i in 0..<(PreviewAssetHelper.maxPreviewImagesToUpload - 1) {
          previewsHelper.addNewImage(assetKey: "\(i)", cgImage: image)
        }

        let result = previewsHelper.shouldStopAddingAssets()

        expect(result).to(beFalse())
      }

      it("returns true when previews are enabled and item count reached max value max") {
        let previewsHelper = PreviewAssetHelper(true, false)

        let image = getImage()
        for i in 0..<(PreviewAssetHelper.maxPreviewImagesToUpload) {
          previewsHelper.addNewImage(assetKey: "\(i)", cgImage: image)
        }

        let result = previewsHelper.shouldStopAddingAssets()

        expect(result).to(beTrue())
      }
    }

    describe("getPreviewKeyFor") {
      it("returns nil when the key is not found") {
        let previewsHelper = PreviewAssetHelper(true, false)
        let key = "randomKey"

        let result = previewsHelper.getPreviewKeyFor(assetKey: key)

        expect(result).to(beNil())
      }

      it("returns the key properly when the key is found") {
        let previewsHelper = PreviewAssetHelper(true, false)
        let key = "randomKey"
        previewsHelper.addNewImage(assetKey: key, cgImage: getImage())

        let result = previewsHelper.getPreviewKeyFor(assetKey: key)

        expect(result).toNot(beNil())
      }
    }

    describe("deinit") {
      it("temporal folder is created on init") {
        let previewsHelper = PreviewAssetHelper(true, false)
        let path = previewsHelper.tempFolder.path()

        let result = FileManager.default.fileExists(atPath: path, isDirectory: nil)

        expect(result).to(beTrue())
      }

      it("temporal folder is deleted on deallocation") {
        let path = autoreleasepool {
          let previewsHelper = PreviewAssetHelper(true, false)

          return previewsHelper.tempFolder.path()
        }
        let result = FileManager.default.fileExists(atPath: path, isDirectory: nil)

        expect(result).to(beFalse())
      }
    }
  }

  class func getImage() -> CGImage {
    let imagePath = Bundle.module.path(
      forResource: "Emerge",
      ofType: "heic",
      inDirectory: "Assets"
    )!
    let image = NSImage(contentsOf: URL(fileURLWithPath: imagePath))!

    var rect = NSRect(origin: CGPoint(x: 0, y: 0), size: image.size)
    return image.cgImage(forProposedRect: &rect, context: NSGraphicsContext.current, hints: nil)!
  }
}
