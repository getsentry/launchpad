//
//  WatchAppSubproductHelper.swift
//
//
//  Created by Itay Brenner on 2/2/24.
//

import Foundation

struct WatchAppSubproductHelper {
  static func createSubproduct(_ rootURL: URL) -> Subproduct? {
    guard
      let watchBundleUrl = try? FileManager.default.contentsOfDirectory(
        at: rootURL.appendingPathComponent("Watch"),
        includingPropertiesForKeys: nil
      ).first,
      let watchPlistData = try? PlistData(appRoot: watchBundleUrl)
    else {
      return nil
    }

    let watchInstallSize =
      (try? FileManager.default.appStoreSizeOfDirectory(at: watchBundleUrl)) ?? 0
    let watchDownloadSize = calculateDownloadSizeForBundle(watchBundleUrl) ?? 0

    return Subproduct(
      productType: .watch,
      installSize: watchInstallSize,
      downloadSize: watchDownloadSize,
      identifier: watchPlistData.appId,
      displayName: watchPlistData.appName
    )

  }
}
