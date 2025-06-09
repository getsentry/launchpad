//
//  PlistData.swift
//
//
//  Created by Itay Brenner on 7/4/23.
//

import Foundation

public struct PlistData {
  public init(appRoot: URL) throws {
    let plistURL: URL
    let iOSPlistURL = appRoot.appendingPathComponent("Info.plist")
    let macOSPlistURL = appRoot.appendingPathComponent("Contents/Info.plist")
    if !FileManager.default.fileExists(atPath: iOSPlistURL.path) {
      if !FileManager.default.fileExists(atPath: macOSPlistURL.path) {
        throw Error.missingPlist
      } else {
        plistURL = macOSPlistURL
      }
    } else {
      plistURL = iOSPlistURL
    }
    let plistData = try Data(contentsOf: plistURL)
    guard
      let plist = try PropertyListSerialization.propertyList(
        from: plistData,
        options: [],
        format: nil
      ) as? [String: Any]
    else {
      throw Error.invalidPlist
    }

    appId = plist[kCFBundleIdentifierKey as String] as? String ?? ""
    appName =
      (plist["CFBundleDisplayName" as String] as? String)?.trimmed()
      ?? (plist[kCFBundleNameKey as String] as? String)?.trimmed() ?? ""
    appVersion = plist["CFBundleShortVersionString"] as? String ?? ""
    appBuild = plist[kCFBundleVersionKey as String] as? String ?? ""
    executableName = plist[kCFBundleExecutableKey as String] as? String ?? ""
    xcodeBuildVersion = plist["DTXcodeBuild"] as? String ?? ""
    platformBuildVersion = plist["DTPlatformBuild"] as? String ?? ""
    buildMachineBuildVersion = plist["BuildMachineOSBuild"] as? String ?? ""
    platformName = plist["DTPlatformName"] as? String ?? ""
    bundleSupportedPlatforms = plist["CFBundleSupportedPlatforms"] as? [String] ?? []

    guard
      let minOS = plist["MinimumOSVersion"] as? String ?? plist["LSMinimumSystemVersion"] as? String
    else {
      throw Error.missingMinOS
    }
    self.minOS = minOS

    var icon: String? = nil
    var alternateIcons: [String] = []
    if let bundleIcons = plist["CFBundleIcons"] as? [String: Any] {
      if let primaryIcon = bundleIcons["CFBundlePrimaryIcon"] as? [String: Any] {
        icon = primaryIcon["CFBundleIconName"] as? String ?? ""
      }
      if let alternateIconsMap = bundleIcons["CFBundleAlternateIcons"]
        as? [String: [String: String]]
      {
        alternateIcons = alternateIconsMap.values.compactMap { dict in
          dict["CFBundleIconName"]
        }
      }
    }
    primaryIconName = icon
    alternateIconNames = alternateIcons
  }

  var supportsHEIC: Bool {
    let comparison = minOS.compare("12.0", options: .numeric)
    if comparison == .orderedDescending || comparison == .orderedSame {
      return true
    }
    return false
  }

  private enum Error: Swift.Error, LocalizedError {
    case invalidPlist
    case missingMinOS
    case missingPlist

    var errorDescription: String? {
      switch self {
      case .invalidPlist:
        return "Info.plist could not be read"
      case .missingMinOS:
        return "Info.plist is missing a MinimumOSVersion key"
      case .missingPlist:
        return "Couldn't find Info.plist in your app."
      }
    }
  }

  public let appId: String
  public let appName: String
  public let appVersion: String
  public let appBuild: String
  public let xcodeBuildVersion: String
  public let platformBuildVersion: String
  public let buildMachineBuildVersion: String
  public let minOS: String
  public let executableName: String
  public let bundleSupportedPlatforms: [String]
  public let platformName: String
  public let primaryIconName: String?
  public let alternateIconNames: [String]
}
