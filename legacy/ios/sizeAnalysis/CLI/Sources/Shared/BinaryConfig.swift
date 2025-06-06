//
//  File.swift
//
//
//  Created by Noah Martin on 2/12/21.
//

import Foundation

enum ThirdPartyFrameworkBundleID: CaseIterable {

  init?(bundleID: String) {
    for framework in Self.allCases {
      if framework.possibleBundleIDs.contains(bundleID) {
        self = framework
        return
      }
    }
    return nil
  }

  case Bugsnag
  case FBSDKCoreKit
  case FaceTec
  case RxSwift
  case Protobuf
  case GoogleAPIClientForREST
  case GoogleUtilities
  case Lottie
  case Realm

  var possibleBundleIDs: [String] {
    switch self {
    case .Bugsnag:
      return ["\(cocoapodsPrefix)Bugsnag", "com.bugsnag.Bugsnag"]
    case .FBSDKCoreKit:
      return ["\(cocoapodsPrefix)FBSDKCoreKit", "com.facebook.sdk.FBSDKCoreKit"]
    case .FaceTec:
      return ["com.facetec.sdk"]
    case .RxSwift:
      return ["\(cocoapodsPrefix)RxSwift"]
    case .Protobuf:
      return ["\(cocoapodsPrefix)Protobuf"]
    case .GoogleAPIClientForREST:
      return ["\(cocoapodsPrefix)GoogleAPIClientForREST"]
    case .GoogleUtilities:
      return ["\(cocoapodsPrefix)GoogleUtilities"]
    case .Lottie:
      return []
    //return ["\(cocoapodsPrefix)Lottie", "com.airbnb.Lottie-iOS"]
    case .Realm:
      return ["\(cocoapodsPrefix)Realm"]
    }
  }

  private var cocoapodsPrefix: String {
    "org.cocoapods."
  }
}

enum ModuleName: Hashable {
  case prefix(String)
  case fullName(String)
  case thirdParty(ThirdPartyModuleName)

  init(type: String, in app: String) {
    self = Self.getModuleName(type: type, in: app)
  }

  private static func getModuleName(type: String, in app: String) -> ModuleName {
    let sanitized = type.trimmingCharacters(in: .init(["_"]))
    var name = ThirdPartyModuleName.forEach(\.postSanitizedPrefix, in: app) {
      module,
      prefix -> ThirdPartyModuleName? in
      guard sanitized.starts(with: prefix) else { return nil }
      return module
    }
    if let name = name {
      return .thirdParty(name)
    }

    name = ThirdPartyModuleName.forEach(\.postSanitizedContains, in: app) {
      module,
      contains -> ThirdPartyModuleName? in
      guard sanitized.contains(contains) else { return nil }
      return module
    }
    if let name = name {
      return .thirdParty(name)
    }

    if sanitized.hasPrefix("Z") && type.starts(with: "_") {
      name = ThirdPartyModuleName.forEach(\.cPlusPlusContains, in: app) {
        module,
        contains -> ThirdPartyModuleName? in
        guard sanitized.contains(contains) else { return nil }
        return module
      }
    }
    if let name = name {
      return .thirdParty(name)
    }

    if sanitized.starts(with: "Z") && type.starts(with: "_") {
      return .thirdParty(.CPlusPlus)
    }

    let capitalizedPrefix = sanitized.objcPrefix
    if capitalizedPrefix.count < 2 {
      let underscoreSeparated = sanitized.split(separator: "_")
      if let firstComponent = underscoreSeparated.first,
        underscoreSeparated.count > 1,
        firstComponent.count > 2
      {
        return .prefix(String(firstComponent))
      }
      return .fullName(sanitized)
    }

    for module in ThirdPartyModuleName.supportedCases(in: app) {
      for modulePrefix in module.objcPrefix {

        if capitalizedPrefix.starts(with: modulePrefix) {
          let remaining = capitalizedPrefix.dropFirst(modulePrefix.count)
          for suffix in [""] + knownSuffixes {
            if remaining == suffix {
              return .thirdParty(module)
            }
          }
          for suffix in knownSuffixNames {
            if sanitized.dropFirst(modulePrefix.count).hasPrefix("\(suffix)") {
              return .thirdParty(module)
            }
          }
        }
      }
    }

    return .prefix(capitalizedPrefix)
  }

  var description: String {
    switch self {
    case .prefix(let name):
      return name
    case .fullName(let name):
      return name
    case .thirdParty(let module):
      return module.rawValue
    }
  }
}

// These are often found at the begining of a typename after the module prefix
let knownSuffixes = [
  "URL",
  "HTTP",
  "JSON",
  "UI",
  "HTTPAPI",
  "MSG",
  "GDT",
  "GDTCC",
  "GTM",
  "CPU",
  "NSURL",
  "SSOJWT",
  "UUID",
  "SDK",
  "KVO",
  "GDPR",
]

let knownSuffixNames = [
  "NSDictionary",
  "NSData",
  "ASId",
  "OAuth",
]

enum ThirdPartyModuleName: String, CaseIterable {
  case Firebase
  case FirebasePerformance = "Firebase Performance"
  case FirebaseDynamicLinks = "Firebase Dynamic Links"
  case FirebaseML = "Firebase ML"
  case GoogleToolbox = "Google Toolbox Mac"
  case GoogleSignIn = "Google Sign In"
  case GoogleUtilities = "Google Utilities"
  case GoogleCast = "Google Cast"
  case AppAuth
  case FBSDK
  case CocoaAsyncSocket
  case RxSwift
  case FBLPromise
  case Braintree
  case Bugsnag
  case LPMessagingSDK
  case GoogleMaps = "Google Maps"
  case MParticle
  case Protobuf = "Google Protobuf"
  case libPhoneNumber
  case Mantle
  case Branch
  case Lottie
  case Aliyun
  case FrozenMountain
  case WeChat
  case NewRelic = "New Relic"
  case AMap
  case CPlusPlus = "C++"

  var swiftModules: [String] {
    var result = [self.rawValue]
    switch self {
    case .FBSDK:
      result += ["FBSDKShareKit", "FBSDKLoginKit", "FBSDKCoreKit"]
    default:
      break
    }
    return result
  }

  // Prefix checked after dropping leading `_` before getting the Obj-C prefix
  var postSanitizedPrefix: [String] {
    switch self {
    case .Firebase:
      return ["FIRCLS", "apmpb"]
    case .FirebaseML:
      return ["FBMLx_"]
    case .Braintree:
      return ["PPDataCollector", "PPConfiguration"]
    case .FBSDK:
      return ["fb_dispatch_", "fb_swizzle", "fb_findSwizzle", "NSStringFromFBSDK"]
    case .Bugsnag:
      return ["BugsnagSessionTracking"]
    case .GoogleMaps:
      return ["GMS"]
    case .GoogleCast:
      return ["GCK"]
    case .FBLPromise:
      return ["Promises"]
    case .CocoaAsyncSocket:
      return ["GCDAsync"]
    case .MParticle:
      return [
        "MParticleReachability", "MParticleWebView", "FilteredMParticleUser",
        "MParticleUserNotification", "MParticleOptions",
      ]
    case .Branch:
      return ["Branch"]
    case .FrozenMountain:
      return ["FMIce"]
    case .AMap:
      return ["AMap"]
    default:
      return []
    }
  }

  var postSanitizedContains: [String] {
    switch self {
    case .FBSDK:
      return ["fbsdk"]
    case .GoogleMaps:
      return ["gmscore"]
    default:
      return []
    }
  }

  var cPlusPlusContains: [String] {
    switch self {
    case .GoogleMaps:
      return ["GMS"]
    case .NewRelic:
      return ["NewRelic", "NRMA"]
    case .AMap:
      return [
        "AnMap", "MAMap", "AMap", "amapfoundation", "CPosCommonFunction", "AnRoadSurface",
        "CLineBuilder", "RoadCreator3d", "CAn", "N4dice", "K4dice", "GDTL", "MACommonNative",
      ]
    case .MParticle:
      return ["mParticle"]
    case .Protobuf:
      return ["google19protobuf"]
    default:
      return []
    }
  }

  var objcPrefix: [String] {
    switch self {
    case .Firebase:
      return ["FIR", "APM", "APME", "APMPB", "APMASL", "APMAEU", "GDTCOR", "GDTCCT"]
    case .FirebasePerformance:
      return ["FPR"]
    case .FirebaseDynamicLinks:
      return ["FIRDL"]
    case .FirebaseML:
      return ["FIRML", "FBML", "GMV"]
    case .GoogleToolbox:
      return ["GTM", "GTMO"]
    case .GoogleSignIn:
      return ["GID", "GIDEMM"]
    case .GoogleUtilities:
      return ["GUL"]
    case .GoogleCast:
      return ["GCK"]
    case .AppAuth:
      return ["OID", "OIDID"]
    case .Protobuf:
      return ["GPB"]
    case .FBSDK:
      return ["FBSDK", "FBSDKSK"]
    case .RxSwift:
      return ["RX"]
    case .Braintree:
      return ["BT", "PPFPTI", "PPOTO", "PPOT", "PPRMOC"]
    case .GoogleMaps:
      return ["GMS"]
    case .MParticle:
      return []  //["MP"] // Removed to support Mercato Pago prefix
    case .libPhoneNumber:
      return ["NB"]
    case .Mantle:
      return ["MTL"]
    case .Branch:
      return ["BNC"]
    case .Lottie:
      return ["LOT"]
    case .Aliyun:
      return ["OSS", "OSSDD"]
    case .WeChat:
      return ["WX"]
    case .NewRelic:
      return ["NRMA"]
    case .AMap:
      return ["MA"]
    case .CPlusPlus, .CocoaAsyncSocket, .FBLPromise, .Bugsnag, .FrozenMountain, .LPMessagingSDK:
      return []
    }
  }

  static func supportedCases(in app: String) -> [Self] {
    var supportedModules = Self.allCases
    if let aMapIndex = supportedModules.firstIndex(of: .AMap), !app.contains("airbnb") {
      supportedModules.remove(at: aMapIndex)
    }
    if let lottieIndex = supportedModules.firstIndex(of: .Lottie),
      app.lowercased().starts(with: "com.airbnb.lottie")
    {
      supportedModules.remove(at: lottieIndex)
    }
    return supportedModules
  }

  static func forEach<T>(
    _ path: KeyPath<Self, [String]>,
    in app: String,
    _ block: (Self, String) -> T?
  ) -> T? {
    for module in Self.supportedCases(in: app) {
      for string in module[keyPath: path] {
        guard let result = block(module, string) else { continue }

        return result
      }
    }
    return nil
  }
}

extension String {
  var objcPrefix: String {
    var capitalizedPrefix = ""
    for character in self {
      if character.isUppercase {
        capitalizedPrefix.append(character)
      } else {
        break
      }
    }
    if capitalizedPrefix.count != count && !dropFirst(capitalizedPrefix.count).starts(with: "_") {
      capitalizedPrefix = String(capitalizedPrefix.dropLast())
    }
    return capitalizedPrefix
  }
}
