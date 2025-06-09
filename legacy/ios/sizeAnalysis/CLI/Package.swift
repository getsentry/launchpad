// swift-tools-version:6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
  name: "AppSizeAnalyzer",
  platforms: [
    .macOS(.v13)
  ],
  products: [
    .executable(
      name: "AppSizeAnalyzer",
      targets: ["AppSizeAnalyzer"]
    )
  ],
  dependencies: [
    .package(url: "https://github.com/EmergeTools/capstone-swift.git", branch: "v5-static"),
    .package(url: "https://github.com/EmergeTools/Zip.git", branch: "master"),
    .package(url: "https://github.com/apple/swift-argument-parser", from: "0.3.1"),
    .package(url: "https://github.com/apple/swift-log.git", from: "1.4.0"),
    .package(url: "https://github.com/httpswift/Swifter.git", from: "1.5.0"),
    .package(url: "https://github.com/noahsmartin/CwlDemangle", branch: "master"),
    .package(url: "https://github.com/Quick/Quick.git", from: "7.0.0"),
    .package(url: "https://github.com/Quick/Nimble.git", from: "12.0.0"),
  ],
  targets: [
    // MARK: - AppSizeAnalyzer (CLI executable)
    .executableTarget(
      name: "AppSizeAnalyzer",
      dependencies: [
        .product(name: "ArgumentParser", package: "swift-argument-parser"),
        "Shared",
      ],
      exclude: [
        // Exclude the static library from being processed as a resource.
        "libjemalloc_pic.a"
      ],
      linkerSettings: [
        .unsafeFlags([
          "-F", "/System/Library/PrivateFrameworks",
          "-framework", "CoreUI",
          "-lc++",
          "-Xlinker", "-force_load",
          "-Xlinker", "./Sources/AppSizeAnalyzer/libjemalloc_pic.a",
          "-Xlinker", "-rpath",
          "-Xlinker", "@executable_path",
        ])
      ]
    ),
    .target(name: "ObjcSupport"),
    .target(
      name: "Shared",
      dependencies: [
        .target(name: "ObjcSupport"),
        .product(name: "Capstone", package: "capstone-swift"),
        .product(name: "Zip", package: "Zip"),
        .product(name: "Logging", package: "swift-log"),
        //.product(name: "Capstone", package: "Capstone"),
        .product(name: "CwlDemangle", package: "CwlDemangle"),
      ],
      swiftSettings: [
        // TODO: Some concurrency warnings we need to fix
        .swiftLanguageMode(.v5)
      ],
      linkerSettings: [
        .unsafeFlags([
          // Use the inherited runpath search paths
          "-Xlinker", "-rpath",
          "-Xlinker", "@executable_path/../Frameworks",
          "-Xlinker", "-rpath",
          "-Xlinker", "@loader_path/Frameworks",
        ])
      ]
    ),

    .testTarget(
      name: "TypeName",
      dependencies: ["Shared"],
      linkerSettings: [
        .unsafeFlags([
          "-F", "/System/Library/PrivateFrameworks",
          "-framework", "CoreUI",
          "-lc++",
          "-Xlinker", "-force_load",
          "-Xlinker", "./Sources/AppSizeAnalyzer/libjemalloc_pic.a",
          "-Xlinker", "-rpath",
          "-Xlinker", "@executable_path",
        ])
      ]
    ),
    .testTarget(
      name: "SharedTests",
      dependencies: ["Shared", "Quick", "Nimble"],
      resources: [
        .copy("Assets")
      ],
      linkerSettings: [
        .unsafeFlags([
          "-F", "/System/Library/PrivateFrameworks",
          "-framework", "CoreUI",
          "-lc++",
          "-Xlinker", "-force_load",
          "-Xlinker", "./Sources/AppSizeAnalyzer/libjemalloc_pic.a",
          "-Xlinker", "-rpath",
          "-Xlinker", "@executable_path",
        ])
      ]
    ),
  ],
  cxxLanguageStandard: .cxx20
)
