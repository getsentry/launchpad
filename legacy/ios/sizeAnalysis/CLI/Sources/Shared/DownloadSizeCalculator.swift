import Compression
import Foundation
import ObjcSupport

struct ShellError: Swift.Error {
  let message: String
}

private func runShell(command: String) throws {
  logger.info("Command: \(command)")
  let result = nonRestrictedSystem(command)
  if result != 0 {
    throw ShellError(message: "Command failed: \(command)")
  }
}

private func lzfseCompressedSize(path: URL) -> Int {
  let sourceData = try! Data(contentsOf: path)
  // Small files may increase in size due to compression, so use a large buffer to avoid this
  let destinationSize = max(sourceData.count, 1_000_000)
  let destinationBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: destinationSize)
  defer { destinationBuffer.deallocate() }
  let algorithm = COMPRESSION_LZFSE
  return sourceData.withUnsafeBytes { bufferPointer -> Int in
    let ptr = bufferPointer.baseAddress?.bindMemory(to: UInt8.self, capacity: sourceData.count)
    let compressedSize = compression_encode_buffer(
      destinationBuffer,
      destinationSize,
      ptr!,
      sourceData.count,
      nil,
      algorithm
    )
    return compressedSize == 0 ? sourceData.count : compressedSize
  }
}

private func zipMetadataSizeForBundle(_ bundleURL: URL) -> UInt {
  let tempDirectoryURL = FileManager.default.temporaryDirectory
  let zipFileURL = tempDirectoryURL.appendingPathComponent(UUID().uuidString)
    .appendingPathExtension("zip")
  let zipSizeInfoFileURL = tempDirectoryURL.appendingPathComponent(UUID().uuidString)
  let bundleDirURL = bundleURL.deletingLastPathComponent()
  // Zip from the bundle's directory so that file paths in the .zip are relative, and thus smaller, to match Apple
  try! runShell(
    command:
      "cd \"\(bundleDirURL.path)\" && zip -r \"\(zipFileURL.path)\" \"\(bundleURL.lastPathComponent)\" > /dev/null"
  )
  try! runShell(command: "unzip -v \"\(zipFileURL.path)\" > \"\(zipSizeInfoFileURL.path)\"")
  let zippedSizeInfo = try! fileContentsString(for: zipSizeInfoFileURL)
  let lastInfoLine = zippedSizeInfo.split(separator: "\n").last!
  let totalZipContentSize = Int(lastInfoLine.split(separator: " ")[1])!
  let attributes = try! FileManager.default.attributesOfItem(atPath: zipFileURL.path)
  let totalZipSize = attributes[FileAttributeKey.size] as! UInt64

  try! FileManager.default.removeItem(at: zipFileURL)
  try! FileManager.default.removeItem(at: zipSizeInfoFileURL)

  return UInt(Int(totalZipSize) - totalZipContentSize)
}

private func fileContentsString(for url: URL) throws -> String {
  do {
    return try String(contentsOf: url, encoding: .utf8)
  } catch {
    logger.error("Unable to open file with utf-8, falling back to isoLatin1")
    return try String(contentsOf: url, encoding: .isoLatin1)
  }
}

private func lzfseContentSizeForBundle(_ bundleURL: URL) -> UInt {
  var totalLzfseContentSize = 0
  if let enumerator = FileManager.default.enumerator(
    at: bundleURL,
    includingPropertiesForKeys: [.isRegularFileKey]
  ) {
    for case let fileURL as URL in enumerator {
      let fileAttributes = try! fileURL.resourceValues(forKeys: [.isRegularFileKey])
      if !fileAttributes.isRegularFile! {
        continue
      }
      totalLzfseContentSize += lzfseCompressedSize(path: fileURL)
    }
  }
  return UInt(totalLzfseContentSize)
}

// Apple appears to use .zip files that are compressed using LZFSE. The total size of that zip file is the
// metadata (such as the path) + actual compressed data. Since `zip` doesn't support LZFSE, just use `zip`
// to get the size of the metadata and then compute the LZFSE content size ourselves
func calculateDownloadSizeForBundle(_ bundleURL: URL) -> UInt? {
  guard bundleURL.pathExtension == "app" else { return nil }  // Frameworks aren't supported

  // The additional amount for the code signature doesn't need to factor in compression, because in practice this data
  // turns out not to be compressible
  let codeSignatureAddition = bundleURL.extraCodeSignatureSize()
  return zipMetadataSizeForBundle(bundleURL) + lzfseContentSizeForBundle(bundleURL)
    + codeSignatureAddition
}
