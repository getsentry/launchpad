//
//  File.swift
//
//
//  Created by Noah Martin on 3/17/21.
//

import Foundation

extension FileManager {
  func appStoreSizeOfDirectory(at directoryURL: URL, ignoreURL: URL? = nil) throws -> UInt {
    var totalCount: UInt = 0
    // The error handler simply stores the error and stops traversal
    var enumeratorError: Swift.Error? = nil
    func errorHandler(_: URL, error: Swift.Error) -> Bool {
      enumeratorError = error
      return false
    }

    let keys = allocatedSizeResourceKeys
    // We have to enumerate all directory contents, including subdirectories.
    let enumerator = self.enumerator(
      at: directoryURL,
      includingPropertiesForKeys: keys,
      options: [],
      errorHandler: errorHandler
    )!

    // We'll sum up content size here:
    var accumulatedSize: UInt = 0

    // Perform the traversal.
    for item in enumerator {
      // Bail out on errors from the errorHandler.
      if enumeratorError != nil { break }

      let contentItemURL = item as! URL
      guard
        ignoreURL == nil
          || !contentItemURL.resolvingSymlinksInPath().path().hasPrefix(ignoreURL!.path())
      else {
        continue
      }

      totalCount += 1

      if contentItemURL.isSymLink {
        // Symlink have 0 disk space
        continue
      }

      // Add up individual file sizes.
      accumulatedSize += try contentItemURL.regularFileAllocatedSize()
      if contentItemURL.pathExtension.isEmpty && contentItemURL.isMachOBinary {
        // For a binary add size from app store code signatures
        accumulatedSize += contentItemURL.extraCodeSignatureSize()
      }
    }

    totalCount += 1

    // Rethrow errors from errorHandler.
    if let error = enumeratorError { throw error }

    return try accumulatedSize + directoryURL.regularFileAllocatedSize() + (totalCount * 1734)
  }
}

let allocatedSizeResourceKeys: [URLResourceKey] = [
  .isRegularFileKey,
  .fileAllocatedSizeKey,
  .totalFileAllocatedSizeKey,
]

extension URL {
  func regularFileAllocatedSize() throws -> UInt {
    var stat1 = stat()
    let _ = stat((path as NSString).fileSystemRepresentation, &stat1)
    if stat1.st_blocks > 0 {
      return UInt(ceil(Double(stat1.st_size) / 4096.0) * 4096)
    } else {
      return UInt(stat1.st_size)
    }
  }
}
