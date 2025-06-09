//
//  File.swift
//
//
//  Created by Noah Martin on 4/17/21.
//

import Foundation
import Logging

public func time<T>(_ name: String, _ block: () -> T) -> T {
  let startTime = ProcessInfo.processInfo.systemUptime
  let result = block()
  let elapsed = ProcessInfo.processInfo.systemUptime - startTime
  logger.info("Time: \(name) \(elapsed)")

  return result
}

// Don't assume any actor isolation since Size hasn't been ported to Swift6
nonisolated(unsafe) public var logger: Logger = {
  var logger = Logger(label: "app-size-analyzer")
  logger.logLevel = .info
  return logger
}()
