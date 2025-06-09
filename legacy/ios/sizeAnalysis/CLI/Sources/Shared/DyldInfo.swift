//
//  File.swift
//
//
//  Created by Wojtek Mandrysz on 02/03/2023.
//

import Foundation

func dyldInfo(binaryPath: String) -> [String] {
  var inits: [String] = []
  let result = launch(tool: "/usr/bin/xcrun", arguments: ["dyld_info", "-inits", binaryPath])
  if result.0 == 0 {
    if let data = result.1 {
      let output = String(decoding: data, as: UTF8.self)
      if let range = output.range(of: "inits:") {
        inits = output[range.upperBound...].split(separator: "\n").compactMap({
          let string = String($0)
          if string.count > 20 {
            return String(String($0)[String.Index(encodedOffset: 20)...])
          }
          return nil
        })
      }
    }
  }
  return inits.sorted()
}

func launch(tool: String, arguments: [String]) -> (Int32, Data?) {
  let pipe = Pipe()
  let proc = Process()
  proc.launchPath = tool
  proc.arguments = arguments
  proc.standardOutput = pipe

  do {
    DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
      proc.terminate()
    }
    try proc.run()
    let standardOutData = pipe.fileHandleForReading.readDataToEndOfFile()
    proc.waitUntilExit()
    pipe.fileHandleForReading.closeFile()
    return (proc.terminationStatus, standardOutData)
  } catch {
    logger.error("Error running dyld_info")
  }
  return (-1, nil)
}
