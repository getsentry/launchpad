//
//  File.swift
//
//
//  Created by Noah Martin on 2/9/21.
//

import Foundation

final class DsymLoader {
  init(url: URL) {
    self.url = url
    data = (try! Data(contentsOf: url, options: .alwaysMapped)) as NSData
    pointer = data.bytes
  }

  let data: NSData
  let pointer: UnsafeRawPointer
  var foundAddress = [(UInt, String)]()

  func load() {
    let bytes = pointer
    var symtabCommand: symtab_command?
    bytes.processLoadComands { command, commandPointer in
      switch command.cmd {
      case UInt32(LC_SYMTAB):
        let commandType = commandPointer.load(as: symtab_command.self)
        symtabCommand = commandType
      default:
        break
      }
      return true
    }

    guard let command = symtabCommand else { return }

    parseTable(command: command)
  }

  func parseTable(command: symtab_command) {
    let bytes = pointer
    let nsyms = command.nsyms
    let stringTableOffset = UInt(command.stroff)
    let symStart = bytes.advanced(by: Int(command.symoff))
    let strStart = bytes.advanced(by: Int(stringTableOffset))
    for i in 0..<nsyms {
      let symbolStart = symStart.advanced(by: Int(i) * MemoryLayout<nlist_64>.size)
      let nlist = symbolStart.load(as: nlist_64.self)
      guard (nlist.n_type & UInt8(N_STAB) == 0) && nlist.n_value != 0 else { continue }

      let stringStart = strStart.advanced(by: Int(nlist.n_un.n_strx))
      let string = String(cString: stringStart.assumingMemoryBound(to: UInt8.self))
      foundAddress.append((UInt(nlist.n_value), string))
    }
  }

  private let url: URL
}
