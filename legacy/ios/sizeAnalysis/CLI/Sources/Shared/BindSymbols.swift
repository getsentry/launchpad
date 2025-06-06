//
//  File.swift
//
//
//  Created by Noah Martin on 4/25/21.
//

import Foundation

struct BoundSymbol {
  var segmentOffset: UInt
  var library: UInt
  var offset: UInt
  var symbol: String

  func address(with loadCommands: [LoadCommand]) -> BoundSymbolAddress {
    let vmStart = loadCommands[Int(segmentOffset)].vmStart
    let address = vmStart + UInt64(offset)
    return BoundSymbolAddress(vmAddress: address, symbol: symbol)
  }

  func description(with loadCommands: [LoadCommand]) -> String {
    description(with: loadCommands[Int(segmentOffset)].vmStart)
  }

  func description(with vmStart: UInt64) -> String {
    let address = vmStart + UInt64(offset)
    let addressFormat = String(format: "%llX", address)
    return "\(addressFormat) \(symbol)"
  }
}

struct BoundSymbolAddress {
  let vmAddress: UInt64
  let symbol: String
}

extension BoundSymbolAddress: Comparable {
  static func < (lhs: BoundSymbolAddress, rhs: BoundSymbolAddress) -> Bool {
    lhs.vmAddress < rhs.vmAddress
  }
}

extension UnsafeRawPointer {
  func readBoundSymbols(size: UInt) -> [BoundSymbol] {
    var current = BoundSymbol(segmentOffset: 0, library: 0, offset: 0, symbol: "")
    var results = [BoundSymbol]()
    let endPointer = advanced(by: Int(size))
    var mutablePointer = self
    repeat {
      let newResults = mutablePointer.readNext(current: &current, endPointer: endPointer)
      results.append(contentsOf: newResults)
    } while mutablePointer < endPointer
    return results
  }

  mutating func readNext(current: inout BoundSymbol, endPointer: UnsafeRawPointer) -> [BoundSymbol]
  {
    while self < endPointer {
      let firstByte = load(as: UInt8.self)
      self += 1
      let immediate = Int32(firstByte) & BIND_IMMEDIATE_MASK
      let opcode = Int32(firstByte) & BIND_OPCODE_MASK
      switch opcode {
      case BIND_OPCODE_DONE:
        let result = current
        current.segmentOffset = 0
        current.library = 0
        current.offset = 0
        current.symbol = ""
        return [result]
      case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        current.library = UInt(immediate)
      case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        let string = readNullTerminatedString()
        current.symbol = string
      case BIND_OPCODE_ADD_ADDR_ULEB:
        let offset = readULEB()
        current.offset &+= offset
      case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        let offset = readULEB()
        let result = current
        current.offset &+= offset &+ UInt(MemoryLayout<UInt64>.size)
        return [result]
      case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        let offset = readULEB()
        current.segmentOffset = UInt(immediate)
        current.offset = offset
      case BIND_OPCODE_SET_ADDEND_SLEB:
        let _ = readULEB()
      case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        let result = current
        current.offset &+= UInt(
          (Int(immediate) &* MemoryLayout<UInt64>.size) &+ MemoryLayout<UInt64>.size
        )
        return [result]
      case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        let count = readULEB()
        let skipping = readULEB()
        var results = [BoundSymbol]()
        for _ in 0..<count {
          results.append(current)
          current.offset &+= skipping &+ UInt(MemoryLayout<UInt64>.size)
        }
        return results
      case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        let count = readULEB()
        current.library = count
      case BIND_OPCODE_DO_BIND:
        let result = current
        current.offset &+= UInt(MemoryLayout<UInt64>.size)
        return [result]
      case BIND_OPCODE_SET_TYPE_IMM:
        break
      case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        break
      default:
        break
      }
    }
    return []
  }

  mutating func readNullTerminatedString() -> String {
    var stringArray = [UInt8]()
    var character: UInt8 = 0
    repeat {
      character = load(as: UInt8.self)
      stringArray.append(character)
      self += 1
    } while character != 0
    return String(cString: stringArray)
  }

  mutating func readULEB() -> UInt {
    var nextByte: UInt8
    var size = 0
    var result: UInt = 0
    repeat {
      nextByte = load(as: UInt8.self)
      self += 1
      let bytes = nextByte & 0x7F
      let shifted = UInt(bytes) << (size * 7)
      size += 1
      result = result | shifted
    } while nextByte & 0x80 != 0
    return result
  }
}
