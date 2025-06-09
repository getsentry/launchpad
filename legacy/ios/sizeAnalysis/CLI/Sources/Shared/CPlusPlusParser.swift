//
//  File.swift
//
//
//  Created by Noah Martin on 7/20/21.
//

import Foundation

final class CPlusPlusParser {

  static func parse(symbol: String) -> SymbolList {
    let sanitizedSymbol = symbol.replacingOccurrences(of: "> >", with: ">>").replacingOccurrences(
      of: "(anonymous namespace)::",
      with: ""
    )
    let results = parseWithSpaces(
      symbol: sanitizedSymbol,
      startIndex: sanitizedSymbol.startIndex,
      endCharacter: nil
    ).0
    if results.count == 1 {
      return results.first!
    } else {
      return SymbolList(kind: .unknown, name: nil, children: results)
    }
  }

  static func parseWithSpaces(symbol: String, startIndex: String.Index, endCharacter: Character?)
    -> ([SymbolList], Bool, String.Index)
  {
    let (list, foundTerminal, index) = parse(
      symbol: symbol,
      startIndex: startIndex,
      endCharacter: endCharacter
    )
    if !foundTerminal && index < symbol.endIndex && symbol[index] == " " {
      let (subList, foundTerminal, subIndex) = parseWithSpaces(
        symbol: symbol,
        startIndex: symbol.index(after: index),
        endCharacter: endCharacter
      )
      let result = SymbolList(
        kind: .unknown,
        name: nil,
        children: [
          SymbolList(kind: .namespaced, name: nil, children: list),
          SymbolList(kind: .namespaced, name: nil, children: subList),
        ]
      )
      return ([result], foundTerminal, subIndex)
    }
    return (list, foundTerminal, index)
  }

  // Parses a command separated and places each in an argument node
  static func parseWithNextArg(symbol: String, startIndex: String.Index, endCharacter: Character?)
    -> ([SymbolList], String.Index)
  {
    var result = [SymbolList]()
    var nextIndex = startIndex
    var foundTerminal = false
    let parseArg = {
      let (list, newFoundTerminal, index) = parseWithSpaces(
        symbol: symbol,
        startIndex: nextIndex,
        endCharacter: endCharacter
      )
      nextIndex = index
      foundTerminal = newFoundTerminal
      result += [SymbolList(kind: .argument, name: nil, children: list)]
    }

    parseArg()
    while (!foundTerminal && nextIndex < symbol.endIndex && symbol[nextIndex] == ",")
      && symbol.index(after: nextIndex) < symbol.endIndex
    {
      nextIndex = symbol.index(after: symbol.index(after: nextIndex))
      parseArg()
    }
    return (result, nextIndex)
  }

  static func parse(symbol: String, startIndex: String.Index, endCharacter: Character?) -> (
    [SymbolList], Bool, String.Index
  ) {
    var children = [SymbolList]()
    var inProgress = ""
    var index = startIndex
    var end = false
    var foundTerminal = false
    while index < symbol.endIndex && !end {
      let character = symbol[index]
      switch character {
      case " ", ",":
        if !inProgress.isEmpty {
          children.append(SymbolList(kind: .identifier, name: inProgress, children: []))
        }
        inProgress = ""
        end = true
      case "<":
        children.append(SymbolList(kind: .identifier, name: inProgress, children: []))
        inProgress = ""
        index = symbol.index(after: index)
        let (genericChildren, endIndex) = parseWithNextArg(
          symbol: symbol,
          startIndex: index,
          endCharacter: ">"
        )
        index = endIndex
        children.append(SymbolList(kind: .generic, name: nil, children: genericChildren))
      case "(":
        var before: String.Index? = nil
        if index > symbol.startIndex {
          before = symbol.index(before: index)
        }
        if !inProgress.isEmpty {
          children.append(SymbolList(kind: .identifier, name: inProgress, children: []))
        }
        index = symbol.index(after: index)
        let (paramsChildren, endIndex) = parseWithNextArg(
          symbol: symbol,
          startIndex: index,
          endCharacter: ")"
        )
        index = endIndex

        // If the previous symbol is a space then ignore these, for example "char foo(int) (.cold.1)"
        if let before = before, symbol[before] != " " {
          children.append(SymbolList(kind: .params, name: nil, children: paramsChildren))
        }
        inProgress = ""
      // TODO: Ensure this isn't the end of the string
      case ":" where symbol[symbol.index(after: index)] == ":":
        // Increment by one to handle the next `:`
        index = symbol.index(after: index)
        if !inProgress.isEmpty {
          children.append(SymbolList(kind: .identifier, name: inProgress, children: []))
        }
        inProgress = ""
        index = symbol.index(after: index)
      case "[" where inProgress == "-" || inProgress == "+":
        index = symbol.index(after: index)
        inProgress = ""
        let (paramsChildren, endIndex) = parseWithNextArg(
          symbol: symbol,
          startIndex: index,
          endCharacter: "]"
        )
        index = endIndex
        children.append(SymbolList(kind: .objcName, name: nil, children: paramsChildren))
      case endCharacter:
        if !inProgress.isEmpty {
          children.append(SymbolList(kind: .identifier, name: inProgress, children: []))
        }
        inProgress = ""
        index = symbol.index(after: index)
        end = true
        foundTerminal = true
      default:
        inProgress += String(symbol[index])
        index = symbol.index(after: index)
      }
    }
    if !inProgress.isEmpty {
      children.append(SymbolList(kind: .identifier, name: inProgress, children: []))
    }
    return (children, foundTerminal, index)
  }
}

struct SymbolList {
  let kind: Kind
  let name: String?
  let children: [SymbolList]

  enum Kind {
    case generic
    case params
    case namespaced
    case identifier
    case argument
    case objcName
    case unknown
  }

  var containsFunction: Bool {
    if kind == .params {
      return true
    }
    return children.map { $0.containsFunction }.reduce(false) { $0 || $1 }
  }

  var path: [String] {
    return children.compactMap {
      switch $0.kind {
      case .generic, .params, .objcName:
        return nil
      case .argument, .namespaced, .unknown:
        preconditionFailure("unhandled type")
      case .identifier:
        return $0.name!
      }
    }
  }

  // We remove leading and trialing symbols like "const" or the return type
  var cannonicalSymbol: SymbolList {
    if let firstSymbol = children.first,
      firstSymbol.kind == .namespaced || firstSymbol.kind == .unknown
    {
      // If the first symbol is namespaced then there is leading or trailing symbols,
      // so we take the last one that contains a function call
      return (children.last(where: { $0.containsFunction }) ?? children.last!).cannonicalSymbol
    }
    return self
  }

  func prettyPrint(level: Int = 0) {
    var line = String(repeating: " ", count: level)
    line.append(name ?? "\(kind)")
    print(line)
    children.forEach { $0.prettyPrint(level: level + 2) }
  }
}
