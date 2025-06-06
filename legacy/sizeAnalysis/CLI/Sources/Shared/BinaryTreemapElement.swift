//
//  File.swift
//
//
//  Created by Noah Martin on 1/28/21.
//

import Foundation

enum TreemapType: String, Encodable {
  case string
  case unmapped
  case modules
  case swiftModule
  case objcPrefix
  case dyld
  case codeSignature
  case externalMethods
  case macho
}

enum TreemapBehavior: String, Encodable {
  // Take the size of other elements in this group if they are hidden
  case `default`
  // Hide if smaller than 5% of container and move this size to the default element
  case hideSmall
  // Always hide if a default element is found
  case hide
}

struct TreemapElementDetails: Encodable {
  var strings: [String]
  var numberObjcClasses: Int
  var stringCount: Int = 0

  mutating func append(otherDetails: TreemapElementDetails) {
    self.strings += otherDetails.strings
    self.numberObjcClasses += otherDetails.numberObjcClasses
  }

  mutating func sorted() {
    stringCount = strings.count
    strings = Array(strings.sorted(by: { $0.count > $1.count }).prefix(20))
  }
}

struct TreemapJsonElement: Encodable {
  let name: String
  var value: UInt
  let type: TreemapType?
  let details: TreemapElementDetails?
  let children: [TreemapJsonElement]?
}

class BinaryTreemapElement {
  init(
    name: String,
    size: UInt,
    type: TreemapType? = nil,
    treemapElementDetails: TreemapElementDetails? = nil,
    children: [BinaryTreemapElement] = []
  ) {
    self.name = name
    self.size = size
    self.type = type
    self.treemapElementDetails = treemapElementDetails
    self.children = children.reduce(
      [:],
      { result, element in
        var newResult = result
        newResult[element.name] = element
        return newResult
      }
    )
  }

  func addChild(
    named name: String,
    parentGrouping: String? = nil,
    at path: [String],
    size: UInt,
    firstPathType type: TreemapType?
  ) {
    if let parentGrouping = parentGrouping {
      if let existingGrouping = children[parentGrouping] {
        existingGrouping.addChild(named: name, at: path, size: size, firstPathType: type)
      } else {
        let element = BinaryTreemapElement(name: parentGrouping, size: 0)
        add(child: element)
        element.addChild(named: name, at: path, size: size, firstPathType: type)
      }
      return
    }
    if let nextComponent = path.first {
      let subPath = Array(path.dropFirst())
      if let child = children[nextComponent] {
        if let type = type {
          // TODO: fix the root problem of this assert that's failing
          // assert(type == child.type, "Type of new element must equal existing type")
        }
        child.addChild(named: name, at: subPath, size: size, firstPathType: nil)
      } else {
        let element = BinaryTreemapElement(name: nextComponent, size: 0, type: type)
        add(child: element)
        element.addChild(named: name, at: subPath, size: size, firstPathType: nil)
      }
      return
    }

    if let child = children[name] {
      if let type = type {
        assert(type == child.type, "Type of new element must equal existing type")
      }
      child.increaseSize(by: size)
    } else {
      let newElement = BinaryTreemapElement(name: name, size: size, type: type)
      add(child: newElement)
    }
  }

  func increaseSize(by amount: UInt) {
    size += amount
    parent?.increaseSize(by: amount)
  }

  func add(child: BinaryTreemapElement) {
    child.parent = self
    children[child.name] = child
    increaseSize(by: child.size)
  }

  let name: String
  private(set) var size: UInt
  let type: TreemapType?
  var treemapElementDetails: TreemapElementDetails?
  private(set) var children: [String: BinaryTreemapElement]
  private var parent: BinaryTreemapElement?

  var sizeOfChildren: UInt {
    children.values.map { $0.size }.reduce(0, +)
  }

  static let commonThirdPartyDependencies = [
    "Firebase",
    "Firebase Performance",
    "Firebase Dynamic Links",
    "Firebase ML",
    "Google Cast",
    "LPMessagingSDK",
    "FBSDK",
    "Braintree",
    "AppAuth",
    "Google Toolbox Mac",
    "Google Utilities",
    "CocoaAsyncSocket",
    "Google Sign In",
    "Google Maps",
    "RxSwift",
    "Branch",
    "libPhoneNumber",
    "SwiftProtobuf",
    "Google Protobuf",
    "New Relic",
    "FrozenMountain",
    "C++",
  ]

  func toJsonElement() -> TreemapJsonElement {
    let childrenSize = sizeOfChildren
    if childrenSize > size {
      logger.error("The children \(children)")
      fatalError("Size of children \(childrenSize) greater than \(size) for \(name)")
    }
    let unmappedSize = size - childrenSize
    var childrenJson = [TreemapJsonElement]()
    if !Self.commonThirdPartyDependencies.contains(name) {
      childrenJson = children.values.map { $0.toJsonElement() }
      if childrenJson.count > 0 && unmappedSize > 0 {
        if type != .macho {
          if let firstChild = childrenJson.firstIndex(where: { $0.name == name }) {
            var updatedChild = childrenJson[firstChild]
            updatedChild.value += unmappedSize
            childrenJson[firstChild] = updatedChild
            // Useful in some cases like when there is a protocol conformance for `rawValue` and a `getter`. We just won't show the `getter`.
          } else if childrenJson.count == 1 && childrenJson.first!.name != "Objc Metadata"
            && childrenJson.first!.name != "Swift Metadata"
            && childrenJson.first!.name != "Objc Category"
          {
            childrenJson = []
          } else {
            childrenJson.append(
              .init(name: name, value: unmappedSize, type: nil, details: nil, children: nil)
            )
          }
        } else {
          let unmappedElement = TreemapJsonElement(
            name: "Unmapped",
            value: unmappedSize,
            type: .unmapped,
            details: nil,
            children: nil
          )
          childrenJson.append(unmappedElement)
        }
      }

      if childrenJson.count == 1
        && (childrenJson[0].name == "getter" || childrenJson[0].name == "init")
      {
        childrenJson = []
      }
    }
    treemapElementDetails?.sorted()
    return TreemapJsonElement(
      name: name,
      value: size,
      type: type,
      details: treemapElementDetails,
      children: childrenJson.count < 1 ? nil : childrenJson
    )
  }
}
