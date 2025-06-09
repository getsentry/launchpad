//
//  File.swift
//
//
//  Created by Noah Martin on 1/24/21.
//

import Foundation

extension RBTreeNode {
  // Retruns the greatest node in this tree less than the new node.
  func beforeAndAfter(newValue: T) -> (RBTreeNode<T>?, RBTreeNode<T>?) {
    var beforeNode: RBTreeNode<T>? = nil
    var afterNode: RBTreeNode<T>? = nil
    traverseInOrder { node in
      guard let key = node.key else { return true }

      if key < newValue {
        beforeNode = node
        return true
      }

      afterNode = node
      return false
    }
    return (beforeNode, afterNode)
  }
}

struct RangeMap<T: Hashable> {

  struct Entry: Comparable {
    static func < (lhs: RangeMap<T>.Entry, rhs: RangeMap<T>.Entry) -> Bool {
      lhs.offset < rhs.offset
    }

    static func == (lhs: RangeMap<T>.Entry, rhs: RangeMap<T>.Entry) -> Bool {
      lhs.offset == rhs.offset
    }

    init<E>(offset: UInt64, value: T, of: E.Type) {
      self.offset = UInt(offset)
      self.size = UInt(MemoryLayout<E>.size)
      self.value = value
      context = ""
      self.range = self.offset..<(self.offset + size)
    }

    init(offset: UInt64, size: UInt, value: T, context: String = "") {
      self.offset = UInt(offset)
      self.size = size
      self.value = value
      self.context = context
      self.range = self.offset..<(self.offset + size)
    }

    var offset: UInt
    var size: UInt
    let value: T
    let context: String

    // Not inclusive
    var end: UInt {
      offset + size
    }

    let range: Range<UInt>

    func intersects(_ other: Entry) -> Bool {
      range.overlaps(other.range)
    }
  }

  var lastPair: (RBTreeNode<Entry>?, RBTreeNode<Entry>?)? = nil
  var conflictSize: UInt = 0

  mutating func add(
    _ entry: Entry,
    allowPartial: Bool = false,
    conflictNotifier: (Entry) -> Void = { _ in }
  ) {
    guard entry.size > 0 else { return }

    let tree = binarySearchTree.root

    let lowerBound = tree.lowerBound(of: entry)

    if let lower = lowerBound?.key, lower.intersects(entry) {
      if lower.end < entry.end {
        if allowPartial {
          let topPartial = entry.end - lower.end
          add(
            .init(offset: UInt64(lower.end), size: topPartial, value: entry.value),
            allowPartial: true
          )
        } else {
          //logger.debug("There is a conflict \(lower) \(entry)")
          conflictSize += entry.size
        }
      }
      conflictNotifier(lower)
      return
    }

    let upperBound = tree.upperBound(of: entry)
    if let lower = lowerBound?.key, let upper = upperBound?.key {
      assert(lower < upper)
    }
    if let upper = upperBound?.key, upper.intersects(entry) {
      // They might be equal
      if upper.offset > entry.offset {
        if allowPartial {
          let bottomPartial = upper.offset - entry.offset
          add(
            .init(offset: UInt64(entry.offset), size: bottomPartial, value: entry.value),
            allowPartial: true
          )
        } else {
          //logger.debug("There is a conflict \(upper) \(entry)")
          conflictSize += entry.size
        }
      }
      if upper.end < entry.end {
        if allowPartial {
          let topPartial = entry.end - upper.end
          add(
            .init(offset: UInt64(upper.end), size: topPartial, value: entry.value),
            allowPartial: true
          )
        } else {
          //logger.debug("There is a conflict \(upper) \(entry)")
          conflictSize += entry.size
        }
      }
      conflictNotifier(upper)
      return
    }

    binarySearchTree.insert(key: entry)
  }

  func forEachRange(_ block: (_ start: UInt, _ size: UInt, T) -> Void) {
    binarySearchTree.root.traverseInOrder { entry -> Bool in
      guard let key = entry.key else { return true }

      block(key.offset, key.size, key.value)
      return true
    }
  }

  var mappedSize: UInt {
    logger.info("conflict size \(conflictSize)")
    var size: UInt = 0
    var map = [T: UInt]()
    binarySearchTree.root.traverseInOrder { node in
      if let key = node.key {
        map[key.value] = (map[key.value] ?? 0) + key.size
      }
      size += node.key?.size ?? 0
      return true
    }
    //logger.debug(map.keys.count)
    //logger.debug(map.keys.filter { ((($0 as! ModuleDescription).provider as? CategoryDescrpition)) != nil })
    return size
  }

  private var binarySearchTree = RedBlackTree<Entry>()
}

extension RangeMap where T == BinaryTag {

  func contains(address: UInt64) -> Bool {
    let testNode = RangeMap<BinaryTag>.Entry(
      offset: address,
      size: 1,
      value: BinaryTag.externalMethods
    )
    if let lowerBound = binarySearchTree.root.lowerBound(of: testNode)?.key,
      lowerBound.intersects(testNode)
    {
      return true
    }

    if let upperBound = binarySearchTree.root.upperBound(of: testNode)?.key,
      upperBound.intersects(testNode)
    {
      return true
    }
    return false
  }
}
