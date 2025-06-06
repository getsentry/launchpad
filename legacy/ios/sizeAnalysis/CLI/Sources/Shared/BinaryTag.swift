//
//  File.swift
//
//
//  Created by Noah Martin on 1/27/21.
//

import CwlDemangle
import Foundation
import ObjcSupport

enum BinaryTag: Hashable {
  enum StringType: String {
    case cfStrings = "CFStrings"
    case needle = "Needle Dependency Strings"
    case swiftFilePaths = "Swift File Paths"
    case unmapped = "Unmapped"
  }

  struct BinaryString: Hashable {
    let string: String?
    let type: StringType
  }

  enum DYLD: String {
    case rebaseInfo = "Rebase"
    case bindInfo = "Bind"
    case weakBind = "Weak Bind"
    case lazyBind = "Lazy Bind"
    case fixups = "Fixups"
    case exports = "Exports"
    case stringTable = "String Table"
  }

  case strings(BinaryString)
  case headers
  case externalMethods
  case codeSignature
  case functionStarts
  case dyld(DYLD)
  case binary(AnyBinaryDetails)

  static func binary(_ details: BinaryDetails) -> Self {
    Self.binary(AnyBinaryDetails(details: details))
  }
}

enum ModuleType: Hashable {
  case swift
  case objcPrefix
  case thirdParty
  case CPlusPlus
  // A helpful grouping but shouldn't be used in module size visualizations
  case grouping

  var treemapType: TreemapType? {
    switch self {
    case .swift:
      return .swiftModule
    case .objcPrefix, .thirdParty, .CPlusPlus:
      return .objcPrefix
    case .grouping:
      return nil
    }
  }
}

extension SwiftSymbol: Hashable {
  public static func == (lhs: SwiftSymbol, rhs: SwiftSymbol) -> Bool {
    lhs.description == rhs.description
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(description)
  }

}

extension SwiftSymbol {

  var identifier: String? {
    var queue = [SwiftSymbol]()
    queue.append(self)
    while !queue.isEmpty {
      let item = queue.removeFirst()
      switch item.kind {
      case .identifier:
        switch item.contents {
        case .none, .index:
          return nil
        case .name(let name):
          return name
        }
      default:
        queue.append(contentsOf: item.children)
      }
    }
    return nil
  }

  var testName: [String] {
    switch self.kind {
    case .global:
      for child in children {
        let result = child.testName
        if result.count > 0 {
          return result
        }
      }
      return []
    case .module, .identifier:
      switch contents {
      case .none, .index:
        return []
      case .name(let name):
        return [name]
      }
    case .lazyProtocolWitnessTableAccessor, .protocolWitnessTableAccessor:
      return children[0].testName
    case .baseWitnessTableAccessor:
      return children[0].testName
    case .boundGenericClass:
      return children[0].testName
    case .protocolConformance:
      return children[0].testName
    case .protocolWitness:
      let conformingFunction = children[1]
      return children[0].testName + ((conformingFunction.identifier.map { [$0] }) ?? [])
    case .privateDeclName:
      if children.count >= 2 {
        return children[1].testName
      } else {
        // An initializer doesn't have a name so it could be a private declaration with only one child element
        return []
      }
    case .extension:
      // First child contains the module this is declared in, more than 2 children can be for generic requirement
      if children.count >= 2 {
        return children[1].testName
      } else {
        preconditionFailure("Invalid extension")
      }
    case .iVarDestroyer:
      return firstComponent(appending: "ivar_destroyer")
    case .deallocator:
      return firstComponent(appending: "deallocator")
    case .initializer:
      // This is used for variable initializers like "variable initialization expression of Lottie.ShapeNode.isEnabled : Swift.Bool ["Lottie", "ShapeNode", "isEnabled", "init"]"
      return firstComponent(appending: "init")
    case .variable:
      return children.filter { $0.kind != .type }.flatMap { $0.testName }
    case .explicitClosure, .implicitClosure:
      if children.count >= 1 {
        return children[0].testName
      } else {
        return []
      }
    case .defaultArgumentInitializer:
      return children.first?.testName ?? []
    case .typeAlias, .protocol, .enum, .structure, .class:
      return children.flatMap { $0.testName }
    case .function:
      if children.count >= 3, children[2].kind == .labelList,
        let functionName = children[1].testName.first
      {
        let typeName = children[0].testName
        let argumentLabels = children[2].children.flatMap { $0.testName }
        if argumentLabels.isEmpty {
          return typeName + [functionName]
        } else {
          return typeName + [functionName + "(\(argumentLabels.joined(separator: ",")))"]
        }
      }
      return children.flatMap { $0.testName }
    case .constructor, .allocator:
      if children.count >= 2, children[1].kind == .labelList {
        let typeName = children[0].testName
        let argumentLabels = children[1].children.flatMap { $0.testName }
        if argumentLabels.isEmpty {
          return typeName + ["init"]
        } else {
          return typeName + ["init" + "(\(argumentLabels.joined(separator: ",")))"]
        }
      }
      return children.flatMap { $0.testName }
    case .typeMetadataAccessFunction:
      return firstComponent(appending: "typeMetadataAccess")
    case .typeMetadataCompletionFunction:
      return firstComponent(appending: "typeMetadataCompletion")
    case .outlinedDestroy:
      return firstComponent(appending: "outlined destory")
    case .outlinedRelease:
      return firstComponent(appending: "outlined release")
    case .outlinedRetain:
      return firstComponent(appending: "outlined retain")
    case .outlinedInitializeWithCopy, .outlinedInitializeWithTake:
      return firstComponent(appending: "outlined init")
    case .outlinedAssignWithCopy, .outlinedAssignWithTake:
      return firstComponent(appending: "outlined assign")
    case .getter:
      return firstComponent(appending: "getter")
    case .setter:
      return firstComponent(appending: "setter")
    case .didSet:
      return firstComponent(appending: "didset")
    case .willSet:
      return firstComponent(appending: "willset")
    case .unsafeMutableAddressor:
      return firstComponent(appending: "addressor")
    case .objcMetadataUpdateFunction:
      return firstComponent(appending: "metadata update")
    case .destructor:
      return firstComponent(appending: "deinit")
    case .modifyAccessor:
      return children.flatMap { $0.testName }
    case .partialApplyForwarder, .partialApplyObjCForwarder:
      return children.flatMap { $0.testName }
    case .type:
      return children.flatMap { $0.testName }
    case .valueWitness:
      return firstComponent(appending: "value witness")
    case .static:
      return children.flatMap { $0.testName }
    case .typeMangling:
      return children.flatMap { $0.testName }
    default:
      return []
    }
  }

  func firstComponent(appending suffix: String) -> [String] {
    if let result = children.first?.testName {
      return result + [suffix]
    }
    return []
  }

  var module: String? {
    var genericSpecializationType: String?
    var queue = [SwiftSymbol]()
    queue.append(self)
    let moduleOrSpecialization: (String) -> String = { module in
      if let generic = genericSpecializationType, module == "Swift" {
        return generic
      }
      return module
    }
    while !queue.isEmpty {
      let item = queue.removeFirst()
      switch item.kind {
      case .module:
        return moduleOrSpecialization(item.description)
      case .moduleDescriptor:
        //Swift.logger.debug("This is a module descriptor \(item.description)")
        queue.append(contentsOf: item.children)
      case .boundGenericEnum:
        for child in item.children {
          if child.kind == .typeList && genericSpecializationType == nil {
            genericSpecializationType = child.module
          }
        }
        queue.append(contentsOf: item.children)
      case .genericSpecialization:
        // TODO: Only use the generic specialization param if the module was "Swift" (or other non-intresting modules)
        for child in item.children {
          if child.kind == .genericSpecializationParam && genericSpecializationType == nil {
            genericSpecializationType = child.module
          }
        }
      default:
        queue.append(contentsOf: item.children)
      }
    }
    return nil
  }

  var typeName: String? {
    var queue = [SwiftSymbol]()
    var fallbackName: String? = nil
    queue.append(self)
    while !queue.isEmpty {
      let item = queue.removeFirst()
      switch item.kind {
      case .enum:
        if item.module == "Swift" {
          fallbackName = item.children.lazy.compactMap { $0.typeName }.first
        } else {
          queue.append(contentsOf: item.children)
        }
      case .identifier:
        switch item.contents {
        case .name(let name):
          return name
        default:
          break
        }
      case .function:
        if let subFunction = item.children.first(where: { $0.kind == .function }),
          let typeName = subFunction.typeName
        {
          return typeName
        } else {
          fallthrough
        }
      case .variable:
        let filteredChildren = item.children.filter({
          $0.kind != .identifier && $0.kind != .localDeclName
        })
        queue.append(contentsOf: filteredChildren)
      case .extension:
        // First child is the module the extension is in
        queue.append(contentsOf: item.children.dropFirst())
      case .labelList:
        break
      case .module:
        break
      case .privateDeclName:
        let filteredChildren = item.children.filter { symbol in
          guard symbol.kind == .identifier else { return true }

          switch symbol.contents {
          case .name(let name):
            return !name.starts(with: "_")
          default:
            break
          }
          return true
        }
        queue.append(contentsOf: filteredChildren)
      default:
        queue.append(contentsOf: item.children)
      }
    }
    return fallbackName
  }

  var droppingModule: String {
    if let module = self.module, description.hasPrefix("\(module).") {
      var result = description
      result.removeFirst("\(module).".count)
      return result
    }
    return description
  }
}

struct BinaryModule: Hashable {
  let name: String
  let type: ModuleType
}

protocol BinaryDetails {
  var module: BinaryModule? { get }

  // Should include the module
  var path: [String] { get }
}

struct AnyBinaryDetails: BinaryDetails, Hashable {
  init(details: BinaryDetails) {
    module = details.module

    let parentGrouping: String?
    if let module = module?.name {
      if module.hasSuffix("Feature") {
        parentGrouping = "Feature"
      } else if module.hasSuffix("FeatureInterface") {
        parentGrouping = "FeatureInterface"
      } else if module.hasSuffix("Service") {
        parentGrouping = "Service"
      } else if module.hasSuffix("ServiceInterface") {
        parentGrouping = "ServiceInterface"
      } else if module.hasSuffix("Plugin") {
        parentGrouping = "Plugin"
      } else if module.hasSuffix("CoreUI") || module.hasSuffix("PrivateUI")
        || module.hasSuffix("SharedUI")
      {
        parentGrouping = "UI"
      } else if module.hasSuffix("Foundation") {
        parentGrouping = "Foundation"
      } else if module.hasSuffix("Adapter") {
        parentGrouping = "Adapter"
      } else {
        parentGrouping = nil
      }
    } else {
      parentGrouping = nil
    }

    if let parentGrouping = parentGrouping {
      path = [parentGrouping] + details.path
    } else {
      path = details.path
    }
  }

  let module: BinaryModule?

  let path: [String]
}

protocol ObjcMethodSupporting: BinaryDetails {
  func method(named name: String) -> BinaryDetails
}

// Actually used for ObjC class or protocol metadata
struct ObjcClassDetails: ObjcMethodSupporting {
  init(className: String, in app: String) {
    if className.starts(with: "_Tt"),
      let symbol = try? CwlDemangle.parseMangledSwiftSymbol(className)
    {
      let moduleName = symbol.module ?? symbol.description
      module = BinaryModule(name: moduleName, type: .swift)
      typeName = symbol.typeName ?? symbol.droppingModule
      return
    }

    let moduleName = ModuleName(type: className, in: app)
    switch moduleName {
    case .fullName(_):
      // TODO: Group these together as Objc classes
      module = nil
      typeName = className
    case .thirdParty(.CPlusPlus):
      // This case should never happen because this is used for objc class metadata
      preconditionFailure("Encountered C++ grouping for objc class metadata")
    case .thirdParty(let thirdPartyName):
      module = BinaryModule(name: thirdPartyName.rawValue, type: .thirdParty)
      typeName = nil
    case .prefix(let prefix):
      module = BinaryModule(name: prefix, type: .objcPrefix)
      typeName = className
    }
  }

  func method(named name: String) -> BinaryDetails {
    if let typeName = typeName {
      return ObjCMethodDetails(module: module, typeName: typeName, methodName: name)
    }
    return self
  }

  let typeName: String?
  let module: BinaryModule?
  func path(typeSuffix: String) -> [String] {
    if let typeName = typeName {
      return [module?.name, typeName, typeSuffix].compactMap { $0 }
    } else {
      return [module?.name].compactMap { $0 }
    }
  }
  var path: [String] {
    path(typeSuffix: "Objc Metadata")
  }
}

struct ObjCMethodDetails: BinaryDetails {
  let module: BinaryModule?
  let typeName: String
  let methodName: String

  var path: [String] {
    [module?.name, typeName, methodName].compactMap { $0 }
  }
}

struct ObjCCategoryDetails: ObjcMethodSupporting {
  init(categoryName: String, conformingName: String?, in app: String) {
    if let name = conformingName {
      let classDetails = ObjcClassDetails(className: name, in: app)
      self.classDetails = classDetails
      module = classDetails.module
      path = classDetails.path(typeSuffix: "Objc Category")
    } else {
      // This seems to happen when the type is Swift but has an extension with @objc or overriden methods.
      if let thirdPartyModule = categoryName.thirdPartySwiftBinaryModule(in: app) {
        classDetails = nil
        module = thirdPartyModule
        path = [thirdPartyModule.name]
      } else {
        let classDetails = ObjcClassDetails(className: categoryName, in: app)
        self.classDetails = classDetails
        module = classDetails.module
        path = classDetails.path(typeSuffix: "Objc Category")
      }
    }
  }

  func method(named name: String) -> BinaryDetails {
    guard let classDetails = classDetails else {
      return self
    }

    return classDetails.method(named: name)
  }

  let classDetails: ObjcClassDetails?

  let module: BinaryModule?
  let path: [String]
}

struct SwiftImplementationDetails: BinaryDetails {
  init(details: SwiftTypeDetails) {
    module = details.module
    path = details.typePath
  }

  var module: BinaryModule?
  let path: [String]
}

struct SwiftTypeDetails: BinaryDetails {

  private init(module: BinaryModule?, typePath: [String]) {
    self.module = module
    self.typePath = typePath
  }

  init(moduleName: String, in app: String) {
    let module = moduleName.swiftBinaryModule(in: app)
    self.module = module
    typePath = [module.name]
  }

  static func boundProtocolConformance(
    details: SymbolTableDetails
  ) -> Self {
    SwiftTypeDetails(module: details.module, typePath: details.path)
  }

  static func objcProtocolConformance(details: ObjcClassDetails) -> Self {
    if details.path.count > 1 {
      return SwiftTypeDetails(module: details.module, typePath: details.path.dropLast())
    } else {
      return SwiftTypeDetails(module: details.module, typePath: details.path)
    }
  }

  func childType(named name: String, in app: String) -> SwiftTypeDetails {
    if typePath.count == 1 && typePath[0] == "__C" {
      // This is an ObjC type bridged to Swift, attempt to get an ObjC prefix module
      let moduleName = ModuleName(type: name, in: app)
      switch moduleName {
      case .thirdParty(.CPlusPlus), .fullName:
        // Nothing we can do to further refine the module, stick with __C
        return appendingPath(name: name)
      case .thirdParty(let thirdPartyName):
        return SwiftTypeDetails(
          module: .init(name: thirdPartyName.rawValue, type: .thirdParty),
          typePath: [thirdPartyName.rawValue]
        )
      case .prefix(let prefix):
        return SwiftTypeDetails(
          module: .init(name: prefix, type: .objcPrefix),
          typePath: [prefix, name]
        )
      }
    } else {
      return appendingPath(name: name)
    }
  }

  var implementation: SwiftImplementationDetails {
    SwiftImplementationDetails(details: self)
  }

  private func appendingPath(name: String) -> SwiftTypeDetails {
    return SwiftTypeDetails(module: module, typePath: typePath + [name])
  }

  var module: BinaryModule?
  let typePath: [String]

  var path: [String] {
    guard module?.type != .thirdParty else { return typePath }

    return typePath + ["Swift Metadata"]
  }
}

struct SymbolTableDetails: BinaryDetails {
  init?(name: String, in app: String, containsGo: Bool = false) {
    if name.starts(with: "_$s") {
      if let symbol = try? CwlDemangle.parseMangledSwiftSymbol(name),
        let module = symbol.binaryModule(in: app)
      {
        self.module = module

        if module.type == .thirdParty {
          path = [module.name]
        } else {
          let detailedResult = Array(symbol.testName.dropFirst())
          if detailedResult.count > 0 {
            path = [module.name] + detailedResult
          } else {
            let name = symbol.typeName ?? symbol.droppingModule
            path = [module.name, name]
          }
        }
        return
      }
      return nil
    } else if let range = name.range(of: #"(\+|-)\[\S*\s\S*]"#, options: .regularExpression),
      let typeName = name[range].dropFirst(2).dropLast().split(separator: " ").first
    {
      var stringTypeName = String(typeName)
      if let categoryStart = stringTypeName.firstIndex(of: "(") {
        stringTypeName = String(stringTypeName[stringTypeName.startIndex..<categoryStart])
      }
      stringTypeName = stringTypeName.trimmingCharacters(in: .init(["_"]))
      let objcClassDetails = ObjcClassDetails(className: stringTypeName, in: app)
      if let functionName = name[range].dropFirst(2).dropLast().split(separator: " ").last {
        let objcMethodDetails = objcClassDetails.method(named: String(functionName))
        module = objcMethodDetails.module
        path = objcMethodDetails.path
      } else {
        module = objcClassDetails.module
        path = [objcClassDetails.module?.name, objcClassDetails.typeName].compactMap { $0 }
      }
      return
    }
    if name.starts(with: "_OUTLINED_FUNCTION") || name.starts(with: "_globalinit_")
      || name.starts(with: "_block_") || name.starts(with: "___Block_")
      || name.starts(with: "___copy_") || name.starts(with: "___destroy")
      || name.starts(with: "___swift_") || name.starts(with: "_objectdestroy.")
    {
      return nil
    }
    if name.starts(with: "_C28") {
      return nil
    }
    if name.starts(with: "_") && name.dropFirst().allSatisfy({ $0.isLowercase }) && name.count == 21
    {
      return nil
    }
    if name.starts(with: "_") && name.count == 9 {
      return nil
    }
    if name.starts(with: "_b") && !name.dropFirst().contains("_") && name.dropFirst().count == 12 {
      return nil
    }
    let moduleName = ModuleName(type: name, in: app)
    switch moduleName {
    case .fullName(let fullName):
      module = nil
      if containsGo, name.hasPrefix("_") {
        path = name.goSymbolPath
      } else {
        path = [fullName]
      }
    case .thirdParty(.CPlusPlus) where name.starts(with: "__Z"):
      guard let path = Self.cPlusPlusSymbolToPath(name) else {
        fallthrough
      }

      self.path = path
      if path.count > 1 {
        module = BinaryModule(name: path.first!, type: .CPlusPlus)
      } else {
        module = nil
      }
    case .thirdParty(.CPlusPlus):
      module = BinaryModule(name: "C++", type: .grouping)
      path = ["C++"]
    case .prefix(let prefix):
      if containsGo, name.hasPrefix("_") {
        module = nil
        path = name.goSymbolPath
      } else {
        module = BinaryModule(name: prefix, type: .objcPrefix)
        path = [prefix, name]
      }
    case .thirdParty(let thirdParty):
      module = BinaryModule(name: thirdParty.rawValue, type: .thirdParty)
      path = [thirdParty.rawValue]
    }
  }

  private static func cPlusPlusSymbolToPath(_ name: String) -> [String]? {
    guard let demangled = Demangler.demangle(name), !demangled.isEmpty else {
      return nil
    }

    let symbol = CPlusPlusParser.parse(symbol: demangled).cannonicalSymbol
    let symbolPath = symbol.cannonicalSymbol.path.filter { !$0.isEmpty }
    guard !symbolPath.isEmpty && symbolPath.first != "" else {
      return nil
    }

    return symbolPath
  }

  let module: BinaryModule?
  let path: [String]
}

extension SwiftSymbol {

  // Next: Also check if it's third party
  func binaryModule(in app: String) -> BinaryModule? {
    guard let module = module else { return nil }

    if module == "__C", let typeName = typeName {
      let objcPrefix = typeName.trimmingCharacters(in: .init(["_"])).objcPrefix
      if objcPrefix.count > 2 {
        return BinaryModule(name: objcPrefix, type: .objcPrefix)
      }
    }
    return module.swiftBinaryModule(in: app)
  }
}

extension String {
  func thirdPartySwiftBinaryModule(in app: String) -> BinaryModule? {
    let thirdPartyName = ThirdPartyModuleName.forEach(\.swiftModules, in: app) {
      thirdPartyModule,
      name -> ThirdPartyModuleName? in
      if self == name {
        return thirdPartyModule
      }
      return nil
    }

    if let thirdPartyName = thirdPartyName {
      return BinaryModule(name: thirdPartyName.rawValue, type: .thirdParty)
    }
    return nil
  }

  func swiftBinaryModule(in app: String) -> BinaryModule {
    if let thirdPartyModule = thirdPartySwiftBinaryModule(in: app) {
      return thirdPartyModule
    }
    return BinaryModule(name: self, type: .swift)
  }
}

extension String {
  var goSymbolPath: [String] {
    self.trimmingCharacters(in: CharacterSet(charactersIn: "_")).split(separator: ".").filter {
      !$0.isEmpty
    }.map { String($0) }
  }
}
