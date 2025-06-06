//
//  BinarySeparator.swift
//  AppSizeAnalyzer
//
//  Created by Noah Martin on 11/14/20.
//

import CwlDemangle
import Foundation
import MachO
import Capstone
import ObjcSupport

extension MethodSignatureResolver {
  public static func isMethodSignature(_ input: String) -> Bool {
    if input.range(of: "\\d+@", options: .regularExpression) != nil {
      return checkMethodSignature(input)
    }
    return false
  }
}

public typealias DSYMs = [String: URL]

public final class BinarySeparator {
  public init(
    url: URL,
    dsym: DSYMs,
    appId: String,
    capstone: Capstone,
    skipSwiftMetadataParsing: Bool,
    skipInstructionDisassembly: Bool,
    skipExtraAssetCatalogImageProcessing: Bool
  ) {
    self.url = url
    self.dsym = dsym
    self.appId = appId
    data = try! NSMutableData(contentsOf: url, options: .alwaysMapped)
    bytes = data.bytes
    self.capstone = capstone
    self.skipSwiftMetadataParsing = skipSwiftMetadataParsing
    self.skipInstructionDisassembly = skipInstructionDisassembly
    self.skipExtraAssetCatalogImageProcessing = skipExtraAssetCatalogImageProcessing
  }

  let data: NSMutableData
  let bytes: UnsafeRawPointer
  var encrypted: Bool = false
  var cstringSection: section_64?
  var ustringSection: section_64?
  var cfstringSection: section_64?
  var strings: Set<String>?
  var appId: String
  var swiftBoundSymbols = [BoundSymbolAddress]()
  var usesChainedFixups = false
  var importedSymbols = [String]()

  let capstone: Capstone
  let skipSwiftMetadataParsing: Bool
  let skipInstructionDisassembly: Bool
  let skipExtraAssetCatalogImageProcessing: Bool

  // Size of cString section
  var cfStringsSize: UInt64 = 0
  var swiftFileSize: UInt64 = 0
  var componentPathSize: UInt64 = 0
  var objcTypeSize: UInt64 = 0
  var objcTypeStrings = [UInt64: String]()
  var largeOtherStrings = [CString]()
  var previewProviders = [(String, String)]()
  var dataInCode = [data_in_code_entry]()

  struct DylibLoadCommand {
    let path: String
    let weak: Bool
  }
  var dylibs = [DylibLoadCommand]()

  let dsym: DSYMs
  public var uuid: String?
  var loadCommands: [LoadCommand] = []

  func sectionEnd(for vmAddress: UInt64) -> UInt64? {
    for command in loadCommands {
      if vmAddress >= command.vmStart && vmAddress < command.vmStart + command.vmSize {
        guard command.sections.count > 0 else {
          return nil
        }

        for section in command.sections {
          if vmAddress >= section.vmStart && vmAddress < section.vmStart + section.size {
            return section.vmStart + section.size
          }
        }
      }
    }
    return nil
  }

  func sectionName(for vmAddress: UInt64) -> String? {
    for command in loadCommands {
      if vmAddress >= command.vmStart && vmAddress < command.vmStart + command.vmSize {
        guard command.sections.count > 0 else {
          #warning("Some segments have no sections")
          return nil
        }

        for section in command.sections {
          if vmAddress >= section.vmStart && vmAddress < section.vmStart + section.size {
            return "\(command.name)/\(section.name)"
          }
        }
      }
    }
    return nil
  }

  func vmAddress(for fileOffset: UInt64) -> UInt64? {
    for command in loadCommands {
      if fileOffset >= command.fileStart && fileOffset < command.fileStart + command.fileSize {
        guard command.sections.count > 0 else {
          #warning("Some segments have no sections")
          return nil
        }

        for section in command.sections {
          if fileOffset >= section.fileStart && fileOffset < section.fileStart + section.size {
            return section.vmStart + (fileOffset - section.fileStart)
          }
        }
      }
    }
    return nil
  }

  func fileOffset(for vmAddress: UInt64) -> UInt64? {
    for command in loadCommands {
      if vmAddress >= command.vmStart && vmAddress < command.vmStart + command.vmSize {
        guard command.sections.count > 0 else {
          #warning("Some segments have no sections")
          return nil
        }

        for section in command.sections {
          if vmAddress >= section.vmStart && vmAddress < section.vmStart + section.size {
            return section.fileStart + (vmAddress - section.vmStart)
          }
        }
      }
    }
    return nil
  }

  func treemapElements(totalSize: UInt) -> BinaryTreemapElement {
    let extraCodeSignatureSize = url.extraCodeSignatureSize()
    let strings = BinaryTreemapElement(name: "Strings", size: 0, type: .string, children: [])
    let modules = BinaryTreemapElement(name: "Modules", size: 0, type: .modules, children: [])
    let functionStarts = BinaryTreemapElement(
      name: "Function Starts",
      size: 0,
      type: .modules,
      children: []
    )
    let dyld = BinaryTreemapElement(name: "DYLD", size: 0, type: .dyld, children: [])
    let codeSignature = BinaryTreemapElement(
      name: "Code Signature",
      size: extraCodeSignatureSize,
      type: .codeSignature,
      children: []
    )
    let externalMethods = BinaryTreemapElement(
      name: "External Methods",
      size: 0,
      type: .externalMethods,
      children: []
    )
    let macho = BinaryTreemapElement(name: "Mach-O", size: 0, type: .macho, children: [])
    var unmappedSize: UInt = 0
    var nextMappedOffset: UInt = 0
    classRangeMap.forEachRange { offset, size, binaryTag in
      while offset > nextMappedOffset {
        let oldOffset = nextMappedOffset
        var lowestFound = offset
        let maxSizeToAdd = offset - nextMappedOffset
        // Need to fallback to the load commands and increment nextMappedOffset to equal offset
        for command in self.loadCommands {
          if command.contains(fileOffset: nextMappedOffset) {
            let treemapCommand: BinaryTreemapElement
            if let command = macho.children[command.name] {
              treemapCommand = command
            } else {
              treemapCommand = BinaryTreemapElement(name: command.name, size: 0, type: .macho)
              macho.add(child: treemapCommand)
            }
            var foundSection: Bool = false
            // It's in this command
            for section in command.sections {
              if section.contains(fileOffset: nextMappedOffset) {
                foundSection = true
                // This is the section to add
                let sizeToAdd = min(
                  maxSizeToAdd,
                  UInt(section.size) - (nextMappedOffset - UInt(section.fileStart))
                )
                nextMappedOffset += sizeToAdd
                treemapCommand.addChild(
                  named: section.name,
                  at: [],
                  size: sizeToAdd,
                  firstPathType: nil
                )
                break
              } else if section.fileStart > nextMappedOffset && lowestFound > section.fileStart {
                lowestFound = UInt(section.fileStart)
              }
            }
            if !foundSection {
              let commandEnd = UInt(command.fileStart + command.fileSize)
              if commandEnd < lowestFound {
                lowestFound = commandEnd
              }
              let sizeToAdd = min(maxSizeToAdd, lowestFound - nextMappedOffset)
              nextMappedOffset += sizeToAdd
              treemapCommand.increaseSize(by: sizeToAdd)
            }
            break
          } else if command.fileStart > nextMappedOffset && lowestFound > command.fileStart {
            lowestFound = UInt(command.fileStart)
          }
        }

        // Didn't increase offset at all, include unmapped
        if oldOffset == nextMappedOffset {
          logger.info("None found, using lowest \(lowestFound)")
          unmappedSize += lowestFound - nextMappedOffset
          nextMappedOffset = lowestFound
        }
        // Make sure some progress was made
        assert(oldOffset != nextMappedOffset)
      }
      assert(nextMappedOffset == offset)

      nextMappedOffset += size
      switch binaryTag {
      case .codeSignature:
        codeSignature.increaseSize(by: size)
      case .externalMethods:
        externalMethods.increaseSize(by: size)
      case .headers:
        macho.addChild(named: "Headers", at: [], size: size, firstPathType: nil)
      case .dyld(let dyldType):
        dyld.addChild(named: dyldType.rawValue, at: [], size: size, firstPathType: nil)
      case .functionStarts:
        functionStarts.increaseSize(by: size)
      case .strings(let stringType):
        let stringArray = stringType.string.map { [$0] } ?? []
        strings.addChild(named: stringType.type.rawValue, at: [], size: size, firstPathType: nil)
      case .binary(let binaryDetails):
        let module = binaryDetails.module
        let path = binaryDetails.path
        modules.addChild(
          named: path.last!,
          parentGrouping: nil,
          at: path.dropLast(),
          size: size,
          firstPathType: module?.type.treemapType
        )
      }
    }
    return BinaryTreemapElement(
      name: url.lastPathComponent,
      size: totalSize + extraCodeSignatureSize,
      type: nil,
      children: [
        strings,
        modules,
        dyld,
        codeSignature,
        externalMethods,
        functionStarts,
        macho,
      ].filter { $0.size > 0 }
    )
  }

  public func processLoadCommands() -> Int {
    var headerSize = 0
    let startingBytes = self.bytes
    var commands = [LoadCommand]()
    var boundSymbols = [BoundSymbol]()
    headerSize += MemoryLayout<mach_header_64>.size
    startingBytes.processLoadComands { command, commandPointer in
      headerSize += Int(command.cmdsize)
      switch command.cmd {
      case UInt32(LC_SEGMENT_64):
        let segmentCommand = commandPointer.load(as: segment_command_64.self)
        let segnameTuple = segmentCommand.segname
        let segname = Name(tuple: segnameTuple).string
        var sectionBytes = commandPointer.advanced(by: MemoryLayout<segment_command_64>.size)
        var sections = [BinarySection]()
        for _ in 0..<segmentCommand.nsects {
          let section = sectionBytes.load(as: section_64.self)
          guard section.offset > 0 else { continue }

          let sectionNameTuple = section.sectname
          let sectionName = Name(tuple: sectionNameTuple).string
          if sectionName == "__cstring" {
            cstringSection = section
          }
          if sectionName == "__ustring" {
            ustringSection = section
          }
          if sectionName == "__cfstring" {
            cfstringSection = section
          }
          sections.append(
            .init(
              name: sectionName,
              size: section.size,
              vmStart: section.addr,
              fileStart: UInt64(section.offset)
            )
          )
          sectionBytes = sectionBytes.advanced(by: MemoryLayout<section_64>.size)
        }
        commands.append(
          LoadCommand(
            name: segname,
            fileStart: segmentCommand.fileoff,
            fileSize: segmentCommand.filesize,
            vmStart: segmentCommand.vmaddr,
            vmSize: segmentCommand.vmsize,
            sections: sections
          )
        )
      case UInt32(LC_SEGMENT):
        let segmentCommand = commandPointer.load(as: segment_command.self)
        let segnameTuple = segmentCommand.segname
        let segname = Name(tuple: segnameTuple).string
        var sectionBytes = commandPointer.advanced(by: MemoryLayout<segment_command>.size)
        var sections = [BinarySection]()
        for _ in 0..<segmentCommand.nsects {
          let section = sectionBytes.load(as: section.self)
          guard section.offset > 0 else { continue }

          let sectionNameTuple = section.sectname
          let sectionName = Name(tuple: sectionNameTuple).string
          sections.append(
            BinarySection(
              name: sectionName,
              size: UInt64(section.size),
              vmStart: UInt64(section.addr),
              fileStart: UInt64(section.offset)
            )
          )
          sectionBytes = sectionBytes.advanced(by: MemoryLayout<section>.size)
        }
        commands.append(
          LoadCommand(
            name: segname,
            fileStart: UInt64(segmentCommand.fileoff),
            fileSize: UInt64(segmentCommand.filesize),
            vmStart: UInt64(segmentCommand.vmaddr),
            vmSize: UInt64(segmentCommand.vmsize),
            sections: sections
          )
        )
      case UInt32(LC_DYLD_INFO_ONLY):
        let dyldCommand = commandPointer.load(as: dyld_info_command.self)
        classRangeMap.add(
          .init(
            offset: UInt64(dyldCommand.rebase_off),
            size: UInt(dyldCommand.rebase_size),
            value: .dyld(.rebaseInfo)
          )
        )
        classRangeMap.add(
          .init(
            offset: UInt64(dyldCommand.bind_off),
            size: UInt(dyldCommand.bind_size),
            value: .dyld(.bindInfo)
          )
        )
        classRangeMap.add(
          .init(
            offset: UInt64(dyldCommand.weak_bind_off),
            size: UInt(dyldCommand.weak_bind_size),
            value: .dyld(.weakBind)
          )
        )
        classRangeMap.add(
          .init(
            offset: UInt64(dyldCommand.lazy_bind_off),
            size: UInt(dyldCommand.lazy_bind_size),
            value: .dyld(.lazyBind)
          )
        )
        classRangeMap.add(
          .init(
            offset: UInt64(dyldCommand.export_off),
            size: UInt(dyldCommand.export_size),
            value: .dyld(.exports)
          )
        )
        let bindPointer = bytes.advanced(by: Int(dyldCommand.bind_off))
        boundSymbols = bindPointer.readBoundSymbols(size: UInt(dyldCommand.bind_size))
      case UInt32(LC_DYLD_EXPORTS_TRIE):
        let exportscommand = commandPointer.load(as: linkedit_data_command.self)
        classRangeMap.add(
          .init(
            offset: UInt64(exportscommand.dataoff),
            size: UInt(exportscommand.datasize),
            value: .dyld(.exports)
          )
        )
      case UInt32(LC_DYLD_CHAINED_FIXUPS):
        let exportscommand = commandPointer.load(as: linkedit_data_command.self)
        classRangeMap.add(
          .init(
            offset: UInt64(exportscommand.dataoff),
            size: UInt(exportscommand.datasize),
            value: .dyld(.fixups)
          )
        )
        let headerStart = bytes.advanced(by: Int(exportscommand.dataoff))
        let header = headerStart.load(as: dyld_chained_fixups_header.self)
        var importsStart = headerStart.advanced(by: Int(header.imports_offset))
        let startName = headerStart.advanced(by: Int(header.symbols_offset))
        logger.info("fixups version \(header.fixups_version)")
        logger.info("starts offset \(header.starts_offset)")
        logger.info("imports offset \(header.imports_offset)")
        logger.info("symbols offset \(header.symbols_offset)")
        logger.info("imports count \(header.imports_count)")
        logger.info("imports format \(header.imports_format)")
        logger.info("symbols format \(header.symbols_format)")
        let importsSize: Int
        let nameOffsetFromImport: (UnsafeRawPointer) -> Int
        switch header.imports_format {
        // DYLD_CHAINED_IMPORT
        case 1:
          importsSize = MemoryLayout<UInt32>.size
          nameOffsetFromImport = { pointer in return Int(pointer.load(as: UInt32.self) >> 9) }
        // DYLD_CHAINED_IMPORT_ADDEND
        case 2:
          importsSize = MemoryLayout<UInt32>.size * 2
          nameOffsetFromImport = { pointer in return Int(pointer.load(as: UInt32.self) >> 9) }
        // DYLD_CHAINED_IMPORT_ADDEND64
        case 3:
          importsSize = MemoryLayout<UInt64>.size * 2
          nameOffsetFromImport = { pointer in return Int(pointer.load(as: UInt64.self) >> 32) }
        default:
          importsSize = MemoryLayout<UInt32>.size
          logger.info("Unknown imports format, will fall back to 32 bit")
          nameOffsetFromImport = { pointer in return Int(pointer.load(as: UInt32.self) >> 9) }
        }
        for _ in 0..<header.imports_count {
          let nameOffset = nameOffsetFromImport(importsStart)
          var namePointer = startName.advanced(by: Int(nameOffset))
          let name = namePointer.readNullTerminatedString()
          importedSymbols.append(name)
          importsStart = importsStart.advanced(by: importsSize)
        }
        usesChainedFixups = true
      case UInt32(LC_FUNCTION_STARTS):
        let functionStartsCommand = commandPointer.load(as: linkedit_data_command.self)
        classRangeMap.add(
          .init(
            offset: UInt64(functionStartsCommand.dataoff),
            size: UInt(functionStartsCommand.datasize),
            value: .functionStarts
          )
        )
      case UInt32(LC_RPATH):
        let rpathCommand = commandPointer.load(as: rpath_command.self)
        var strPtr = commandPointer.advanced(by: Int(rpathCommand.path.offset))
        let strSize = rpathCommand.cmdsize - UInt32(MemoryLayout<rpath_command>.size)
        var strBytes = [UInt8]()
        for _ in 0..<strSize {
          let byte = strPtr.load(as: UInt8.self)
          strBytes.append(byte)
          strPtr = strPtr.advanced(by: 1)
        }
        strBytes.append(0)
        let _ = String(cString: strBytes)
      // This is not used for anything yet, but we could use it to more intelligently tell if the loaded dyilbs will be found at runtime
      case UInt32(LC_LOAD_DYLIB), UInt32(LC_LOAD_WEAK_DYLIB), UInt32(LC_REEXPORT_DYLIB):
        let command = commandPointer.load(as: dylib_command.self)
        var strPtr = commandPointer.advanced(by: Int(command.dylib.name.offset))
        let strSize = command.cmdsize - UInt32(MemoryLayout<dylib_command>.size)
        var strBytes = [UInt8]()
        for _ in 0..<strSize {
          let byte = strPtr.load(as: UInt8.self)
          strBytes.append(byte)
          strPtr = strPtr.advanced(by: 1)
        }
        strBytes.append(0)
        let name = String(cString: strBytes)
        dylibs.append(.init(path: name, weak: command.cmd == UInt32(LC_LOAD_WEAK_DYLIB)))
      case UInt32(LC_SYMTAB):
        let segmentCommand = commandPointer.load(as: symtab_command.self)

        classRangeMap.add(
          .init(
            offset: UInt64(segmentCommand.stroff),
            size: UInt(segmentCommand.strsize),
            value: .dyld(.stringTable)
          )
        )
      case UInt32(LC_ENCRYPTION_INFO_64):
        let encryptionCommand = commandPointer.load(as: encryption_info_command_64.self)
        if encryptionCommand.cryptid != 0 {
          encrypted = true
        }
        break
      case UInt32(LC_UUID):
        let uuidCommand = commandPointer.load(as: uuid_command.self)
        self.uuid = UUID(uuid: uuidCommand.uuid).uuidString
        break
      case UInt32(LC_CODE_SIGNATURE):
        let command = commandPointer.load(as: linkedit_data_command.self)
        classRangeMap.add(
          .init(
            offset: UInt64(command.dataoff),
            size: UInt(command.datasize),
            value: .codeSignature
          )
        )
      case UInt32(LC_DATA_IN_CODE):
        let command = commandPointer.load(as: linkedit_data_command.self)
        let numberOfEntries = Int(command.datasize) / MemoryLayout<data_in_code_entry>.size
        let typedPointer = bytes.advanced(by: Int(command.dataoff)).bindMemory(
          to: data_in_code_entry.self,
          capacity: numberOfEntries
        )
        let bufferPointer = UnsafeBufferPointer(start: typedPointer, count: numberOfEntries)
        dataInCode = Array(bufferPointer)
      default:
        break
      }
      return true
    }
    commands = commands.map { cmd in
      guard cmd.name == "__LINKEDIT" else { return cmd }

      var newCmd = cmd
      //      let sectionSize = newCmd.sections.map { $0.size }.reduce(0, +)
      //      let leftoverSize = newCmd.fileSize - sectionSize
      newCmd.sections += [
        BinarySection(
          name: "LINKEDIT",
          size: cmd.fileSize,
          vmStart: cmd.vmStart,
          fileStart: cmd.fileStart
        )
      ]
      return newCmd
    }
    loadCommands = commands
    swiftBoundSymbols = boundSymbols.filter { $0.symbol.starts(with: "_$s") }.map {
      $0.address(with: loadCommands)
    }
    swiftBoundSymbols.sort()
    classRangeMap.add(.init(offset: 0, size: UInt(headerSize), value: .headers))
    return headerSize
  }

  private func parseProtocolList() {
    guard
      let section = loadCommands.flatMap({ $0.sections }).first(where: {
        $0.name == "__objc_protolist"
      })
    else {
      return
    }

    let start = section.fileStart
    let size = section.size
    let protocolListPointers = parseUInt64(start: start, size: size)
    for (vmAddress, fileOffset) in protocolListPointers {
      if let moduleDetails = parseProtocol(vmAddress: rebase(vmAddress)) {
        classRangeMap.add(
          .init(offset: fileOffset, value: BinaryTag.binary(moduleDetails), of: UInt64.self)
        )
      } else {
        assertionFailure("Could not parse protocol list")
      }
    }
  }

  func parseObjcObjects() {
    guard !encrypted && !skipSwiftMetadataParsing else { return }

    parseSwiftProtocolConformance()
    parseSwiftProtocolDescriptors()
    parseSwiftTypes()
    parseClassList()
    parseProtocolList()
    parseMethodList()

    guard
      let textSection = loadCommands.filter({ $0.name == "__TEXT" }).first?.sections.filter({
        $0.name == "__text"
      }).first
    else { return }

    if let uuid = uuid, let dsym = dsym[uuid] {
      let dsymLoader = DsymLoader(url: dsym)
      dsymLoader.load()
      time("\(appId) DysymTime") {
        // The binary contains go code if _runtime.buildVersion is found in the data segment
        let containsGo =
          dsymLoader.foundAddress.first { (start, name) in
            if !textSection.contains(vmOffset: start) && name == "_runtime.buildVersion" {
              return true
            }
            return false
          } != nil
        // Will skip last element
        let filteredDsymElements = dsymLoader.foundAddress.compactMap {
          (start, name) -> (UInt, SymbolTableDetails)? in
          guard textSection.contains(vmOffset: start) else {
            return nil
          }
          if let elementName = SymbolTableDetails(
            name: name,
            in: appId,
            containsGo: containsGo
          ) {
            return (start, elementName)
          }
          return nil
        }
        let sortedElements = filteredDsymElements.sorted(by: { $0.0 < $1.0 })
        sortedElements.iterateByTwo { (firstTuple, secondTuple) in
          let start = firstTuple.0
          let element = firstTuple.1
          let secondStart = secondTuple?.0
          if element.module?.name == "Swift" {
            if toProcessAddress[Int(start)] == nil {
              toProcessAddress[Int(start)] = .binary(element)
            }
          } else {
            let size = parseMethod(
              vmStart: UInt64(start),
              named: .binary(element),
              maxEnd: secondStart.map { UInt64($0) }
            )
          }
        }
      }
    }

    repeat {
      let copiedAddresses = toProcessAddress
      toProcessAddress.removeAll()
      let keys = copiedAddresses.keys.sorted()
      keys.iterateByTwo { (key, nextAddress) in
        parseMethod(
          vmStart: UInt64(key),
          named: copiedAddresses[key]!,
          maxEnd: nextAddress.map { UInt64($0) }
        )
      }
    } while !toProcessAddress.isEmpty

    //    logger.debug("Before outlined functions \(outlinedFunctions.count)")
    //    let leftOutlinedFunctions = outlinedFunctions.subtracting(alreadyProcessedAddress.map { UInt($0) })
    //    logger.debug("Left outlined functions \(leftOutlinedFunctions.count)")
    //    for address in leftOutlinedFunctions.prefix(10) {
    //      logger.debug("Left outliend function \(address)")
    //    }
    //    let leftToProcess = toProcessAddress.subtracting(alreadyProcessedAddress.map { Int($0) })
    //    logger.debug("Left to process \(leftToProcess.count)")

    //    for (offset, name) in swiftDataSymbols {
    //      guard let fileOffset = fileOffset(for: UInt64(offset)) else { preconditionFailure("No file offset") }
    //
    //      if !classRangeMap.contains(address: UInt64(fileOffset)) {
    //        let symbolName = (try? CwlDemangle.parseMangledSwiftSymbol(name).description) ?? name
    //        logger.debug("The name \(symbolName) in \(sectionName(for: UInt64(offset))) at \(offset)")
    //      }
    //    }
  }

  var classRangeMap = RangeMap<BinaryTag>()

  // Map of file offsets for objc method names to module descriptions
  var objcMethNameToModule = [UInt64: BinaryModule]()

  var parsedSwiftOffsets = [UInt: SwiftTypeDetails]()

  private func parseSwiftProtocol(fileOffset: UInt, pointerStart: UInt64?) -> SwiftTypeDetails? {
    if let typeDescription = parsedSwiftOffsets[fileOffset] {
      if let pointerStart = pointerStart {
        classRangeMap.add(
          .init(offset: pointerStart, value: .binary(typeDescription), of: Int32.self)
        )
      }
      return typeDescription
    }

    let protocolDescriptor = bytes.advanced(by: Int(fileOffset)).load(as: ProtocolDescriptor.self)
    guard
      let parent = computeOffset(fileStart: fileOffset, object: protocolDescriptor, path: \.parent)
    else {
      assertionFailure("Protocol has no parent offset")
      return nil
    }

    guard let parentType = loadType(from: parent, pointerStart: nil) else { return nil }

    let nameLocation = computeOffset(
      fileStart: fileOffset,
      object: protocolDescriptor,
      path: \.name,
      canBeIndirect: false
    )!
    let (protocolName, size) = readNullTerminatedString(
      pointer: bytes.advanced(by: Int(nameLocation))
    )
    protocols.insert((parentType.typePath + [protocolName]).joined(separator: "."))
    let typeDetails = parentType.childType(named: protocolName, in: appId)
    let moduleDetails = BinaryTag.binary(typeDetails)

    if let pointerStart = pointerStart {
      classRangeMap.add(
        .init(offset: pointerStart, size: UInt(MemoryLayout<Int32>.size), value: moduleDetails)
      )
    }

    parsedSwiftOffsets[fileOffset] = typeDetails

    classRangeMap.add(
      .init(offset: UInt64(fileOffset), value: moduleDetails, of: ProtocolDescriptor.self)
    )

    classRangeMap.add(.init(offset: UInt64(nameLocation), size: UInt(size), value: moduleDetails))

    var trailingObjectOffset = fileOffset + UInt(MemoryLayout<ProtocolDescriptor>.stride)
    for _ in 0..<protocolDescriptor.numRequirementsInSignature {
      parseGenericRequirementDescriptor(
        requirementsStart: trailingObjectOffset,
        moduleDetails: typeDetails
      )
      trailingObjectOffset += UInt(MemoryLayout<TargetGenericRequirementDescriptor>.stride)
    }
    if protocolDescriptor.numRequirements != 0 {
      let requirmentSize = UInt(MemoryLayout<TargetProtocolRequirement>.stride)
      let requirementsStart = trailingObjectOffset
      classRangeMap.add(
        .init(
          offset: UInt64(requirementsStart),
          size: UInt(protocolDescriptor.numRequirements) * requirmentSize,
          value: moduleDetails
        )
      )
    }

    if protocolDescriptor.associatedTypeNames != 0 {
      let associatedTypeOffset = computeOffset(
        fileStart: fileOffset,
        object: protocolDescriptor,
        path: \.associatedTypeNames,
        canBeIndirect: false
      )!
      let (_, size) = readNullTerminatedString(
        pointer: bytes.advanced(by: Int(associatedTypeOffset))
      )
      classRangeMap.add(
        .init(offset: UInt64(associatedTypeOffset), size: UInt(size), value: moduleDetails)
      )
    }
    return typeDetails
  }

  private func parseGenericRequirementDescriptor(
    requirementsStart: UInt,
    moduleDetails: SwiftTypeDetails
  ) {
    parseGenericRequirementDescriptor(
      requirementsStart: requirementsStart,
      moduleDetails: .binary(moduleDetails)
    )
  }

  private func parseGenericRequirementDescriptor(requirementsStart: UInt, moduleDetails: BinaryTag)
  {
    let genericRequirement = bytes.advanced(by: Int(requirementsStart)).load(
      as: TargetGenericRequirementDescriptor.self
    )
    let flags = GenericRequirementFlags(rawFlags: genericRequirement.flags)
    let nameLocation = computeOffset(
      fileStart: requirementsStart,
      object: genericRequirement,
      path: \.param,
      canBeIndirect: false
    )!
    let mangledLength = readMangledNameLength(pointer: bytes.advanced(by: Int(nameLocation)))
    classRangeMap.add(
      .init(offset: UInt64(nameLocation), size: UInt(mangledLength), value: moduleDetails)
    )
    if flags.kind == .some(.BaseClass) {
      let nameLocation = computeOffset(
        fileStart: requirementsStart,
        object: genericRequirement,
        path: \.type,
        canBeIndirect: false
      )!
      let mangledLength = readMangledNameLength(pointer: bytes.advanced(by: Int(nameLocation)))
      classRangeMap.add(
        .init(offset: UInt64(nameLocation), size: UInt(mangledLength), value: moduleDetails)
      )
    }
    classRangeMap.add(
      .init(
        offset: UInt64(requirementsStart),
        value: moduleDetails,
        of: TargetGenericRequirementDescriptor.self
      )
    )
  }

  private func parseSwiftClass(fileOffset: UInt, pointerStart: UInt64?) -> SwiftTypeDetails? {
    if let typeDescription = parsedSwiftOffsets[fileOffset] {
      if let pointerStart = pointerStart {
        classRangeMap.add(
          .init(offset: pointerStart, value: .binary(typeDescription), of: Int32.self)
        )
      }
      return typeDescription
    }

    let classDescriptor = bytes.advanced(by: Int(fileOffset)).load(as: TargetClassDescriptor.self)

    if classDescriptor.parent == 0 {
      assertionFailure("Superclass typ is null")
      return nil
    }
    guard
      let parentOffset = computeOffset(
        fileStart: fileOffset,
        object: classDescriptor,
        path: \.parent,
        canBeIndirect: true
      )
    else {
      assertionFailure("Class has no parent offset")
      return nil
    }
    guard
      let nameLocation = computeOffset(
        fileStart: fileOffset,
        object: classDescriptor,
        path: \.name,
        canBeIndirect: false
      )
    else {
      return nil
    }
    let (name, size) = self.readNullTerminatedString(pointer: bytes.advanced(by: Int(nameLocation)))

    guard let parentType = loadType(from: parentOffset, pointerStart: nil) else {
      logger.warning("no module found for parent of \(name)")
      return nil
    }

    // TODO: User accessFunction
    let typeDescription = parentType.childType(named: name, in: appId)
    let moduleDetails = BinaryTag.binary(typeDescription)

    if let pointerStart = pointerStart {
      classRangeMap.add(
        .init(offset: pointerStart, size: UInt(MemoryLayout<Int32>.size), value: moduleDetails)
      )
    }
    parsedSwiftOffsets[fileOffset] = typeDescription

    classRangeMap.add(
      .init(offset: UInt64(fileOffset), value: moduleDetails, of: TargetClassDescriptor.self)
    )

    classRangeMap.add(.init(offset: UInt64(nameLocation), size: UInt(size), value: moduleDetails))

    if classDescriptor.fieldDescriptor != 0 {
      let fieldVMAddress =
        Int64(
          vmAddress(
            for: UInt64(fileOffset)
              + UInt64(MemoryLayout<ClassDescriptor>.offset(of: \ClassDescriptor.fieldDescriptor)!)
          )!
        ) + Int64(classDescriptor.fieldDescriptor)
      parseFieldDescriptor(from: UInt64(fieldVMAddress), moduleDescription: typeDescription)
    }
    let superclassType = computeOffset(
      fileStart: fileOffset,
      object: classDescriptor,
      path: \.superclassType,
      canBeIndirect: false
    )!
    //logger.debug(sectionName(for: vmAddress(for: UInt64(superclassType))!))
    let mangledNameLength = self.readMangledNameLength(
      pointer: bytes.advanced(by: Int(superclassType))
    )
    classRangeMap.add(
      .init(offset: UInt64(superclassType), size: UInt(mangledNameLength), value: moduleDetails)
    )

    var trailingObjectPointer = fileOffset + UInt(MemoryLayout<TargetClassDescriptor>.size)
    let flags = classDescriptor.flags
    let type = classDescriptor.typeFlags
    if flags.isGeneric {
      let genericContext = bytes.advanced(by: Int(trailingObjectPointer)).load(
        as: TargetTypeGenericContextDescriptorHeader.self
      )
      let parameterSize = Int(ceil(Double(genericContext.base.numberOfParams) / 4.0))
      let totalGenericSize =
        MemoryLayout<TargetTypeGenericContextDescriptorHeader>.size + parameterSize * 4 + Int(
          genericContext.base.numberOfRequirements
        )
        * MemoryLayout<TargetGenericRequirementDescriptor>.size

      classRangeMap.add(
        .init(
          offset: UInt64(trailingObjectPointer),
          size: UInt(totalGenericSize),
          value: moduleDetails
        )
      )
      trailingObjectPointer += UInt(totalGenericSize)
      //      trailingObjectPointer += UInt(MemoryLayout<TargetTypeGenericContextDescriptorHeader>.size)
      //      trailingObjectPointer += UInt(parameterSize * MemoryLayout<UInt32>.size)
      //      for _ in 0..<genericContext.base.numberOfRequirements {
      //        //let descriptor = data.bytes.advanced(by: Int(trailingObjectPointer)).load(as: TargetGenericRequirementDescriptor.self)
      //        //let paramVMAddress = UInt64(Int(vmAddress(for: UInt64(trailingObjectPointer))!) + Int(descriptor.param))
      //        //let paramFileOffset = self.fileOffset(for: paramVMAddress)!
      //        //let (name, _) = self.readNullTerminatedString(pointer: self.data.bytes.advanced(by: Int(paramFileOffset)))
      //        trailingObjectPointer += UInt(MemoryLayout<TargetGenericRequirementDescriptor>.size)
      //      }

    }
    guard !type.hasResilientSuperclass else {
      return typeDescription
    }
    guard !type.hasForeignMetadataInitialization else {
      return typeDescription
    }
    if type.hasSingletonMetadataInitialization {
      let singletonMetadata = bytes.advanced(by: Int(trailingObjectPointer)).load(
        as: TargetSingletonMetadataInitialization.self
      )
      if singletonMetadata.completionFunction != 0 {
        let functionFileAddress = computeOffset(
          fileStart: trailingObjectPointer,
          object: singletonMetadata,
          path: \.completionFunction,
          canBeIndirect: false
        )!
        let functionVM = vmAddress(for: UInt64(functionFileAddress))!
        if let name = sectionName(for: functionVM), name == "__TEXT/__text" {
          toProcessAddress[Int(functionVM)] = .binary(typeDescription.implementation)
        }
      }
      classRangeMap.add(
        .init(
          offset: UInt64(trailingObjectPointer),
          value: moduleDetails,
          of: TargetSingletonMetadataInitialization.self
        )
      )
      trailingObjectPointer += UInt(MemoryLayout<TargetSingletonMetadataInitialization>.size)
    }

    if type.hasVTable {
      let vTableHeader = bytes.advanced(by: Int(trailingObjectPointer)).load(
        as: TargetVTableDescriptorHeader.self
      )
      classRangeMap.add(
        .init(
          offset: UInt64(trailingObjectPointer),
          value: moduleDetails,
          of: TargetVTableDescriptorHeader.self
        )
      )
      let methodDescriptorsStart =
        Int(trailingObjectPointer) + MemoryLayout<TargetVTableDescriptorHeader>.size
      classRangeMap.add(
        .init(
          offset: UInt64(methodDescriptorsStart),
          size: UInt(MemoryLayout<TargetMethodDescriptor>.size * Int(vTableHeader.VTableSize)),
          value: moduleDetails
        )
      )
      for i in 0..<vTableHeader.VTableSize {
        let pointerFileOffset =
          methodDescriptorsStart + Int(i) * MemoryLayout<TargetMethodDescriptor>.size
        let descriptor = bytes.advanced(by: pointerFileOffset).load(as: TargetMethodDescriptor.self)
        if descriptor.impl != 0 {
          let methodVMAddress =
            Int(vmAddress(for: UInt64(pointerFileOffset))!) + Int(descriptor.impl)
          if methodVMAddress > 0 {
            toProcessAddress[Int(methodVMAddress + 4)] = .binary(typeDescription.implementation)
          }
        }
      }
    }
    return typeDescription
  }

  private func parseFieldDescriptor(
    from fieldVMAddress: UInt64,
    moduleDescription: SwiftTypeDetails
  ) {
    let fieldFileOffset = self.fileOffset(for: fieldVMAddress)!
    let fieldDescriptor = bytes.advanced(by: Int(fieldFileOffset)).load(as: FieldDescriptor.self)
    if fieldDescriptor.mangledTypeName != 0 {
      let nameVMOffset = Int(fieldVMAddress) + Int(fieldDescriptor.mangledTypeName)
      let nameOffset = self.fileOffset(for: UInt64(nameVMOffset))!
      let mangledNameLength = readMangledNameLength(pointer: bytes.advanced(by: Int(nameOffset)))
      classRangeMap.add(
        .init(offset: nameOffset, size: UInt(mangledNameLength), value: .binary(moduleDescription))
      )
    }
    let fieldDescriptorSize = MemoryLayout<FieldDescriptor>.size
    let numFields = Int(fieldDescriptor.numFields)
    let fieldSize = Int(fieldDescriptor.fieldRecordSize)
    classRangeMap.add(
      .init(
        offset: fieldFileOffset,
        size: UInt(fieldDescriptorSize + (numFields * fieldSize)),
        value: .binary(moduleDescription)
      )
    )
    let fieldRecordStart = Int(fieldFileOffset) + fieldDescriptorSize
    let nameOffset = MemoryLayout<FieldRecord>.offset(of: \FieldRecord.fieldName)!
    let typeNameOffset = MemoryLayout<FieldRecord>.offset(of: \FieldRecord.mangledTypeName)!
    for i in 0..<numFields {
      let recordStart = fieldRecordStart + i * fieldSize
      let record = bytes.advanced(by: recordStart).load(as: FieldRecord.self)
      if record.fieldName != 0 {
        let vmFieldName =
          Int(vmAddress(for: UInt64(recordStart + nameOffset))!) + Int(record.fieldName)
        let fileFieldName = self.fileOffset(for: UInt64(vmFieldName))!
        let (_, fieldNameSize) = readNullTerminatedString(
          pointer: bytes.advanced(by: Int(fileFieldName))
        )
        classRangeMap.add(
          .init(offset: fileFieldName, size: UInt(fieldNameSize), value: .binary(moduleDescription))
        )
      }
      if record.mangledTypeName != 0 {
        let vmTypeName =
          Int(vmAddress(for: UInt64(recordStart + typeNameOffset))!) + Int(record.mangledTypeName)
        let fileTypeName = self.fileOffset(for: UInt64(vmTypeName))!
        let mangledNameLength = readMangledNameLength(
          pointer: bytes.advanced(by: Int(fileTypeName))
        )
        classRangeMap.add(
          .init(
            offset: fileTypeName,
            size: UInt(mangledNameLength),
            value: .binary(moduleDescription)
          )
        )
      }
    }
  }

  private func parseSwiftStruct(from offset: UInt, pointerStart: UInt64?) -> SwiftTypeDetails? {
    if let typeDescription = parsedSwiftOffsets[offset] {
      if let pointerStart = pointerStart {
        classRangeMap.add(
          .init(
            offset: pointerStart,
            size: UInt(MemoryLayout<Int32>.size),
            value: .binary(typeDescription)
          )
        )
      }
      return typeDescription
    }
    let structDescriptor = bytes.advanced(by: Int(offset)).load(as: StructDescriptor.self)

    guard
      let parentOffset = computeOffset(fileStart: offset, object: structDescriptor, path: \.parent)
    else {
      assertionFailure("Struct has no parent offset")
      return nil
    }

    guard let parentType = loadType(from: parentOffset, pointerStart: nil) else {
      assertionFailure("Struct parent has no module")
      return nil
    }

    let nameLocation = computeOffset(
      fileStart: offset,
      object: structDescriptor,
      path: \.name,
      canBeIndirect: false
    )!
    let (structName, size) = self.readNullTerminatedString(
      pointer: bytes.advanced(by: Int(nameLocation))
    )

    let typeDescription = parentType.childType(named: structName, in: appId)
    let moduleDetails = BinaryTag.binary(typeDescription)

    parsedSwiftOffsets[offset] = typeDescription

    if let pointerStart = pointerStart {
      classRangeMap.add(
        .init(offset: pointerStart, size: UInt(MemoryLayout<Int32>.size), value: moduleDetails)
      )
    }

    if structDescriptor.fieldDescriptor != 0 {
      let fieldVMAddress =
        Int64(
          vmAddress(
            for: UInt64(offset)
              + UInt64(
                MemoryLayout<StructDescriptor>.offset(of: \StructDescriptor.fieldDescriptor)!
              )
          )!
        )
        + Int64(structDescriptor.fieldDescriptor)
      parseFieldDescriptor(from: UInt64(fieldVMAddress), moduleDescription: typeDescription)
    }
    classRangeMap.add(
      .init(offset: UInt64(offset), value: moduleDetails, of: StructDescriptor.self)
    )
    classRangeMap.add(.init(offset: UInt64(nameLocation), size: UInt(size), value: moduleDetails))
    var trailingObjectPointer = offset + UInt(MemoryLayout<StructDescriptor>.size)
    let flags = structDescriptor.flags
    let typeFlags = TypeContextDescriptorFlags(rawFlags: flags.kindSpecificFlags)
    if flags.isGeneric {
      let genericContext = bytes.advanced(by: Int(trailingObjectPointer)).load(
        as: TargetTypeGenericContextDescriptorHeader.self
      )
      let parameterSize = Int(ceil(Double(genericContext.base.numberOfParams) / 4.0))
      let totalGenericSize =
        MemoryLayout<TargetTypeGenericContextDescriptorHeader>.size + parameterSize * 4 + Int(
          genericContext.base.numberOfRequirements
        )
        * MemoryLayout<TargetGenericRequirementDescriptor>.size

      classRangeMap.add(
        .init(
          offset: UInt64(trailingObjectPointer),
          size: UInt(totalGenericSize),
          value: moduleDetails
        )
      )
      trailingObjectPointer += UInt(totalGenericSize)
    }
    guard !typeFlags.hasForeignMetadataInitialization else {
      return typeDescription
    }

    if typeFlags.hasSingletonMetadataInitialization {
      let singletonMetadata = bytes.advanced(by: Int(trailingObjectPointer)).load(
        as: TargetSingletonMetadataInitialization.self
      )
      if singletonMetadata.completionFunction != 0 {
        let functionFileAddress = computeOffset(
          fileStart: trailingObjectPointer,
          object: singletonMetadata,
          path: \.completionFunction,
          canBeIndirect: false
        )!
        let functionVM = vmAddress(for: UInt64(functionFileAddress))!
        toProcessAddress[Int(functionVM)] = .binary(typeDescription.implementation)
      }
      classRangeMap.add(
        .init(
          offset: UInt64(trailingObjectPointer),
          value: moduleDetails,
          of: TargetSingletonMetadataInitialization.self
        )
      )
      trailingObjectPointer += UInt(MemoryLayout<TargetSingletonMetadataInitialization>.size)
    }

    return typeDescription
  }

  private func parseSwiftEnum(from offset: UInt, pointerStart: UInt64?) -> SwiftTypeDetails? {
    if let typeDescription = parsedSwiftOffsets[offset] {
      if let pointerStart = pointerStart {
        classRangeMap.add(
          .init(
            offset: pointerStart,
            size: UInt(MemoryLayout<Int32>.size),
            value: .binary(typeDescription)
          )
        )
      }
      return typeDescription
    }

    let structDescriptor = bytes.advanced(by: Int(offset)).load(as: EnumDescriptor.self)

    guard
      let parentOffset = computeOffset(fileStart: offset, object: structDescriptor, path: \.parent)
    else {
      assertionFailure("Enum has no parent offset")
      return nil
    }

    guard let parentType = loadType(from: parentOffset, pointerStart: nil) else {
      assertionFailure("Enum parent has no module")
      return nil
    }

    let nameLocation = computeOffset(
      fileStart: offset,
      object: structDescriptor,
      path: \.name,
      canBeIndirect: false
    )!
    let (enumName, size) = self.readNullTerminatedString(
      pointer: bytes.advanced(by: Int(nameLocation))
    )
    let typeDescription = parentType.childType(named: enumName, in: appId)
    let moduleDetails = BinaryTag.binary(typeDescription)
    parsedSwiftOffsets[offset] = typeDescription

    if let pointerStart = pointerStart {
      classRangeMap.add(
        .init(offset: pointerStart, size: UInt(MemoryLayout<Int32>.size), value: moduleDetails)
      )
    }

    if structDescriptor.fieldDescriptor != 0 {
      let fieldVMAddress =
        Int64(
          vmAddress(
            for: UInt64(offset)
              + UInt64(MemoryLayout<EnumDescriptor>.offset(of: \EnumDescriptor.fieldDescriptor)!)
          )!
        )
        + Int64(structDescriptor.fieldDescriptor)
      parseFieldDescriptor(from: UInt64(fieldVMAddress), moduleDescription: typeDescription)
    }
    classRangeMap.add(.init(offset: UInt64(offset), value: moduleDetails, of: EnumDescriptor.self))
    classRangeMap.add(.init(offset: UInt64(nameLocation), size: UInt(size), value: moduleDetails))

    var trailingObjectPointer = offset + UInt(MemoryLayout<EnumDescriptor>.size)
    let flags = structDescriptor.flags
    let typeFlags = TypeContextDescriptorFlags(rawFlags: flags.kindSpecificFlags)
    if flags.isGeneric {
      let genericContext = bytes.advanced(by: Int(trailingObjectPointer)).load(
        as: TargetTypeGenericContextDescriptorHeader.self
      )
      let parameterSize = Int(ceil(Double(genericContext.base.numberOfParams) / 4.0))
      let totalGenericSize =
        MemoryLayout<TargetTypeGenericContextDescriptorHeader>.size + parameterSize * 4 + Int(
          genericContext.base.numberOfRequirements
        )
        * MemoryLayout<TargetGenericRequirementDescriptor>.size

      classRangeMap.add(
        .init(
          offset: UInt64(trailingObjectPointer),
          size: UInt(totalGenericSize),
          value: moduleDetails
        )
      )
      trailingObjectPointer += UInt(totalGenericSize)
    }

    guard !typeFlags.hasForeignMetadataInitialization else {
      return typeDescription
    }

    if typeFlags.hasSingletonMetadataInitialization {
      let singletonMetadata = bytes.advanced(by: Int(trailingObjectPointer)).load(
        as: TargetSingletonMetadataInitialization.self
      )
      if singletonMetadata.completionFunction != 0 {
        let functionFileAddress = computeOffset(
          fileStart: trailingObjectPointer,
          object: singletonMetadata,
          path: \.completionFunction,
          canBeIndirect: false
        )!
        let functionVM = vmAddress(for: UInt64(functionFileAddress))!
        toProcessAddress[Int(functionVM)] = .binary(typeDescription.implementation)
      }
      classRangeMap.add(
        .init(
          offset: UInt64(trailingObjectPointer),
          value: moduleDetails,
          of: TargetSingletonMetadataInitialization.self
        )
      )
      trailingObjectPointer += UInt(MemoryLayout<TargetSingletonMetadataInitialization>.size)
    }

    if typeFlags.hasCanonicalMetadataPrespecializations {
      logger.info("canonical metadata enum")
    }

    return typeDescription
  }

  // offset is the address in the file of this type, pointerStart is the address in the file of the Int32 offset that pointed to this type
  private func loadType(from offset: UInt, pointerStart: UInt64?) -> SwiftTypeDetails? {
    if let typeDescription = parsedSwiftOffsets[offset] {
      if let pointerStart = pointerStart {
        classRangeMap.add(
          .init(offset: pointerStart, value: .binary(typeDescription), of: Int32.self)
        )
      }
      return typeDescription
    }

    let test = bytes.advanced(by: Int(offset)).load(as: TargetModuleContextDescriptor.self)
    let flags = ContextDescriptorFlags(rawFlags: test.flags)

    guard let kind = flags.kind else {
      assertionFailure("Invalid kind")
      return nil
    }

    let loadParent: () -> SwiftTypeDetails? = {
      if test.parent != 0 {
        if let parentLocation = self.computeOffset(fileStart: offset, object: test, path: \.parent)
        {
          return self.loadType(from: parentLocation, pointerStart: nil)
        } else {
          #if DEBUG
            logger.debug("Indirect")
          #endif
          return nil
        }
      }
      return nil
    }

    switch kind {
    case .Module:
      guard
        let nameLocation = computeOffset(
          fileStart: offset,
          object: test,
          path: \.name,
          canBeIndirect: false
        )
      else { return nil }
      let (name, size) = self.readNullTerminatedString(
        pointer: bytes.advanced(by: Int(nameLocation))
      )
      let typeDescription = SwiftTypeDetails(moduleName: name, in: appId)
      parsedSwiftOffsets[offset] = typeDescription
      classRangeMap.add(
        .init(
          offset: UInt64(offset),
          value: .binary(typeDescription),
          of: TargetModuleContextDescriptor.self
        )
      )
      if let pointerStart = pointerStart {
        classRangeMap.add(
          .init(offset: pointerStart, value: .binary(typeDescription), of: Int32.self)
        )
      }
      classRangeMap.add(
        .init(offset: UInt64(nameLocation), size: UInt(size), value: .binary(typeDescription))
      )
      return typeDescription
    case .Protocol:
      return parseSwiftProtocol(fileOffset: offset, pointerStart: pointerStart)
    case .Enum:
      return parseSwiftEnum(from: offset, pointerStart: pointerStart)
    case .Struct:
      return parseSwiftStruct(from: offset, pointerStart: pointerStart)
    case .Class:
      return parseSwiftClass(fileOffset: offset, pointerStart: pointerStart)
    case .Extension:
      let extensionDescriptor = bytes.advanced(by: Int(offset)).load(
        as: TargetExtensionContextDescriptor.self
      )
      if let module = loadParent() {
        let moduleDetails = BinaryTag.binary(module)
        parsedSwiftOffsets[offset] = module
        if let pointerStart = pointerStart {
          classRangeMap.add(.init(offset: pointerStart, value: moduleDetails, of: Int32.self))
        }
        classRangeMap.add(
          .init(
            offset: UInt64(offset),
            value: moduleDetails,
            of: TargetExtensionContextDescriptor.self
          )
        )
        var trailingObjectPointer =
          offset + UInt(MemoryLayout<TargetExtensionContextDescriptor>.size)
        if extensionDescriptor.flags.isGeneric {
          let genericContext = bytes.advanced(by: Int(trailingObjectPointer)).load(
            as: TargetGenericContextDescriptorHeader.self
          )
          let parameterSize = Int(ceil(Double(genericContext.numberOfParams) / 4.0))
          let totalGenericSize =
            MemoryLayout<TargetGenericContextDescriptorHeader>.size + parameterSize * 4 + Int(
              genericContext.numberOfRequirements
            )
            * MemoryLayout<TargetGenericRequirementDescriptor>.size

          classRangeMap.add(
            .init(
              offset: UInt64(trailingObjectPointer),
              size: UInt(totalGenericSize),
              value: moduleDetails
            )
          )
          trailingObjectPointer += UInt(totalGenericSize)
        }
        return module
      }
      assertionFailure("Extension with no parent")
      return nil
    case .OpaqueType:
      #if DEBUG
        logger.debug("opaque")
      #endif
      return nil
    case .Anonymous:
      let anonymousDescriptor = bytes.advanced(by: Int(offset)).load(
        as: TargetAnonymousContextDescriptor.self
      )
      if let module = loadParent() {
        let moduleDetails = BinaryTag.binary(module)
        parsedSwiftOffsets[offset] = module
        if let pointerStart = pointerStart {
          classRangeMap.add(.init(offset: pointerStart, value: moduleDetails, of: Int32.self))
        }
        classRangeMap.add(
          .init(
            offset: UInt64(offset),
            value: moduleDetails,
            of: TargetAnonymousContextDescriptor.self
          )
        )
        var trailingObjectPointer =
          offset + UInt(MemoryLayout<TargetAnonymousContextDescriptor>.size)
        if anonymousDescriptor.flags.isGeneric {
          let genericContext = bytes.advanced(by: Int(trailingObjectPointer)).load(
            as: TargetGenericContextDescriptorHeader.self
          )
          let parameterSize = Int(ceil(Double(genericContext.numberOfParams) / 4.0))
          let totalGenericSize =
            MemoryLayout<TargetGenericContextDescriptorHeader>.size + parameterSize * 4 + Int(
              genericContext.numberOfRequirements
            )
            * MemoryLayout<TargetGenericRequirementDescriptor>.size

          classRangeMap.add(
            .init(
              offset: UInt64(trailingObjectPointer),
              size: UInt(totalGenericSize),
              value: moduleDetails
            )
          )
          trailingObjectPointer += UInt(totalGenericSize)
        }
        let flags = AnonymousContextDescriptorFlags(
          rawFalgs: anonymousDescriptor.flags.kindSpecificFlags
        )
        if flags.hasMangledName {
          let namePointerRelative = bytes.advanced(by: Int(trailingObjectPointer)).load(
            as: Int32.self
          )
          classRangeMap.add(
            .init(offset: UInt64(trailingObjectPointer), value: moduleDetails, of: Int32.self)
          )
          let pointer =
            Int(vmAddress(for: UInt64(trailingObjectPointer))!) + Int(namePointerRelative)
          let filePointer = fileOffset(for: UInt64(pointer))!
          let size = readMangledNameLength(pointer: bytes.advanced(by: Int(filePointer)))
          classRangeMap.add(.init(offset: filePointer, size: UInt(size), value: moduleDetails))
          trailingObjectPointer += UInt(MemoryLayout<Int32>.size)
        }
        return module
      }
      assertionFailure("Anonymous with no parent")
      return nil
    }
  }

  private func parseSwiftTypes() {
    guard
      let section = loadCommands.flatMap({ $0.sections }).first(where: {
        $0.name == "__swift5_types"
      })
    else { return }

    let start = section.fileStart
    let size = section.size
    let offsetsList = parseInt32(start: start, size: size)
    for (relativeOffset, offsetStart) in offsetsList {
      var typeFileAddress = Int(offsetStart) + Int(relativeOffset)
      if relativeOffset % 2 == 1 {
        let offset = relativeOffset & ~1
        let dataPtr = rebase(
          bytes.advanced(by: Int(offsetStart) + Int(offset)).load(as: UInt64.self)
        )
        typeFileAddress = Int(fileOffset(for: dataPtr) ?? 0)
      }
      guard typeFileAddress > 0 && typeFileAddress < data.count else {
        logger.warning("Invalid swift type")
        continue
      }

      _ = loadType(from: UInt(typeFileAddress), pointerStart: offsetStart)
    }
  }

  private func parseSwiftProtocolDescriptors() {
    guard
      let section = loadCommands.flatMap({ $0.sections }).first(where: {
        $0.name == "__swift5_protos"
      })
    else { return }

    let start = section.fileStart
    let size = section.size
    let offsetsList = parseInt32(start: start, size: size)
    for (relativeOffset, offsetStart) in offsetsList {
      let typeFileAddress = Int(offsetStart) + Int(relativeOffset)
      guard typeFileAddress > 0 && typeFileAddress < data.count else {
        logger.warning("Invalid swift protocol")
        continue
      }

      _ = loadType(from: UInt(typeFileAddress), pointerStart: offsetStart)
    }
  }

  var protocols = Set<String>()
  var protocolConformed = Set<String>()

  private func isPreviewProtocol(name: String) -> Bool {
    name == "SwiftUI.PreviewProvider" || name == "DeveloperToolsSupport.PreviewRegistry"
  }

  private func loadProtocolConformance(from offset: Int, pointerStart: UInt64) {
    let conformance = bytes.advanced(by: offset).load(as: ProtocolConformanceDescriptor.self)
    let conformanceFlags = ConformanceFlags(rawFlags: conformance.conformanceFlags)
    guard let conformanceKind = conformanceFlags.kind else {
      assertionFailure("Invalid conformance kind")
      return
    }

    var isSwiftUI: Bool = false
    var moduleDetails: BinaryTag?
    var implementationDetails: BinaryTag?
    if let protocolLocation = computeOffset(
      fileStart: UInt(offset),
      object: conformance,
      path: \.protocolDescriptor
    ) {
      let module = loadType(from: protocolLocation, pointerStart: nil)
      moduleDetails = .binary(module!)
      implementationDetails = .binary(module!.implementation)
      protocolConformed.insert(module!.typePath.joined(separator: "."))
    } else if let indirectVMLocation = lookupIndirectRelativePointer(
      fileStart: UInt(offset),
      object: conformance,
      path: \.protocolDescriptor
    ) {
      let boundSymbolIndex = swiftBoundSymbols.binarySearch(predicate: {
        $0.vmAddress < indirectVMLocation
      })
      if boundSymbolIndex < swiftBoundSymbols.count
        && swiftBoundSymbols[boundSymbolIndex].vmAddress == indirectVMLocation
      {
        let boundSymbol = swiftBoundSymbols[boundSymbolIndex]
        if let symbolTableElement = SymbolTableDetails(
          name: boundSymbol.symbol,
          in: appId
        ) {
          let element = SwiftTypeDetails.boundProtocolConformance(details: symbolTableElement)
          if isPreviewProtocol(name: element.typePath.joined(separator: ".")) {
            isSwiftUI = true
          }
          protocolConformed.insert(element.typePath.joined(separator: "."))
          moduleDetails = .binary(element)
          implementationDetails = .binary(element)
        } else {
          logger.warning("protocol not parsed")
        }
      } else if usesChainedFixups {
        let result = fileOffset(for: UInt64(indirectVMLocation))!
        let finalPointer = bytes.advanced(by: Int(result)).load(as: UInt64.self)
        let ordinal = (finalPointer & 0xFFFFFF)
        if finalPointer >> 63 == 1 && ordinal < importedSymbols.count {
          let name = importedSymbols[Int(ordinal)]
          if name.starts(with: "_$s") {
            if let symbolTableElement = SymbolTableDetails(name: name, in: appId) {
              let element = SwiftTypeDetails.boundProtocolConformance(details: symbolTableElement)
              if isPreviewProtocol(name: element.typePath.joined(separator: ".")) {
                isSwiftUI = true
              }
              protocolConformed.insert(element.typePath.joined(separator: "."))
              moduleDetails = .binary(element)
              implementationDetails = .binary(element)
            }
          }
        }
      } else {
        logger.info("protocol not found in bound symbols")
      }
    }
    switch conformanceKind {
    case .DirectTypeDescriptor:
      if let nominalTypeLocation = computeOffset(
        fileStart: UInt(offset),
        object: conformance,
        path: \.nominalTypeDescriptor,
        canBeIndirect: false
      ) {
        if let module = loadType(from: nominalTypeLocation, pointerStart: nil) {
          if let moduleName = module.module?.name, isSwiftUI {
            previewProviders.append((moduleName, module.typePath.joined(separator: ".")))
          }
          moduleDetails = .binary(module)
          implementationDetails = .binary(module.implementation)
        }
      } else {
        logger.info("did not find \(conformance.nominalTypeDescriptor)")
      }
    case .IndirectTypeDescriptor:
      break
    case .DirectObjCClassName:
      guard
        let objcClassNameLocation = computeOffset(
          fileStart: UInt(offset),
          object: conformance,
          path: \.nominalTypeDescriptor,
          canBeIndirect: false
        )
      else { return }
      let (string, size) = readNullTerminatedString(
        pointer: bytes.advanced(by: Int(objcClassNameLocation))
      )
      let objcDetails = SwiftTypeDetails.objcProtocolConformance(
        details: ObjcClassDetails(className: string, in: appId)
      )
      if let moduleName = objcDetails.module?.name, moduleName != "NS" && moduleName != "UI" {
        moduleDetails = .binary(objcDetails)
        implementationDetails = .binary(objcDetails)
      } else {
        moduleDetails = moduleDetails ?? .binary(objcDetails)
        implementationDetails = implementationDetails ?? .binary(objcDetails)
      }
      classRangeMap.add(
        .init(offset: UInt64(objcClassNameLocation), size: UInt(size), value: moduleDetails!)
      )
      break
    case .IndirectObjCClass:
      break
    }

    var trailingObjectsOffset =
      UInt(offset) + UInt(MemoryLayout<ProtocolConformanceDescriptor>.stride)

    // TODO: Attribute size of the witness table
    //let witnessTableOffset = computeOffset(fileStart: UInt(offset), object: conformance, path: \.protocolWitnessTable, canBeIndirect: false)!
    //logger.debug("Protocol witness table offset \(vmAddress(for: UInt64(witnessTableOffset))!) for \(module?.description.module)")
    if let module = moduleDetails, let implementationDetails = implementationDetails {
      classRangeMap.add(.init(offset: pointerStart, value: module, of: UInt32.self))
      classRangeMap.add(
        .init(offset: UInt64(offset), value: module, of: ProtocolConformanceDescriptor.self)
      )
      if conformanceFlags.isRetroactive {
        let contextPointerRelative = bytes.advanced(by: Int(trailingObjectsOffset)).load(
          as: Int32.self
        )
        let typePointer =
          Int(vmAddress(for: UInt64(trailingObjectsOffset))!) + Int(contextPointerRelative)
        let typeFilePointer = fileOffset(for: UInt64(typePointer))!
        let _ = loadType(from: UInt(typeFilePointer), pointerStart: nil)
        classRangeMap.add(
          .init(offset: UInt64(trailingObjectsOffset), value: module, of: Int32.self)
        )
        trailingObjectsOffset += UInt(MemoryLayout<Int32>.size)
      }
      for _ in 0..<conformanceFlags.numConditionalRequirements {
        parseGenericRequirementDescriptor(
          requirementsStart: trailingObjectsOffset,
          moduleDetails: module
        )
        trailingObjectsOffset += UInt(MemoryLayout<TargetGenericRequirementDescriptor>.stride)
      }
      if conformanceFlags.hasResilientWitnesses {
        let numWitnesses = bytes.advanced(by: Int(trailingObjectsOffset)).load(as: UInt32.self)
        classRangeMap.add(
          .init(offset: UInt64(trailingObjectsOffset), value: module, of: UInt32.self)
        )
        trailingObjectsOffset += UInt(MemoryLayout<UInt32>.size)
        let sizeOfResilientWitnesses =
          UInt(numWitnesses) * UInt(MemoryLayout<TargetResilientWitness>.size)
        classRangeMap.add(
          .init(
            offset: UInt64(trailingObjectsOffset),
            size: sizeOfResilientWitnesses,
            value: module
          )
        )
        trailingObjectsOffset += sizeOfResilientWitnesses
      }
      if conformanceFlags.hasGenericWitnessTable {
        let genericWitnessTable = bytes.advanced(by: Int(trailingObjectsOffset)).load(
          as: TargetGenericWitnessTable.self
        )
        classRangeMap.add(
          .init(
            offset: UInt64(trailingObjectsOffset),
            value: module,
            of: TargetGenericWitnessTable.self
          )
        )
        if genericWitnessTable.instantiator != 0 {
          let instantiatorOffset = computeOffset(
            fileStart: trailingObjectsOffset,
            object: genericWitnessTable,
            path: \.instantiator,
            canBeIndirect: false
          )!
          toProcessAddress[Int(instantiatorOffset)] = implementationDetails
        }
      }
    }
  }

  private func parseSwiftProtocolConformance() {
    guard
      let section = loadCommands.flatMap({ $0.sections }).first(where: {
        $0.name == "__swift5_proto"
      })
    else { return }

    let start = section.fileStart
    let size = section.size
    let offsetsList = parseInt32(start: start, size: size)
    for (relativeOffset, offsetStart) in offsetsList {
      let typeFileAddress = Int(offsetStart) + Int(relativeOffset)
      guard typeFileAddress > 0 && typeFileAddress < data.count else {
        logger.warning("Invalid protocol conformance offset")
        continue
      }
      loadProtocolConformance(from: typeFileAddress, pointerStart: offsetStart)
    }
  }

  private func parseMethodList() {
    guard
      let section = loadCommands.flatMap({ $0.sections }).first(where: {
        $0.name == "__objc_selrefs"
      })
    else { return }
    let start = section.fileStart
    let size = section.size
    classRangeMap.add(.init(offset: start, size: UInt(size), value: .externalMethods))
    let selNamePointers = parseUInt64(start: start, size: size)
    for (vmAddress, _) in selNamePointers {
      guard let nameFileOffset = fileOffset(for: rebase(vmAddress)) else {
        return
      }

      if objcMethNameToModule[nameFileOffset] == nil {
        let (_, size) = readNullTerminatedString(pointer: bytes.advanced(by: Int(nameFileOffset)))
        classRangeMap.add(.init(offset: nameFileOffset, size: UInt(size), value: .externalMethods))
      }
    }
  }

  private func rebase(_ pointer: UInt64) -> UInt64 {
    if usesChainedFixups, pointer != 0 && pointer >> 63 == 0 {
      let unpackedTarget = pointer.unpackedTarget
      // Old format is DYLD_CHAINED_PTR_64
      if unpackedTarget > 4_000_000_000 {
        return unpackedTarget
      }
      // New format is DYLD_CHAINED_PTR_64_OFFSET
      if let result = self.vmAddress(for: unpackedTarget) {
        return result
      } else {
        return pointer
      }
    }
    if usesChainedFixups, pointer >> 63 == 1 {
      return 0
    }
    return pointer
  }

  private func parseObjcProperties(from listStart: UInt64, name: AnyBinaryDetails) {
    loadObjcArray(vmAddress: listStart, name: name) { (_, property: BaseProperty) in
      totalProperties += 1
      if let propertyNameOffset = fileOffset(for: rebase(property.name)) {
        let (propertyName, size) = readNullTerminatedString(
          pointer: bytes.advanced(by: Int(propertyNameOffset))
        )
        objcTypeStrings[propertyNameOffset] = propertyName
        self.classRangeMap.add(
          .init(offset: propertyNameOffset, size: UInt(size), value: BinaryTag.binary(name))
        )
      }
      if let attributesOffset = fileOffset(for: rebase(property.attributes)) {
        let (attributes, size) = readNullTerminatedString(
          pointer: bytes.advanced(by: Int(attributesOffset))
        )
        objcTypeStrings[attributesOffset] = attributes
        self.classRangeMap.add(
          .init(offset: attributesOffset, size: UInt(size), value: BinaryTag.binary(name))
        )
      }
    }
  }

  func parseCategoryList() {
    if let section = loadCommands.flatMap({ $0.sections }).first(where: {
      $0.name == "__objc_catlist"
    }) {
      parseCategoryList(section: section)
    }
    if let section = loadCommands.flatMap({ $0.sections }).first(where: {
      $0.name == "__objc_nlcatlist"
    }) {
      parseCategoryList(section: section)
    }
  }

  func parseCategoryList(section: BinarySection) {
    let start = section.fileStart
    let size = section.size
    let categoryPointers = parseUInt64(start: start, size: size)
    for (vmAddress, fileOffset) in categoryPointers {
      parseObjcCategory(vmAddress: rebase(vmAddress), pointerFileOffset: fileOffset)
    }
  }

  func parseObjcCategory(vmAddress: UInt64, pointerFileOffset: UInt64) {
    guard parsedObjcOffsets[vmAddress] == nil else {
      return
    }
    guard let categoryFileOffset = fileOffset(for: vmAddress) else { return }

    let objcCategory = bytes.advanced(by: Int(categoryFileOffset)).load(as: ObjcCategory.self)
    guard let nameFileOffset = fileOffset(for: rebase(objcCategory.name)) else { return }
    let (name, size) = readNullTerminatedString(pointer: bytes.advanced(by: Int(nameFileOffset)))

    let className: String?
    // Skip this for bound pointers
    if rebase(objcCategory.cls) != 0 {
      guard let classFileOffset = fileOffset(for: rebase(objcCategory.cls)) else {
        assertionFailure("Obj-C category not found")
        return
      }
      let objcClass = bytes.advanced(by: Int(classFileOffset)).load(as: ObjCClass.self)
      guard let dataFilePtr = fileOffset(for: rebase(objcClass.dataPtr)) else {
        assertionFailure("Obj-C class data not found")
        return
      }

      let classRoT = bytes.advanced(by: Int(dataFilePtr)).load(as: ClassRoT.self)
      guard let nameFileOffset = fileOffset(for: rebase(classRoT.name)) else {
        assertionFailure("Obj-C class name not found")
        return
      }

      let (name, _) = readNullTerminatedString(pointer: bytes.advanced(by: Int(nameFileOffset)))
      className = name
    } else {
      className = nil
    }
    let categoryDetails = ObjCCategoryDetails(
      categoryName: name,
      conformingName: className,
      in: appId
    )
    let moduleDetails = BinaryTag.binary(categoryDetails)
    parsedObjcOffsets[vmAddress] = .init(details: categoryDetails)

    classRangeMap.add(
      .init(offset: pointerFileOffset, value: moduleDetails, of: type(of: vmAddress))
    )
    classRangeMap.add(
      .init(offset: categoryFileOffset, value: moduleDetails, of: ObjcCategory.self)
    )
    classRangeMap.add(.init(offset: nameFileOffset, size: UInt(size), value: moduleDetails))

    _ = parseObjcMethodList(vmAddress: rebase(objcCategory.instanceMethods), name: categoryDetails)
    _ = parseObjcMethodList(vmAddress: rebase(objcCategory.classMethods), name: categoryDetails)
    loadObjcArray(
      vmAddress: rebase(objcCategory.protocols),
      name: .init(details: categoryDetails),
      skipFirst: true
    ) { (_, objcProtocolPointer: UInt64) in
      parseProtocol(vmAddress: rebase(objcProtocolPointer))
    }
    parseObjcProperties(
      from: rebase(objcCategory.instanceProperties),
      name: .init(details: categoryDetails)
    )
  }

  func parseUInt64(start: UInt64, size: UInt64) -> [(UInt64, UInt64)] {
    parseList(type: UInt64.self, start: start, size: size)
  }

  func parseInt32(start: UInt64, size: UInt64) -> [(Int32, UInt64)] {
    parseList(type: Int32.self, start: start, size: size)
  }

  func parseList<T>(type: T.Type, start: UInt64, size: UInt64) -> [(T, UInt64)] {
    var dataPointer = bytes.advanced(by: Int(start))
    var fileOffset = start
    let pointerSize = MemoryLayout<T>.size
    var classPointers = [(T, UInt64)]()
    for _ in 0..<Int(size) / pointerSize {
      let pointer = dataPointer.load(as: T.self)
      classPointers.append((pointer, fileOffset))
      dataPointer = dataPointer.advanced(by: pointerSize)
      fileOffset += UInt64(pointerSize)
    }
    return classPointers
  }

  func parseClassList() {
    if let classList = loadCommands.flatMap({ $0.sections }).first(where: {
      $0.name == "__objc_classlist"
    }) {
      parseClassList(section: classList)
    }
    if let classList = loadCommands.flatMap({ $0.sections }).first(where: {
      $0.name == "__objc_nlclslist"
    }) {
      parseClassList(section: classList)
    }
  }

  func parseClassList(section: BinarySection) {
    let start = section.fileStart
    let size = section.size
    let classPointers = parseUInt64(start: start, size: size)
    for (vmAddress, fileOffset) in classPointers {
      parseObjcClass(vmAddress: rebase(vmAddress), pointerFileOffset: fileOffset)
    }
  }

  var objcMethodNames = Set<String>()

  var classNames = [String: [String]]()

  // Returns the number of methods
  private func parseObjcMethodList(vmAddress: UInt64, name: ObjcMethodSupporting) -> UInt {
    var count: UInt = 0
    guard let methodFlagsFileOffset = fileOffset(for: vmAddress) else { return 0 }

    let methodFlags = bytes.advanced(by: Int(methodFlagsFileOffset)).load(as: UInt32.self)
    let smallMethodListFlag: UInt32 = 0x8000_0000
    let smallList = (methodFlags & smallMethodListFlag) != 0

    let handleMethod: (UInt64, UInt64, UInt64) -> Void = {
      nameAddress,
      typeNameAddress,
      implAddress in
      var nameWithMethod: BinaryTag = .binary(name)
      if let methodNameOffset = self.fileOffset(for: nameAddress) {
        if self.objcMethNameToModule[methodNameOffset] == nil {
          self.objcMethNameToModule[methodNameOffset] = name.module
        }
        let (methodName, size) = self.readNullTerminatedString(
          pointer: self.bytes.advanced(by: Int(methodNameOffset))
        )
        self.objcMethodNames.insert(methodName)
        nameWithMethod = .binary(name.method(named: methodName))
        self.classRangeMap.add(
          .init(offset: methodNameOffset, size: UInt(size), value: .binary(name))
        )
      }

      if let typeNameOffset = self.fileOffset(for: typeNameAddress) {
        let (typeName, size) = self.readNullTerminatedString(
          pointer: self.bytes.advanced(by: Int(typeNameOffset))
        )
        self.objcTypeStrings[typeNameOffset] = typeName
        self.classRangeMap.add(
          .init(offset: typeNameOffset, size: UInt(size), value: .binary(name))
        )
      }

      if implAddress != 0 {
        self.toProcessAddress[Int(implAddress)] = nameWithMethod
      }

    }
    if smallList {
      loadObjcArray(vmAddress: vmAddress, name: .init(details: name)) {
        (pointer, method: ObjcRelativeMethod) in
        count += 1
        var methodNameVM: UInt64 = 0
        if method.name != 0 {
          let methodNameAddress = Int(pointer) + Int(method.name)
          if let methodFileOffset = fileOffset(for: UInt64(methodNameAddress)) {
            let realAddress = bytes.advanced(by: Int(methodFileOffset)).load(as: UInt64.self)
            methodNameVM = realAddress
          }
        }
        var methodTypeVM: UInt64 = 0
        if method.types != 0 {
          let methodTypeAddress = Int(pointer) + MemoryLayout<Int32>.size + Int(method.types)
          methodTypeVM = UInt64(methodTypeAddress)
        }
        var methodImplVM: UInt64 = 0
        if method.impl != 0 {
          let methodImplAddress = Int(pointer) + (MemoryLayout<Int32>.size * 2) + Int(method.impl)
          methodImplVM = UInt64(methodImplAddress)
        }
        handleMethod(methodNameVM, methodTypeVM, methodImplVM)
      }
    } else {
      loadObjcArray(vmAddress: vmAddress, name: .init(details: name)) { (_, method: ObjcMethod) in
        count += 1
        handleMethod(rebase(method.name), rebase(method.types), rebase(method.impl))
      }
    }
    return count
  }

  var alreadyProcessedAddress = Set<UInt64>()
  var toProcessAddress = [Int: BinaryTag]()
  var methodSizes = [Int]()

  private func getBlockSize(vmStart: UInt64, maxEnd: UInt64?) -> DisasembleResult? {
    if let maxEnd = maxEnd {
      precondition(maxEnd >= vmStart)
      // This means the parseMethod function reached the end of where it can parse
      if maxEnd == vmStart {
        return nil
      }
    }
    guard !alreadyProcessedAddress.contains(vmStart) else { return nil }

    alreadyProcessedAddress.insert(vmStart)
    guard let section = sectionName(for: vmStart), section.starts(with: "__TEXT"),
      ![
        "__TEXT/__swift5_reflstr", "__TEXT/__swift5_typeref", "__TEXT/__swift5_fieldmd",
        "__TEXT/__const", "__TEXT/__constg_swiftt", "__TEXT/__cstring", "__TEXT/__objc_methname",
        "__TEXT/__unwind_info", "__TEXT/__eh_frame",
      ].contains(section)
    else { return nil }
    guard let sectionEnd = sectionEnd(for: vmStart) else { return nil }

    let maxLeftInSection = sectionEnd - vmStart
    let maxMethodSize: UInt64
    if let maxEnd = maxEnd {
      let maxSizeToNextFunction = maxEnd - vmStart
      maxMethodSize = min(maxLeftInSection, maxSizeToNextFunction)
    } else {
      maxMethodSize = maxLeftInSection
    }
    if maxMethodSize == 0 {
      return nil
    }

    guard let methodFileOfset = fileOffset(for: vmStart) else {
      return nil
    }

    let offset = Int(methodFileOfset)
    var totalReadSize = 0
    let readIncrement = 4 * 100
    let maxReadSize = min(400000 * 4, maxMethodSize)
    var nonSubroutineBranches = [Int]()
    var subroutineBranches = [Int]()
    var relativeAddresses = [Int]()
    repeat {
      let readStart = offset + totalReadSize
      let sizeToRead = min((Int(maxReadSize) - totalReadSize), readIncrement)
      guard sizeToRead > 0 else {
        break
      }

      let dataNoCopy = Data(
        bytesNoCopy: data.mutableBytes.advanced(by: readStart),
        count: sizeToRead,
        deallocator: .none
      )
      let disassembleResult =
        if skipInstructionDisassembly {
          DisasembleResult(
            size: nil,
            nonSubroutineBranch: [],
            subroutineBranch: [],
            relativeAddresses: []
          )
        } else {
          disasembleInstructions(
            capstone: self.capstone,
            data: dataNoCopy,
            startAddress: vmStart + UInt64(totalReadSize)
          )
        }
      let returnSize = disassembleResult.size
      nonSubroutineBranches.append(contentsOf: disassembleResult.nonSubroutineBranch)
      subroutineBranches.append(contentsOf: disassembleResult.subroutineBranch)
      relativeAddresses.append(contentsOf: disassembleResult.relativeAddresses)
      if let returnOffset = returnSize {
        totalReadSize += returnOffset
        break
      }
      totalReadSize += sizeToRead
    } while totalReadSize < maxReadSize

    return .init(
      size: totalReadSize,
      nonSubroutineBranch: nonSubroutineBranches,
      subroutineBranch: subroutineBranches,
      relativeAddresses: relativeAddresses
    )
  }

  @discardableResult
  private func parseMethod(vmStart: UInt64, named: BinaryTag, maxEnd: UInt64?) -> UInt {

    var vmPosition = vmStart
    var nonSubroutineBranches = [Int]()
    var subroutineBranches = [Int]()
    var relativeAddresses = [Int]()
    repeat {
      guard let blockResult = getBlockSize(vmStart: vmPosition, maxEnd: maxEnd) else {
        break
      }
      vmPosition += UInt64(blockResult.size ?? 0)
      nonSubroutineBranches.append(contentsOf: blockResult.nonSubroutineBranch)
      subroutineBranches.append(contentsOf: blockResult.subroutineBranch)
      relativeAddresses.append(contentsOf: blockResult.relativeAddresses)
      // If there is not a branch to continue the function we should stop parsing
      if nonSubroutineBranches.firstIndex(where: { $0 == vmPosition }) == nil {
        break
      }
    } while true

    let totalReadSize = vmPosition - vmStart
    guard totalReadSize > 0 else { return 0 }

    if totalReadSize >= 1_600_000 {
      logger.warning("The total size is max")
    }
    let processedVMRange = vmStart..<vmPosition
    for address in subroutineBranches where !processedVMRange.contains(UInt64(address)) {
      toProcessAddress[address] = named
    }
    let newBranchesVM = nonSubroutineBranches.filter { !processedVMRange.contains(UInt64($0)) }
      .sorted()
    for branch in newBranchesVM {
      toProcessAddress[branch] = named
    }
    let newRelativeAddresses = relativeAddresses.filter { !processedVMRange.contains(UInt64($0)) }
      .sorted()
    for branch in newRelativeAddresses {
      if toProcessAddress[branch] == nil {
        toProcessAddress[branch] = named
      }
    }
    methodSizes.append(Int(totalReadSize))
    classRangeMap.add(
      .init(offset: fileOffset(for: vmStart)!, size: UInt(totalReadSize), value: named),
      allowPartial: false
    )
    return UInt(totalReadSize)
  }

  var parsedObjcOffsets = [UInt64: AnyBinaryDetails]()
  var totalMethods: UInt = 0
  var totalProtocols = 0
  var totalIVars = 0
  var totalProperties = 0

  func parseObjcClass(vmAddress: UInt64, pointerFileOffset: UInt64? = nil) {
    if let moduleProviding = parsedObjcOffsets[vmAddress] {
      if let pointerFileOffset = pointerFileOffset {
        classRangeMap.add(
          .init(
            offset: pointerFileOffset,
            value: BinaryTag.binary(moduleProviding),
            of: type(of: vmAddress)
          )
        )
      }
      return
    }

    guard let classFileOffset = fileOffset(for: vmAddress) else { return }

    let objcClass = bytes.advanced(by: Int(classFileOffset)).load(as: ObjCClass.self)
    guard let dataFilePtr = fileOffset(for: rebase(objcClass.dataPtr)) else {
      assertionFailure("Obj-C class data not found")
      return
    }

    let classRoT = bytes.advanced(by: Int(dataFilePtr)).load(as: ClassRoT.self)
    guard let nameFileOffset = fileOffset(for: rebase(classRoT.name)) else {
      assertionFailure("Obj-C class name not found")
      return
    }

    let (classStringName, classNameSize) = readNullTerminatedString(
      pointer: bytes.advanced(by: Int(nameFileOffset))
    )
    let moduleDetails = ObjcClassDetails(className: classStringName, in: appId)
    classNames[classStringName] = AnyBinaryDetails(details: moduleDetails).path
    if let pointerFileOffset = pointerFileOffset {
      classRangeMap.add(
        .init(offset: pointerFileOffset, value: .binary(moduleDetails), of: type(of: vmAddress))
      )
    }

    parsedObjcOffsets[vmAddress] = .init(details: moduleDetails)

    if rebase(objcClass.isa) != 0 {
      parseObjcClass(vmAddress: rebase(objcClass.isa))
    }
    if rebase(objcClass.superclass) != 0 {
      parseObjcClass(vmAddress: rebase(objcClass.superclass))
    }

    classRangeMap.add(
      .init(
        offset: classFileOffset,
        value: .binary(moduleDetails),
        of: ObjCClass.self
      )
    )
    classRangeMap.add(.init(offset: dataFilePtr, value: .binary(moduleDetails), of: ClassRoT.self))
    classRangeMap.add(
      .init(offset: nameFileOffset, size: UInt(classNameSize), value: .binary(moduleDetails))
    )

    // Parse method list
    totalMethods += parseObjcMethodList(
      vmAddress: rebase(classRoT.baseMethodList),
      name: moduleDetails
    )

    // Parse protocols
    loadObjcArray(
      vmAddress: rebase(classRoT.baseProtocols),
      name: .init(details: moduleDetails),
      skipFirst: true
    ) { (_, objcProtocolPointer: UInt64) in
      totalProtocols += 1
      parseProtocol(vmAddress: rebase(objcProtocolPointer))
    }

    loadObjcArray(vmAddress: rebase(classRoT.ivars), name: .init(details: moduleDetails)) {
      (_, ivar: ObjcIVar) in
      totalIVars += 1
      var ivarName = ""
      if let ivarNameOffset = fileOffset(for: rebase(ivar.name)) {
        let (name, size) = readNullTerminatedString(
          pointer: bytes.advanced(by: Int(ivarNameOffset))
        )
        objcTypeStrings[ivarNameOffset] = name
        ivarName = name
        self.classRangeMap.add(
          .init(offset: ivarNameOffset, size: UInt(size), value: .binary(moduleDetails))
        )
      }
      if let ivarTypeOffset = fileOffset(for: rebase(ivar.type)) {
        let (name, size) = readNullTerminatedString(
          pointer: bytes.advanced(by: Int(ivarTypeOffset))
        )
        objcTypeStrings[ivarTypeOffset] = name
        self.classRangeMap.add(
          .init(offset: ivarTypeOffset, size: UInt(size), value: .binary(moduleDetails))
        )
      }
      if let fileIvarOffset = fileOffset(for: rebase(ivar.offset)) {
        var alignment = ivar.alignment
        // Convert the alignment to bytes.
        if alignment == ~0 {
          alignment = 8
        } else {
          alignment = (1 << alignment)
        }
        self.classRangeMap.add(
          .init(
            offset: fileIvarOffset,
            size: 4,
            value: .binary(moduleDetails),
            context: "\(ivarName) \(ivar.alignment)"
          )
        )
      }
    }
    parseObjcProperties(from: rebase(classRoT.baseProperties), name: .init(details: moduleDetails))
  }

  @discardableResult
  private func parseProtocol(vmAddress: UInt64) -> AnyBinaryDetails? {
    if let moduleDescription = parsedObjcOffsets[vmAddress] {
      return moduleDescription
    }

    guard let protocolFileOffset = fileOffset(for: vmAddress) else {
      assertionFailure("Protocol file offset not found")
      return nil
    }

    let objcProtocol = bytes.advanced(by: Int(protocolFileOffset)).load(as: ObjcProtocol.self)
    guard let protocolNameOffset = fileOffset(for: rebase(objcProtocol.mangledName)) else {
      assertionFailure("Protocol name not found")
      return nil
    }

    let (protocolStringName, protocolNameSize) = readNullTerminatedString(
      pointer: bytes.advanced(by: Int(protocolNameOffset))
    )
    let moduleDetails = ObjcClassDetails(className: protocolStringName, in: appId)
    parsedObjcOffsets[vmAddress] = .init(details: moduleDetails)

    classRangeMap.add(
      .init(
        offset: protocolFileOffset,
        size: UInt(objcProtocol.size),
        value: .binary(moduleDetails)
      )
    )
    classRangeMap.add(
      .init(offset: protocolNameOffset, size: UInt(protocolNameSize), value: .binary(moduleDetails))
    )

    let loadProtocolProperties = { (vmAddress: UInt64) in
      guard vmAddress != 0 else { return }

      self.parseObjcProperties(from: vmAddress, name: .init(details: moduleDetails))
    }

    var methodCount: UInt = 0
    // Protocol instance methods
    methodCount += parseObjcMethodList(
      vmAddress: rebase(objcProtocol.instanceMethods),
      name: moduleDetails
    )

    // Protocol class methods
    methodCount += parseObjcMethodList(
      vmAddress: rebase(objcProtocol.classMethods),
      name: moduleDetails
    )

    // Protocol optional class methods
    methodCount += parseObjcMethodList(
      vmAddress: rebase(objcProtocol.optionalClassMethods),
      name: moduleDetails
    )

    // Protocol optional instance methods
    methodCount += parseObjcMethodList(
      vmAddress: rebase(objcProtocol.optionalInstanceMethods),
      name: moduleDetails
    )

    // Parse protocols this protocol inherits from
    if rebase(objcProtocol.protocols) != 0 {
      loadObjcArray(
        vmAddress: rebase(objcProtocol.protocols),
        name: .init(details: moduleDetails),
        skipFirst: true
      ) { (_, objcProtocolPointer: UInt64) in
        parseProtocol(vmAddress: rebase(objcProtocolPointer))
      }
    }

    loadProtocolProperties(rebase(objcProtocol.instanceProperties))

    if let offset = MemoryLayout<ObjcProtocol>.offset(of: \ObjcProtocol.extendedMethodTypes),
      objcProtocol.size > offset
    {
      guard let fileListOffset = fileOffset(for: rebase(objcProtocol.extendedMethodTypes)) else {
        return .init(details: moduleDetails)
      }

      var objcArrayPointer = bytes.advanced(by: Int(fileListOffset))
      classRangeMap.add(
        .init(
          offset: fileListOffset,
          size: methodCount * UInt(MemoryLayout<UInt64>.size),
          value: .binary(moduleDetails)
        )
      )
      for _ in 0..<methodCount {
        let loaded = rebase(objcArrayPointer.load(as: UInt64.self))
        objcArrayPointer = objcArrayPointer.advanced(by: MemoryLayout<UInt64>.size)
        guard let typeOffset = self.fileOffset(for: loaded) else {
          assertionFailure("Protocol types name not found")
          return nil
        }
        let (_, size) = self.readNullTerminatedString(pointer: bytes.advanced(by: Int(typeOffset)))
        classRangeMap.add(
          .init(offset: typeOffset, size: UInt(size), value: .binary(moduleDetails))
        )
      }
    }

    if let offset = MemoryLayout<ObjcProtocol>.offset(of: \ObjcProtocol.classProperties),
      objcProtocol.size > offset
    {
      loadProtocolProperties(rebase(objcProtocol.classProperties))
    }
    return .init(details: moduleDetails)
  }

  private func loadObjcArray<T>(
    vmAddress: UInt64,
    name: AnyBinaryDetails,
    skipFirst: Bool = false,
    parse: (UInt64, T) -> Void
  ) {
    guard let fileListOffset = fileOffset(for: vmAddress) else { return }

    let objectSize = MemoryLayout<T>.size
    var objcArrayPointer = bytes.advanced(by: Int(fileListOffset))
    let count: Int
    let int64Size = MemoryLayout<UInt64>.size
    if !skipFirst {
      let int32Size = MemoryLayout<UInt32>.size
      // First UInt32 is not used
      objcArrayPointer = objcArrayPointer.advanced(by: int32Size)
      count = Int(objcArrayPointer.load(as: UInt32.self))
      objcArrayPointer = objcArrayPointer.advanced(by: int32Size)
    } else {
      count = Int(objcArrayPointer.load(as: UInt64.self))
      objcArrayPointer = objcArrayPointer.advanced(by: int64Size)
    }
    classRangeMap.add(
      .init(
        offset: fileListOffset,
        size: UInt(int64Size) + (UInt(objectSize) * UInt(count)),
        value: BinaryTag.binary(name)
      )
    )
    var objectStart = vmAddress + UInt64(int64Size)
    for _ in 0..<count {
      let loaded = objcArrayPointer.load(as: T.self)
      parse(objectStart, loaded)
      objcArrayPointer = objcArrayPointer.advanced(by: objectSize)
      objectStart += UInt64(objectSize)
    }
  }

  func findStrings() {
    guard !encrypted else { return }

    guard let cStringFileStart = cStringFileStart, let cstringSection = cstringSection,
      let cStringVMStart = cStringVMStart
    else { return }
    analyzeCString(
      fileOffset: cStringFileStart,
      size: cstringSection.size,
      startAddress: cStringVMStart
    )
  }

  func readMangledNameLength(pointer: UnsafeRawPointer) -> Int {
    var typedPointer = pointer.assumingMemoryBound(to: UInt8.self)
    var lastByte: UInt8 = 0
    var length: Int = 0

    //    guard typedPointer.pointee == 1 else { return ("", 0) }
    //    var relativeOffset: Int32 = 0
    //    withUnsafeMutableBytes(of: &relativeOffset) { ptr in
    //      let buffer = UnsafeRawBufferPointer(start: pointer.advanced(by: 1), count: MemoryLayout<Int32>.size)
    //      ptr.copyMemory(from: UnsafeRawBufferPointer(.init(buffer)))
    //    }
    //    let startingFileOffset = data.bytes.distance(to: pointer.advanced(by: 1))
    //    let startingVMAddress = vmAddress(for: UInt64(startingFileOffset))!
    //    let pointingVMAddress = UInt64(Int(startingVMAddress) + Int(relativeOffset))
    //    let name = sectionName(for: pointingVMAddress)
    //    logger.debug("starting in \(sectionName(for: startingVMAddress))")
    //    logger.debug("the relative offset \(relativeOffset) in \(name) \(pointingVMAddress)")
    //    parseSwiftClass(fileOffset: UInt(fileOffset(for: pointingVMAddress)!), pointerStart: nil)

    repeat {
      let byte = typedPointer.pointee
      typedPointer = typedPointer.advanced(by: 1)
      length += 1
      if byte == 0xFF {
        continue
      }
      if byte >= 0x01 && byte <= 0x17 {
        typedPointer = typedPointer.advanced(by: 4)
        length += 4
      } else if byte >= 0x18 && byte <= 0x1F {
        typedPointer = typedPointer.advanced(by: 8)
        length += 4
      }
      lastByte = byte
    } while lastByte != 0
    return length
  }

  func readNullTerminatedString(pointer: UnsafeRawPointer) -> (String, Int) {
    let string = String(cString: pointer.assumingMemoryBound(to: UInt8.self))
    // Some Obj-C type encodings are just a null character, skip these
    if string.count == 0 {
      return ("", 0)
    }

    let startFileOffset = bytes.distance(to: pointer)
    if let cstringSection = cstringSection,
      startFileOffset < cstringSection.offset
        || startFileOffset > UInt64(cstringSection.offset) + cstringSection.size
    {
      return (string, string.count + 1)
    }

    var endPointer = pointer.advanced(by: string.count)
    var nullCount = 0
    var loaded: UInt8
    repeat {
      loaded = endPointer.load(as: UInt8.self)
      nullCount += 1
      endPointer = endPointer.advanced(by: 1)
    } while loaded == 0
    // Add one for the null character
    return (string, string.lengthOfBytes(using: .utf8) + nullCount - 1)
  }

  // VM addresses not file addresses
  func getConstantStringAddresses() -> Set<UInt64> {
    var addresses = Set<UInt64>()
    if let cfstringSection = cfstringSection {
      classRangeMap.add(
        .init(
          offset: UInt64(cfstringSection.offset),
          size: UInt(cfstringSection.size),
          value: .strings(.init(string: nil, type: .cfStrings))
        )
      )
      var pointer = bytes.advanced(by: Int(cfstringSection.offset))
      for _ in 0..<(cfstringSection.size / (16 + 8 + 8)) {
        // First 8 bytes are unused
        pointer = pointer.advanced(by: 16)
        let vmAddress = rebase(pointer.load(as: UInt64.self))
        addresses.insert(vmAddress)
        pointer = pointer.advanced(by: 8)
        // This is the size of the string
        let _ = pointer.load(as: UInt64.self)
        pointer = pointer.advanced(by: 8)
        // TODO: ustring section
      }
    }
    return addresses
  }

  func analyzeCString(fileOffset: UInt64, size: UInt64, startAddress: UInt64) {
    var current = bytes.advanced(by: Int(fileOffset))
    var currentVMStart = startAddress
    var isAddingZero = false
    var strings = [UInt64: CString]()
    var array = [UInt8]()
    var largestObjcTypeString = [CString]()
    var largestOtherStrings = [CString]()
    let addIfNecessary: (inout [CString], CString) -> Void = { array, newValue in
      let minSize = 1000
      guard newValue.size > minSize else { return }

      array.append(newValue)
    }
    let constantAddresses = getConstantStringAddresses()
    for i in 0...size {
      let byte: UInt8
      if i == size {
        byte = 1
      } else {
        byte = current.load(as: UInt8.self)
      }
      if byte == 0 {
        isAddingZero = true
      } else if isAddingZero {
        // Finished previous string
        let string = String(cString: array)
        let currentSize = UInt64(array.count)
        let cString = CString(string: string, vmStart: currentVMStart, size: currentSize)
        let fileStart = self.fileOffset(for: currentVMStart)!
        if constantAddresses.contains(currentVMStart) {
          classRangeMap.add(
            .init(
              offset: fileStart,
              size: UInt(array.count),
              value: .strings(.init(string: string, type: .cfStrings))
            )
          )
          cfStringsSize += UInt64(array.count)
          addIfNecessary(&largestOtherStrings, cString)
        } else if string.hasSuffix(".swift") {
          classRangeMap.add(
            .init(
              offset: fileStart,
              size: UInt(array.count),
              value: .strings(.init(string: string, type: .swiftFilePaths))
            )
          )
          swiftFileSize += UInt64(array.count)
          addIfNecessary(&largestOtherStrings, cString)
        } else if objcTypeStrings[fileStart] != nil {
          // Obj-C properties
        } else if string.hasPrefix("^->") {
          let fileStart = self.fileOffset(for: currentVMStart)!
          classRangeMap.add(
            .init(
              offset: fileStart,
              size: UInt(array.count),
              value: .strings(.init(string: string, type: .needle))
            )
          )
          componentPathSize += UInt64(array.count)
          addIfNecessary(&largestOtherStrings, cString)
        } else if MethodSignatureResolver.isMethodSignature(string) {
          classRangeMap.add(
            .init(
              offset: fileStart,
              size: UInt(array.count),
              value: .strings(.init(string: string, type: .unmapped))
            )
          )
          // Obj-C methods
          objcTypeSize += UInt64(array.count)
          addIfNecessary(&largestObjcTypeString, cString)
        } else {
          classRangeMap.add(
            .init(
              offset: fileStart,
              size: UInt(array.count),
              value: .strings(.init(string: string, type: .unmapped))
            )
          )
          addIfNecessary(&largestOtherStrings, cString)
        }
        strings[currentVMStart] = cString
        currentVMStart += currentSize
        array.removeAll()
        isAddingZero = false
      }
      array.append(byte)
      if i < size {
        current = current.advanced(by: 1)
      }
    }
    self.strings = Set(strings.values.map { $0.string })

    largestOtherStrings.sort { $0.size > $1.size }
    largestObjcTypeString.sort { $0.size > $1.size }
    //largeObjcStrings = largestObjcTypeString
    largeOtherStrings = largestOtherStrings
  }

  var cStringVMStart: UInt64? {
    cstringSection?.addr
  }
  var cStringFileStart: UInt64? {
    cstringSection.map { UInt64($0.offset) }
  }

  func lookupIndirectRelativePointer<T>(
    fileStart: UInt,
    object: T,
    path: KeyPath<T, RelativePointer>,
    canBeIndirect: Bool = true
  ) -> UInt? {
    let fileLookup = fileStart + UInt(MemoryLayout<T>.offset(of: path)!)
    guard let vmStart = vmAddress(for: UInt64(fileLookup)) else { return nil }

    let relativePointer = object[keyPath: path]
    guard
      let vmDestination = relativePointer.offset(from: UInt(vmStart), canBeIndirect: canBeIndirect)
    else { return nil }
    return vmDestination
  }

  func computeOffset<T>(
    fileStart: UInt,
    object: T,
    path: KeyPath<T, RelativePointer>,
    canBeIndirect: Bool = true
  ) -> UInt? {
    let relativePointer = object[keyPath: path]
    guard
      let vmDestination = lookupIndirectRelativePointer(
        fileStart: fileStart,
        object: object,
        path: path,
        canBeIndirect: canBeIndirect
      )
    else { return nil }

    if let result = fileOffset(for: UInt64(vmDestination)) {
      if canBeIndirect && relativePointer % 2 == 1 {
        let finalPointer = bytes.advanced(by: Int(result)).load(as: UInt64.self)
        //logger.debug("Got final pointer \(finalPointer)")
        return fileOffset(for: rebase(finalPointer)).map { UInt($0) }
      }
      return UInt(result)
    }

    return nil
  }

  let url: URL
}

extension URL {
  public func machOUUID() -> String? {
    if let data = try? NSData(contentsOf: self, options: .alwaysMapped) {
      let pointer = data.bytes
      let result = pointer.machOUUID()
      return result
    }
    return nil
  }
}

extension UnsafeRawPointer {
  func numberOfCommands() -> (Int, UnsafeRawPointer)? {
    let headerPointer = load(as: mach_header_64.self)
    let headerSize: Int
    if headerPointer.magic == MH_MAGIC_64 {
      headerSize = MemoryLayout<mach_header_64>.size
    } else {
      return nil
    }

    return (Int(headerPointer.ncmds), advanced(by: headerSize))
  }

  func processLoadComands(_ callback: (load_command, UnsafeRawPointer) -> Bool) {
    var pointer: UnsafeRawPointer
    guard let (numberOfCommands, headers) = numberOfCommands() else { return }

    if numberOfCommands > 1000 {
      logger.warning("Too many load commands")
      return
    }

    pointer = headers
    for _ in 0..<numberOfCommands {
      let command = pointer.load(as: load_command.self)
      if !callback(command, pointer) {
        break
      }
      pointer = pointer.advanced(by: Int(command.cmdsize))
    }
  }

  func machOUUID() -> String? {
    var uuidString: String? = nil
    processLoadComands { command, commandPointer in
      guard command.cmd == LC_UUID else { return true }
      let uuidCommand = commandPointer.load(as: uuid_command.self)

      uuidString = UUID(uuid: uuidCommand.uuid).uuidString
      return false
    }
    return uuidString
  }
}

extension Array {
  func iterateByTwo(_ block: (Element, Element?) -> Void) {
    var shifted: [Element?] = Array(self.dropFirst())
    shifted.append(nil)
    zip(self, shifted).forEach(block)
  }
}

extension UInt64 {
  var unpackedTarget: UInt64 {
    return (((self >> 36) & 0xFF) << 56) | (self & 0xF_FFFF_FFFF)
  }
}

func disasembleInstructions(
  capstone: Capstone,
  data: Data,
  startAddress: UInt64
) -> DisasembleResult {
  var branchAddress = [Int]()
  var branchLinkAddress = [Int]()
  var relativeAddresses = [Int]()
  do {
    var processedSize = 0
    let finished = try disassemble(capstone: capstone, data: data, at: startAddress) { ins in
      if standardBranchInstructions.contains(ins.mnemonic) {
        if let address = Int(ins.operandsString.dropFirst(3), radix: 16) {
          branchAddress.append(address)
        } else {
          logger.warning("Invalid standard branch instruction \(ins)")
        }
      } else if expandedLinks.contains(ins.mnemonic) {
        if let addrString = ins.operandsString.split(separator: ",").last,
          let address = Int(addrString.dropFirst(4), radix: 16)
        {
          branchAddress.append(address)
        } else {
          logger.warning("Invalid expanded link \(ins)")
        }
      } else if standardBranchLinks.contains(ins.mnemonic) {
        if let address = Int(ins.operandsString.dropFirst(3), radix: 16) {
          branchLinkAddress.append(address)
        } else {
          logger.warning("Invalid standard branch link \(ins)")
        }
      } else if relativeAddress.contains(ins.mnemonic) {
        if let addrString = ins.operandsString.split(separator: ",").last {
          if let address = Int(addrString.dropFirst(4), radix: 16) {
            relativeAddresses.append(address)
          } else if let immediateValue = Int(addrString.dropFirst(2), radix: 16) {
            // eg 'adr x1, #0'
            // possible fix: relativeAddresses.append(Int(ins.address) + immediateValue)
            // logger.warning("Invalid relative address with immediate value \(ins)")
          } else {
            logger.warning("Invalid relative address \(ins)")
          }
        }
      }
      processedSize += Int(ins.size)
      if ins.mnemonic == "ret" || ins.mnemonic == "b" || ins.mnemonic == "br" {
        return false
      }
      return true
    }
    if finished {
      return DisasembleResult(
        size: nil,
        nonSubroutineBranch: branchAddress,
        subroutineBranch: branchLinkAddress,
        relativeAddresses: relativeAddresses
      )
    } else {
      return DisasembleResult(
        size: processedSize,
        nonSubroutineBranch: branchAddress,
        subroutineBranch: branchLinkAddress,
        relativeAddresses: relativeAddresses
      )
    }
  } catch {
    logger.error("capstone error \(error)")
  }
  return DisasembleResult(
    size: nil,
    nonSubroutineBranch: branchAddress,
    subroutineBranch: branchLinkAddress,
    relativeAddresses: relativeAddresses
  )
}

private func disassemble<Ins: Instruction>(
  capstone: Capstone,
  data: Data,
  at address: UInt64,
  parse: (Ins) -> Bool
) throws -> Bool {
  var instruction: Ins
  var i = 0
  repeat {
    let rangeData = data[i...]
    let capstoneResult: [Ins] = try capstone.disassemble(
      code: rangeData,
      address: address + UInt64(i),
      count: 1
    )
    if let ins = capstoneResult.first {
      i = i + Int(ins.size)
      instruction = ins
    } else {
      return true
    }
  } while parse(instruction) && i < data.count
  return i >= data.count
}

// Not a subroutine
let standardBranchInstructions = [
  "b",
  "bne",
  "b.ne",
  "b.eq",
  "b.hs",
  "b.vs",
  "b.ge",
  "b.lt",
  "b.hi",
  "b.gt",
  "b.lo",
  "b.le",
  "b.vc",
  "b.ls",
  "b.mi",
  "b.pl",
]
// Branch to a subroutine
let standardBranchLinks = [
  "bl"
]
// Not a subroutine
let expandedLinks = [
  "cbz",
  "cbnz",
  "tbnz",
  "tbz",
]

let relativeAddress = [
  "adr"
]
