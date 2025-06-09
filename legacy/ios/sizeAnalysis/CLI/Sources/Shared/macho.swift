//
//  File.swift
//
//
//  Created by Noah Martin on 11/18/20.
//

import Foundation

public struct mach_header_64 {
  let magic: UInt32 /* mach magic number identifier */
  let cputype: Int32 /* cpu specifier */
  let cpusubtype: Int32 /* machine specifier */
  let filetype: UInt32 /* type of file */
  let ncmds: UInt32 /* number of load commands */
  let sizeofcmds: UInt32 /* the size of all the load commands */
  let flags: UInt32 /* flags */
  let reserved: UInt32 /* reserved */
}

public struct fat_header {
  public let magic: UInt32 /* FAT_MAGIC or FAT_MAGIC_64 */
  let nfat_arch: UInt32 /* number of structs that follow */

  var requiresReverse: Bool {
    magic == FAT_CIGAM
  }

  public var numberOfArchs: UInt {
    if !requiresReverse {
      return UInt(nfat_arch)
    } else {
      return UInt(nfat_arch.byteSwapped)
    }
  }

  public func archs(from: FileHandle) -> [cpu_type_t] {
    var archs = [cpu_type_t]()
    for _ in 0..<numberOfArchs {
      let arch_pointer = (from.readData(ofLength: MemoryLayout<fat_arch>.size) as NSData).bytes
        .assumingMemoryBound(to: fat_arch.self)
      if requiresReverse {
        archs.append(arch_pointer.pointee.cputype.byteSwapped)
      } else {
        archs.append(arch_pointer.pointee.cputype)
      }
    }
    return archs
  }
}

public let FAT_MAGIC = 0xcafe_babe
public let FAT_CIGAM = 0xbeba_feca

struct load_command {
  let cmd: UInt32 /* type of load command */
  let cmdsize: UInt32 /* total size of command in bytes */
}

typealias vm_prot_t = Int32

struct segment_command_64 {

  let cmd: UInt32 /* for 64-bit architectures */
  /* LC_SEGMENT_64 */

  let cmdsize: UInt32 /* includes sizeof section_64 structs */

  let segname:
    (
      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8
    ) /* segment name */

  let vmaddr: UInt64 /* memory address of this segment */

  let vmsize: UInt64 /* memory size of this segment */

  let fileoff: UInt64 /* file offset of this segment */

  let filesize: UInt64 /* amount to map from the file */

  let maxprot: vm_prot_t /* maximum VM protection */

  let initprot: vm_prot_t /* initial VM protection */

  let nsects: UInt32 /* number of sections in segment */

  let flags: UInt32 /* flags */
}

struct section_64 {

  let sectname:
    (
      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8
    ) /* for 64-bit architectures */
  /* name of this section */

  let segname:
    (
      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8
    ) /* segment this section goes in */

  let addr: UInt64 /* memory address of this section */

  let size: UInt64 /* size in bytes of this section */

  let offset: UInt32 /* file offset of this section */

  let align: UInt32 /* section alignment (power of 2) */

  let reloff: UInt32 /* file offset of relocation entries */

  let nreloc: UInt32 /* number of relocation entries */

  let flags: UInt32 /* flags (section type and attributes)*/

  let reserved1: UInt32 /* reserved (for offset or index) */

  let reserved2: UInt32 /* reserved (for count or sizeof) */

  let reserved3: UInt32 /* reserved */
}

let LC_REQ_DYLD = 0x8000_0000
let LC_SEGMENT_64 = 0x19
let LC_DYLD_INFO_ONLY = (0x22 | LC_REQ_DYLD)
let LC_SYMTAB = 0x2
let LC_DYSYMTAB = 0xb
let LC_UUID = 0x1b

struct ClassDescriptor {
  let flags: UInt32
  let parent: Int32
  let name: Int32
  let accessFunction: Int32
  let fieldDescriptor: Int32
  let superclassType: Int32
  let metadataNegativeSizeInWords: UInt32
  let metadataPositiveSizeInWords: UInt32
  let numImmediateMembers: UInt32
  let numFields: UInt32
}
