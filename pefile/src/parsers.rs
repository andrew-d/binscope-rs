#![allow(non_snake_case)]

use std::cmp;
use std::io;

use byteorder::{ReadBytesExt, LittleEndian};
use nom::{IResult, le_i32, le_u8, le_u16, le_u32, le_u64};

use consts::*;
use types::*;

pub fn parse_dos_header(input: &[u8]) -> IResult<&[u8], DosHeader> {
  chain!(input,
    tag!("MZ")                                  ~
    e_cblp:     le_u16                          ~
    e_cp:       le_u16                          ~
    e_crlc:     le_u16                          ~
    e_cparhdr:  le_u16                          ~
    e_minalloc: le_u16                          ~
    e_maxalloc: le_u16                          ~
    e_ss:       le_u16                          ~
    e_sp:       le_u16                          ~
    e_csum:     le_u16                          ~
    e_ip:       le_u16                          ~
    e_cs:       le_u16                          ~
    e_lfarlc:   le_u16                          ~
    e_ovno:     le_u16                          ~
    e_res:      count_fixed!( call!(le_u16), u16, 4 )  ~
    e_oemid:    le_u16                          ~
    e_oeminfo:  le_u16                          ~
    e_res2:     count_fixed!( call!(le_u16), u16, 10 ) ~
    e_lfanew:   le_i32                          ,

    || {
      DosHeader {
        e_magic:    0x5A4D, // 'MZ',
        e_cblp:     e_cblp,
        e_cp:       e_cp,
        e_crlc:     e_crlc,
        e_cparhdr:  e_cparhdr,
        e_minalloc: e_minalloc,
        e_maxalloc: e_maxalloc,
        e_ss:       e_ss,
        e_sp:       e_sp,
        e_csum:     e_csum,
        e_ip:       e_ip,
        e_cs:       e_cs,
        e_lfarlc:   e_lfarlc,
        e_ovno:     e_ovno,
        e_res:      e_res,
        e_oemid:    e_oemid,
        e_oeminfo:  e_oeminfo,
        e_res2:     e_res2,
        e_lfanew:   e_lfanew,
      }
    }
   )
}


fn parse_file_header(input: &[u8]) -> IResult<&[u8], FileHeader> {
  chain!(input,
    machine:              le_u16 ~
    numberOfSections:     le_u16 ~
    timeDateStamp:        le_u32 ~
    pointerToSymbolTable: le_u32 ~
    numberOfSymbols:      le_u32 ~
    sizeOfOptionalHeader: le_u16 ~
    characteristics:      le_u16 ,

    || {
      FileHeader {
        Machine:              machine,
        NumberOfSections:     numberOfSections,
        TimeDateStamp:        timeDateStamp,
        PointerToSymbolTable: pointerToSymbolTable,
        NumberOfSymbols:      numberOfSymbols,
        SizeOfOptionalHeader: sizeOfOptionalHeader,
        Characteristics:      characteristics,
      }
    }
  )
}


fn parse_data_directory(input: &[u8]) -> IResult<&[u8], DataDirectory> {
  chain!(input,
    virtualAddress: le_u32 ~
    size:           le_u32 ,

    || {
      DataDirectory {
        VirtualAddress: virtualAddress,
        Size:           size,
      }
    }
  )
}


fn parse_data_directories(input: &[u8], count: u32) -> IResult<&[u8], Vec<DataDirectory>> {
  let min_count = cmp::min(count, 0x10) as usize;

  debug!("Parsing {} data directories", min_count);
  count!(input,
    parse_data_directory,
    min_count
  )
}


fn parse_optional_header_32(input: &[u8]) -> IResult<&[u8], OptionalHeader32> {
  chain!(input,
    magic:                       le_u16 ~
    majorLinkerVersion:          le_u8  ~
    minorLinkerVersion:          le_u8  ~
    sizeOfCode:                  le_u32 ~
    sizeOfInitializedData:       le_u32 ~
    sizeOfUninitializedData:     le_u32 ~
    addressOfEntryPoint:         le_u32 ~
    baseOfCode:                  le_u32 ~
    baseOfData:                  le_u32 ~
    imageBase:                   le_u32 ~
    sectionAlignment:            le_u32 ~
    fileAlignment:               le_u32 ~
    majorOperatingSystemVersion: le_u16 ~
    minorOperatingSystemVersion: le_u16 ~
    majorImageVersion:           le_u16 ~
    minorImageVersion:           le_u16 ~
    majorSubsystemVersion:       le_u16 ~
    minorSubsystemVersion:       le_u16 ~
    win32VersionValue:           le_u32 ~
    sizeOfImage:                 le_u32 ~
    sizeOfHeaders:               le_u32 ~
    checkSum:                    le_u32 ~
    subsystem:                   le_u16 ~
    dllCharacteristics:          le_u16 ~
    sizeOfStackReserve:          le_u32 ~
    sizeOfStackCommit:           le_u32 ~
    sizeOfHeapReserve:           le_u32 ~
    sizeOfHeapCommit:            le_u32 ~
    loaderFlags:                 le_u32 ~
    numberOfRvaAndSizes:         le_u32 ~
    dataDirectory:               apply!(parse_data_directories, numberOfRvaAndSizes) ,

    || {
      let mut ret = OptionalHeader32 {
        Magic:                       magic,
        MajorLinkerVersion:          majorLinkerVersion,
        MinorLinkerVersion:          minorLinkerVersion,
        SizeOfCode:                  sizeOfCode,
        SizeOfInitializedData:       sizeOfInitializedData,
        SizeOfUninitializedData:     sizeOfUninitializedData,
        AddressOfEntryPoint:         addressOfEntryPoint,
        BaseOfCode:                  baseOfCode,
        BaseOfData:                  baseOfData,
        ImageBase:                   imageBase,
        SectionAlignment:            sectionAlignment,
        FileAlignment:               fileAlignment,
        MajorOperatingSystemVersion: majorOperatingSystemVersion,
        MinorOperatingSystemVersion: minorOperatingSystemVersion,
        MajorImageVersion:           majorImageVersion,
        MinorImageVersion:           minorImageVersion,
        MajorSubsystemVersion:       majorSubsystemVersion,
        MinorSubsystemVersion:       minorSubsystemVersion,
        Win32VersionValue:           win32VersionValue,
        SizeOfImage:                 sizeOfImage,
        SizeOfHeaders:               sizeOfHeaders,
        CheckSum:                    checkSum,
        Subsystem:                   subsystem,
        DllCharacteristics:          dllCharacteristics,
        SizeOfStackReserve:          sizeOfStackReserve,
        SizeOfStackCommit:           sizeOfStackCommit,
        SizeOfHeapReserve:           sizeOfHeapReserve,
        SizeOfHeapCommit:            sizeOfHeapCommit,
        LoaderFlags:                 loaderFlags,
        NumberOfRvaAndSizes:         numberOfRvaAndSizes,
        DataDirectory:               [DataDirectory{VirtualAddress: 0, Size: 0}; IMAGE_NUMBEROF_DIRECTORY_ENTRIES]
      };

      for (i, dir) in dataDirectory.iter().enumerate() {
        ret.DataDirectory[i] = *dir;
      }

      ret
    }
  )
}


fn parse_optional_header_64(input: &[u8]) -> IResult<&[u8], OptionalHeader64> {
  chain!(input,
    magic:                       le_u16 ~
    majorLinkerVersion:          le_u8  ~
    minorLinkerVersion:          le_u8  ~
    sizeOfCode:                  le_u32 ~
    sizeOfInitializedData:       le_u32 ~
    sizeOfUninitializedData:     le_u32 ~
    addressOfEntryPoint:         le_u32 ~
    baseOfCode:                  le_u32 ~
    imageBase:                   le_u64 ~
    sectionAlignment:            le_u32 ~
    fileAlignment:               le_u32 ~
    majorOperatingSystemVersion: le_u16 ~
    minorOperatingSystemVersion: le_u16 ~
    majorImageVersion:           le_u16 ~
    minorImageVersion:           le_u16 ~
    majorSubsystemVersion:       le_u16 ~
    minorSubsystemVersion:       le_u16 ~
    win32VersionValue:           le_u32 ~
    sizeOfImage:                 le_u32 ~
    sizeOfHeaders:               le_u32 ~
    checkSum:                    le_u32 ~
    subsystem:                   le_u16 ~
    dllCharacteristics:          le_u16 ~
    sizeOfStackReserve:          le_u64 ~
    sizeOfStackCommit:           le_u64 ~
    sizeOfHeapReserve:           le_u64 ~
    sizeOfHeapCommit:            le_u64 ~
    loaderFlags:                 le_u32 ~
    numberOfRvaAndSizes:         le_u32 ~
    dataDirectory:               apply!(parse_data_directories, numberOfRvaAndSizes) ,

    || {
      let mut ret = OptionalHeader64 {
        Magic:                       magic,
        MajorLinkerVersion:          majorLinkerVersion,
        MinorLinkerVersion:          minorLinkerVersion,
        SizeOfCode:                  sizeOfCode,
        SizeOfInitializedData:       sizeOfInitializedData,
        SizeOfUninitializedData:     sizeOfUninitializedData,
        AddressOfEntryPoint:         addressOfEntryPoint,
        BaseOfCode:                  baseOfCode,
        ImageBase:                   imageBase,
        SectionAlignment:            sectionAlignment,
        FileAlignment:               fileAlignment,
        MajorOperatingSystemVersion: majorOperatingSystemVersion,
        MinorOperatingSystemVersion: minorOperatingSystemVersion,
        MajorImageVersion:           majorImageVersion,
        MinorImageVersion:           minorImageVersion,
        MajorSubsystemVersion:       majorSubsystemVersion,
        MinorSubsystemVersion:       minorSubsystemVersion,
        Win32VersionValue:           win32VersionValue,
        SizeOfImage:                 sizeOfImage,
        SizeOfHeaders:               sizeOfHeaders,
        CheckSum:                    checkSum,
        Subsystem:                   subsystem,
        DllCharacteristics:          dllCharacteristics,
        SizeOfStackReserve:          sizeOfStackReserve,
        SizeOfStackCommit:           sizeOfStackCommit,
        SizeOfHeapReserve:           sizeOfHeapReserve,
        SizeOfHeapCommit:            sizeOfHeapCommit,
        LoaderFlags:                 loaderFlags,
        NumberOfRvaAndSizes:         numberOfRvaAndSizes,
        DataDirectory:               [DataDirectory{VirtualAddress: 0, Size: 0}; IMAGE_NUMBEROF_DIRECTORY_ENTRIES]
      };

      for (i, dir) in dataDirectory.iter().enumerate() {
        ret.DataDirectory[i] = *dir;
      }

      ret
    }
  )
}


pub fn parse_nt_headers(input: &[u8]) -> IResult<&[u8], NtHeaders> {
  chain!(input,
    signature:   tag!("PE\0\0")                                           ~
    file_header: parse_file_header                                        ~
    optional_32: cond!(file_header.Machine == IMAGE_FILE_MACHINE_I386,
                       call!(parse_optional_header_32))                   ~
    optional_64: cond!(file_header.Machine == IMAGE_FILE_MACHINE_AMD64,
                       call!(parse_optional_header_64))                   ,

    || {
      // Parse the signature - we could use the hard-coded value, but this
      // doesn't duplicate code :-)
      let sig = {
        let mut cur = io::Cursor::new(signature);
        cur.read_u32::<LittleEndian>().unwrap()
      };

      // Pick and wrap the correct optional header
      let optional_header = match (optional_32, optional_64) {
        (Some(hdr), None) => OptionalHeader::Headers32(hdr),
        (None, Some(hdr)) => OptionalHeader::Headers64(hdr),
        (None, None)      => OptionalHeader::Unknown,

        (Some(_), Some(_)) => unreachable!(),
      };

      // All set!
      NtHeaders {
        Signature:      sig,
        FileHeader:     file_header,
        OptionalHeader: optional_header,
      }
    }
  )
}


pub fn parse_section_header(input: &[u8]) -> IResult<&[u8], SectionHeader> {
  chain!(input,
    name:                          count_fixed!( call!(le_u8), u8, IMAGE_SIZEOF_SHORT_NAME ) ~
    physicalAddressAndVirtualSize: le_u32 ~
    virtualAddress:                le_u32 ~
    sizeOfRawData:                 le_u32 ~
    pointerToRawData:              le_u32 ~
    pointerToRelocations:          le_u32 ~
    pointerToLinenumbers:          le_u32 ~
    numberOfRelocations:           le_u16 ~
    numberOfLinenumbers:           le_u16 ~
    characteristics:               le_u32,

    || {
      SectionHeader {
        Name:                          SectionName(name),
        PhysicalAddressAndVirtualSize: physicalAddressAndVirtualSize,
        VirtualAddress:                virtualAddress,
        SizeOfRawData:                 sizeOfRawData,
        PointerToRawData:              pointerToRawData,
        PointerToRelocations:          pointerToRelocations,
        PointerToLinenumbers:          pointerToLinenumbers,
        NumberOfRelocations:           numberOfRelocations,
        NumberOfLinenumbers:           numberOfLinenumbers,
        Characteristics:               characteristics,
      }
    }
  )
}


pub fn parse_load_config_directory32(input: &[u8]) -> IResult<&[u8], LoadConfigDirectory32> {
  chain!(input,
    size:                          le_u32 ~
    timeDateStamp:                 le_u32 ~
    majorVersion:                  le_u16 ~
    minorVersion:                  le_u16 ~
    globalFlagsClear:              le_u32 ~
    globalFlagsSet:                le_u32 ~
    criticalSectionDefaultTimeout: le_u32 ~
    deCommitFreeBlockThreshold:    le_u32 ~
    deCommitTotalFreeThreshold:    le_u32 ~
    lockPrefixTable:               le_u32 ~
    maximumAllocationSize:         le_u32 ~
    virtualMemoryThreshold:        le_u32 ~
    processHeapFlags:              le_u32 ~
    processAffinityMask:           le_u32 ~
    csdVersion:                    le_u16 ~
    reserved1:                     le_u16 ~
    editList:                      le_u32 ~
    securityCookie:                le_u32 ~
    seHandlerTable:                le_u32 ~
    seHandlerCount:                le_u32,

    || {
      LoadConfigDirectory32 {
        Size:                          size,
        TimeDateStamp:                 timeDateStamp,
        MajorVersion:                  majorVersion,
        MinorVersion:                  minorVersion,
        GlobalFlagsClear:              globalFlagsClear,
        GlobalFlagsSet:                globalFlagsSet,
        CriticalSectionDefaultTimeout: criticalSectionDefaultTimeout,
        DeCommitFreeBlockThreshold:    deCommitFreeBlockThreshold,
        DeCommitTotalFreeThreshold:    deCommitTotalFreeThreshold,
        LockPrefixTable:               lockPrefixTable,
        MaximumAllocationSize:         maximumAllocationSize,
        VirtualMemoryThreshold:        virtualMemoryThreshold,
        ProcessHeapFlags:              processHeapFlags,
        ProcessAffinityMask:           processAffinityMask,
        CSDVersion:                    csdVersion,
        Reserved1:                     reserved1,
        EditList:                      editList,
        SecurityCookie:                securityCookie,
        SEHandlerTable:                seHandlerTable,
        SEHandlerCount:                seHandlerCount,
      }
    }
  )
}


pub fn parse_load_config_directory64(input: &[u8]) -> IResult<&[u8], LoadConfigDirectory64> {
  chain!(input,
    size:                           le_u32 ~
    timeDateStamp:                  le_u32 ~
    majorVersion:                   le_u16 ~
    minorVersion:                   le_u16 ~
    globalFlagsClear:               le_u32 ~
    globalFlagsSet:                 le_u32 ~
    criticalSectionDefaultTimeout:  le_u32 ~
    deCommitFreeBlockThreshold:     le_u64 ~
    deCommitTotalFreeThreshold:     le_u64 ~
    lockPrefixTable:                le_u64 ~
    maximumAllocationSize:          le_u64 ~
    virtualMemoryThreshold:         le_u64 ~
    processAffinityMask:            le_u64 ~
    processHeapFlags:               le_u32 ~
    csdVersion:                     le_u16 ~
    reserved1:                      le_u16 ~
    editList:                       le_u64 ~
    securityCookie:                 le_u64 ~
    seHandlerTable:                 le_u64 ~
    seHandlerCount:                 le_u64 ,

    || {
      LoadConfigDirectory64 {
        Size:                           size,
        TimeDateStamp:                  timeDateStamp,
        MajorVersion:                   majorVersion,
        MinorVersion:                   minorVersion,
        GlobalFlagsClear:               globalFlagsClear,
        GlobalFlagsSet:                 globalFlagsSet,
        CriticalSectionDefaultTimeout:  criticalSectionDefaultTimeout,
        DeCommitFreeBlockThreshold:     deCommitFreeBlockThreshold,
        DeCommitTotalFreeThreshold:     deCommitTotalFreeThreshold,
        LockPrefixTable:                lockPrefixTable,
        MaximumAllocationSize:          maximumAllocationSize,
        VirtualMemoryThreshold:         virtualMemoryThreshold,
        ProcessAffinityMask:            processAffinityMask,
        ProcessHeapFlags:               processHeapFlags,
        CSDVersion:                     csdVersion,
        Reserved1:                      reserved1,
        EditList:                       editList,
        SecurityCookie:                 securityCookie,
        SEHandlerTable:                 seHandlerTable,
        SEHandlerCount:                 seHandlerCount,
      }
    }
  )
}
