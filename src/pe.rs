use std::cmp;
use std::fmt;
use std::io::Cursor;

use byteorder::{ReadBytesExt, LittleEndian};
use nom::{IResult, le_i32, le_u8, le_u16, le_u32, le_u64};


// We put all the constants in a submodule that allows dead code, to prevent
// ridiculous numbers of warnings.
#[allow(dead_code)]
mod consts {
  pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0;
  pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
  pub const IMAGE_FILE_MACHINE_R3000: u16 = 0x0162;
  pub const IMAGE_FILE_MACHINE_R4000: u16 = 0x0166;
  pub const IMAGE_FILE_MACHINE_R10000: u16 = 0x0168;
  pub const IMAGE_FILE_MACHINE_WCEMIPSV2: u16 = 0x0169;
  pub const IMAGE_FILE_MACHINE_ALPHA: u16 = 0x0184;
  pub const IMAGE_FILE_MACHINE_SH3: u16 = 0x01a2;
  pub const IMAGE_FILE_MACHINE_SH3DSP: u16 = 0x01a3;
  pub const IMAGE_FILE_MACHINE_SH3E: u16 = 0x01a4;
  pub const IMAGE_FILE_MACHINE_SH4: u16 = 0x01a6;
  pub const IMAGE_FILE_MACHINE_SH5: u16 = 0x01a8;
  pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
  pub const IMAGE_FILE_MACHINE_ARMV7: u16 = 0x01c4;
  pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
  pub const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01c2;
  pub const IMAGE_FILE_MACHINE_AM33: u16 = 0x01d3;
  pub const IMAGE_FILE_MACHINE_POWERPC: u16 = 0x01F0;
  pub const IMAGE_FILE_MACHINE_POWERPCFP: u16 = 0x01f1;
  pub const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;
  pub const IMAGE_FILE_MACHINE_MIPS16: u16 = 0x0266;
  pub const IMAGE_FILE_MACHINE_ALPHA64: u16 = 0x0284;
  pub const IMAGE_FILE_MACHINE_MIPSFPU: u16 = 0x0366;
  pub const IMAGE_FILE_MACHINE_MIPSFPU16: u16 = 0x0466;
  pub const IMAGE_FILE_MACHINE_AXP64: u16 = IMAGE_FILE_MACHINE_ALPHA64;
  pub const IMAGE_FILE_MACHINE_TRICORE: u16 = 0x0520;
  pub const IMAGE_FILE_MACHINE_CEF: u16 = 0x0CEF;
  pub const IMAGE_FILE_MACHINE_EBC: u16 = 0x0EBC;
  pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
  pub const IMAGE_FILE_MACHINE_M32R: u16 = 0x9041;
  pub const IMAGE_FILE_MACHINE_CEE: u16 = 0xc0ee;

  pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
  pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
  pub const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;
  pub const IMAGE_FILE_LOCAL_SYMS_STRIPPED: u16 = 0x0008;
  pub const IMAGE_FILE_AGGRESIVE_WS_TRIM: u16 = 0x0010;
  pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
  pub const IMAGE_FILE_BYTES_REVERSED_LO: u16 = 0x0080;
  pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
  pub const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x0200;
  pub const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
  pub const IMAGE_FILE_NET_RUN_FROM_SWAP: u16 = 0x0800;
  pub const IMAGE_FILE_SYSTEM: u16 = 0x1000;
  pub const IMAGE_FILE_DLL: u16 = 0x2000;
  pub const IMAGE_FILE_UP_SYSTEM_ONLY: u16 = 0x4000;
  pub const IMAGE_FILE_BYTES_REVERSED_HI: u16 = 0x8000;

  pub const IMAGE_SUBSYSTEM_UNKNOWN: u16 = 0;
  pub const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
  pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
  pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
  pub const IMAGE_SUBSYSTEM_OS2_CUI: u16 = 5;
  pub const IMAGE_SUBSYSTEM_POSIX_CUI: u16 = 7;
  pub const IMAGE_SUBSYSTEM_NATIVE_WINDOWS: u16 = 8;
  pub const IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: u16 = 9;
  pub const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;
  pub const IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: u16 = 11;
  pub const IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: u16 = 12;
  pub const IMAGE_SUBSYSTEM_EFI_ROM: u16 = 13;
  pub const IMAGE_SUBSYSTEM_XBOX: u16 = 14;
  pub const IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: u16 = 16;

  pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
  pub const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
  pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
  pub const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;
  pub const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
  pub const IMAGE_DLLCHARACTERISTICS_NO_BIND: u16 = 0x0800;
  pub const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;
  pub const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: u16 = 0x2000;
  pub const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

  pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
  pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
  pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
  pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
  pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
  pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
  pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
  pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
  pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
  pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
  pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
  pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
  pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
  pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
  pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

  pub const IMAGE_SCN_TYPE_NO_PAD: u32 = 0x00000008;

  pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
  pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
  pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
  pub const IMAGE_SCN_LNK_OTHER: u32 = 0x00000100;
  pub const IMAGE_SCN_LNK_INFO: u32 = 0x00000200;
  pub const IMAGE_SCN_LNK_REMOVE: u32 = 0x00000800;
  pub const IMAGE_SCN_LNK_COMDAT: u32 = 0x00001000;
  pub const IMAGE_SCN_NO_DEFER_SPEC_EXC: u32 = 0x00004000;
  pub const IMAGE_SCN_GPREL: u32 = 0x00008000;
  pub const IMAGE_SCN_MEM_FARDATA: u32 = 0x00008000;
  pub const IMAGE_SCN_MEM_PURGEABLE: u32 = 0x00020000;
  pub const IMAGE_SCN_MEM_16BIT: u32 = 0x00020000;
  pub const IMAGE_SCN_MEM_LOCKED: u32 = 0x00040000;
  pub const IMAGE_SCN_MEM_PRELOAD: u32 = 0x00080000;

  pub const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x00100000;
  pub const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x00200000;
  pub const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x00300000;
  pub const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x00400000;
  pub const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x00500000;
  pub const IMAGE_SCN_ALIGN_32BYTES: u32 = 0x00600000;
  pub const IMAGE_SCN_ALIGN_64BYTES: u32 = 0x00700000;
  pub const IMAGE_SCN_ALIGN_128BYTES: u32 = 0x00800000;
  pub const IMAGE_SCN_ALIGN_256BYTES: u32 = 0x00900000;
  pub const IMAGE_SCN_ALIGN_512BYTES: u32 = 0x00A00000;
  pub const IMAGE_SCN_ALIGN_1024BYTES: u32 = 0x00B00000;
  pub const IMAGE_SCN_ALIGN_2048BYTES: u32 = 0x00C00000;
  pub const IMAGE_SCN_ALIGN_4096BYTES: u32 = 0x00D00000;
  pub const IMAGE_SCN_ALIGN_8192BYTES: u32 = 0x00E00000;

  pub const IMAGE_SCN_ALIGN_MASK: u32 = 0x00F00000;

  pub const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x01000000;
  pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x02000000;
  pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x04000000;
  pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x08000000;
  pub const IMAGE_SCN_MEM_SHARED: u32 = 0x10000000;
  pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
  pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
  pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

  pub const IMAGE_SCN_SCALE_INDEX: u32 = 0x00000001;
}

// Re-export the above constants so we can use them.
pub use self::consts::*;


#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct DosHeader {
  pub e_magic:    u16,
  pub e_cblp:     u16,
  pub e_cp:       u16,
  pub e_crlc:     u16,
  pub e_cparhdr:  u16,
  pub e_minalloc: u16,
  pub e_maxalloc: u16,
  pub e_ss:       u16,
  pub e_sp:       u16,
  pub e_csum:     u16,
  pub e_ip:       u16,
  pub e_cs:       u16,
  pub e_lfarlc:   u16,
  pub e_ovno:     u16,
  pub e_res:      [u16; 4],
  pub e_oemid:    u16,
  pub e_oeminfo:  u16,
  pub e_res2:     [u16; 10],
  pub e_lfanew:   i32,
}


pub fn parse_dos_header(input: &[u8]) -> IResult<&[u8], DosHeader> {
  chain!(input,
    tag!("MZ")                            ~
    e_cblp:     le_u16                    ~
    e_cp:       le_u16                    ~
    e_crlc:     le_u16                    ~
    e_cparhdr:  le_u16                    ~
    e_minalloc: le_u16                    ~
    e_maxalloc: le_u16                    ~
    e_ss:       le_u16                    ~
    e_sp:       le_u16                    ~
    e_csum:     le_u16                    ~
    e_ip:       le_u16                    ~
    e_cs:       le_u16                    ~
    e_lfarlc:   le_u16                    ~
    e_ovno:     le_u16                    ~
    e_res:      count!( le_u16, u16, 4 )  ~
    e_oemid:    le_u16                    ~
    e_oeminfo:  le_u16                    ~
    e_res2:     count!( le_u16, u16, 10 ) ~
    e_lfanew:   le_i32                    ,
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


#[allow(non_snake_case)]
#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct NtHeaders {
  pub Signature:      u32,
  pub FileHeader:     FileHeader,
  pub OptionalHeader: OptionalHeader,
}


#[allow(non_snake_case)]
#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FileHeader {
  pub Machine:              u16,
  pub NumberOfSections:     u16,
  pub TimeDateStamp:        u32,
  pub PointerToSymbolTable: u32,
  pub NumberOfSymbols:      u32,
  pub SizeOfOptionalHeader: u16,
  pub Characteristics:      u16,
}


const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;


#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct DataDirectory {
  pub VirtualAddress: u32,
  pub Size:           u32,
}


#[allow(non_snake_case)]
#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct OptionalHeader32 {
  pub Magic:                       u16,
  pub MajorLinkerVersion:          u8,
  pub MinorLinkerVersion:          u8,
  pub SizeOfCode:                  u32,
  pub SizeOfInitializedData:       u32,
  pub SizeOfUninitializedData:     u32,
  pub AddressOfEntryPoint:         u32,
  pub BaseOfCode:                  u32,
  pub BaseOfData:                  u32,
  pub ImageBase:                   u32,
  pub SectionAlignment:            u32,
  pub FileAlignment:               u32,
  pub MajorOperatingSystemVersion: u16,
  pub MinorOperatingSystemVersion: u16,
  pub MajorImageVersion:           u16,
  pub MinorImageVersion:           u16,
  pub MajorSubsystemVersion:       u16,
  pub MinorSubsystemVersion:       u16,
  pub Win32VersionValue:           u32,
  pub SizeOfImage:                 u32,
  pub SizeOfHeaders:               u32,
  pub CheckSum:                    u32,
  pub Subsystem:                   u16,
  pub DllCharacteristics:          u16,
  pub SizeOfStackReserve:          u32,
  pub SizeOfStackCommit:           u32,
  pub SizeOfHeapReserve:           u32,
  pub SizeOfHeapCommit:            u32,
  pub LoaderFlags:                 u32,
  pub NumberOfRvaAndSizes:         u32,
  pub DataDirectory:               [DataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

#[allow(non_snake_case)]
#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct OptionalHeader64 {
  pub Magic:                       u16,
  pub MajorLinkerVersion:          u8,
  pub MinorLinkerVersion:          u8,
  pub SizeOfCode:                  u32,
  pub SizeOfInitializedData:       u32,
  pub SizeOfUninitializedData:     u32,
  pub AddressOfEntryPoint:         u32,
  pub BaseOfCode:                  u32,
  pub ImageBase:                   u64,
  pub SectionAlignment:            u32,
  pub FileAlignment:               u32,
  pub MajorOperatingSystemVersion: u16,
  pub MinorOperatingSystemVersion: u16,
  pub MajorImageVersion:           u16,
  pub MinorImageVersion:           u16,
  pub MajorSubsystemVersion:       u16,
  pub MinorSubsystemVersion:       u16,
  pub Win32VersionValue:           u32,
  pub SizeOfImage:                 u32,
  pub SizeOfHeaders:               u32,
  pub CheckSum:                    u32,
  pub Subsystem:                   u16,
  pub DllCharacteristics:          u16,
  pub SizeOfStackReserve:          u64,
  pub SizeOfStackCommit:           u64,
  pub SizeOfHeapReserve:           u64,
  pub SizeOfHeapCommit:            u64,
  pub LoaderFlags:                 u32,
  pub NumberOfRvaAndSizes:         u32,
  pub DataDirectory:               [DataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}


#[derive(Debug, PartialEq, Eq)]
pub enum OptionalHeader {
  Headers32(OptionalHeader32),
  Headers64(OptionalHeader64),
  Unknown,
}


#[allow(non_snake_case)]
fn file_header(input: &[u8]) -> IResult<&[u8], FileHeader> {
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


/// Copy of the old count! macro before it switched to fixed-size arrays, and
/// with a slight optimization to use Vec::with_capacity instead of Vec::new.
macro_rules! vec_count(
  ($i:expr, $submac:ident!( $($args:tt)* ), $count: expr) => (
    {
      let mut begin = 0;
      let mut remaining = $i.len();
      let mut res = Vec::with_capacity($count);
      let mut cnt = 0;
      let mut err = false;
      loop {
        match $submac!(&$i[begin..], $($args)*) {
          ::nom::IResult::Done(i,o) => {
            res.push(o);
            begin += remaining - i.len();
            remaining = i.len();
            cnt = cnt + 1;
            if cnt == $count {
              break
            }
          },
          ::nom::IResult::Error(_)  => {
            err = true;
            break;
          },
          ::nom::IResult::Incomplete(_) => {
            break;
          }
        }
      }
      if err {
        ::nom::IResult::Error(::nom::Err::Position(::nom::ErrorCode::Count as u32,$i))
      } else if cnt == $count {
        ::nom::IResult::Done(&$i[begin..], res)
      } else {
        ::nom::IResult::Incomplete(::nom::Needed::Unknown)
      }
    }
  );
  ($i:expr, $f:expr, $count: expr) => (
    vec_count!($i, call!($f), $count);
  );
);


// TODO: remove parse_ prefix?
#[allow(non_snake_case)]
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


// TODO: remove parse_ prefix?
fn parse_data_directories(input: &[u8], count: u32) -> IResult<&[u8], Vec<DataDirectory>> {
  let min_count = cmp::min(count, 0x10) as usize;

  debug!("Parsing {} data directories", min_count);
  vec_count!(input,
    parse_data_directory,
    min_count
  )
}


#[allow(non_snake_case)]
fn optional_header_32(input: &[u8]) -> IResult<&[u8], OptionalHeader32> {
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


#[allow(non_snake_case)]
fn optional_header_64(input: &[u8]) -> IResult<&[u8], OptionalHeader64> {
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
    file_header: file_header                                              ~
    optional_32: cond!(file_header.Machine == 0x014c, call!(optional_header_32)) ~
    optional_64: cond!(file_header.Machine == 0x8664, call!(optional_header_64)) ,

    || {
      // Parse the signature - we could use the hard-coded value, but this
      // doesn't duplicate code :-)
      let sig = {
        let mut cur = Cursor::new(signature);
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


pub const IMAGE_SIZEOF_SHORT_NAME: usize = 8;


#[derive(PartialEq, Eq)]
pub struct SectionName([u8; IMAGE_SIZEOF_SHORT_NAME]);


impl fmt::Debug for SectionName {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
    let SectionName(ref arr) = *self;

    let strs: Vec<String> = arr.iter()
      .map(|&b| {
        if b >= 0x20 && b < 0x80 && b != b'"' && b != b'\\' {
          format!("{}", b as char)
        } else {
          format!("\\x{:02x}", b)
        }
      })
      .collect();

    write!(fmt, "SectionName(\"{}\")", strs.connect(""))
  }
}


#[allow(non_snake_case)]
#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SectionHeader {
  pub Name:                          SectionName,
  pub PhysicalAddressAndVirtualSize: u32,
  pub VirtualAddress:                u32,
  pub SizeOfRawData:                 u32,
  pub PointerToRawData:              u32,
  pub PointerToRelocations:          u32,
  pub PointerToLinenumbers:          u32,
  pub NumberOfRelocations:           u16,
  pub NumberOfLinenumbers:           u16,
  pub Characteristics:               u32,
}


impl SectionHeader {
  pub fn contains_virtual_address(&self, addr: u32) -> bool {
    addr >= self.VirtualAddress && addr <= (self.VirtualAddress + self.SizeOfRawData)
  }
}


#[allow(non_snake_case)]
pub fn parse_section_header(input: &[u8]) -> IResult<&[u8], SectionHeader> {
  chain!(input,
    name:                          count!( le_u8, u8, IMAGE_SIZEOF_SHORT_NAME ) ~
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
