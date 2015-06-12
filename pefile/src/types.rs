#![allow(dead_code, non_snake_case)]

use std::fmt;

use typemap::Key;

use consts::{
    IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
    IMAGE_SIZEOF_SHORT_NAME
};


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


#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct NtHeaders {
    pub Signature:      u32,
    pub FileHeader:     FileHeader,
    pub OptionalHeader: OptionalHeader,
}

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


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct DataDirectory {
    pub VirtualAddress: u32,
    pub Size:           u32,
}


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


#[derive(PartialEq, Eq)]
pub struct SectionName(pub [u8; IMAGE_SIZEOF_SHORT_NAME]);


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


#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct LoadConfigDirectory32 {
    pub Size:                          u32,
    pub TimeDateStamp:                 u32,
    pub MajorVersion:                  u16,
    pub MinorVersion:                  u16,
    pub GlobalFlagsClear:              u32,
    pub GlobalFlagsSet:                u32,
    pub CriticalSectionDefaultTimeout: u32,
    pub DeCommitFreeBlockThreshold:    u32,
    pub DeCommitTotalFreeThreshold:    u32,
    pub LockPrefixTable:               u32,           // VA
    pub MaximumAllocationSize:         u32,
    pub VirtualMemoryThreshold:        u32,
    pub ProcessHeapFlags:              u32,
    pub ProcessAffinityMask:           u32,
    pub CSDVersion:                    u16,
    pub Reserved1:                     u16,
    pub EditList:                      u32,           // VA
    pub SecurityCookie:                u32,           // VA
    pub SEHandlerTable:                u32,           // VA
    pub SEHandlerCount:                u32,
}


#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct LoadConfigDirectory64 {
    pub Size:                           u32,
    pub TimeDateStamp:                  u32,
    pub MajorVersion:                   u16,
    pub MinorVersion:                   u16,
    pub GlobalFlagsClear:               u32,
    pub GlobalFlagsSet:                 u32,
    pub CriticalSectionDefaultTimeout:  u32,
    pub DeCommitFreeBlockThreshold:     u64,
    pub DeCommitTotalFreeThreshold:     u64,
    pub LockPrefixTable:                u64,
    pub MaximumAllocationSize:          u64,
    pub VirtualMemoryThreshold:         u64,
    pub ProcessAffinityMask:            u64,
    pub ProcessHeapFlags:               u32,
    pub CSDVersion:                     u16,
    pub Reserved1:                      u16,
    pub EditList:                       u64,
    pub SecurityCookie:                 u64,
    pub SEHandlerTable:                 u64,
    pub SEHandlerCount:                 u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoadConfigDirectory {
    Directory32(LoadConfigDirectory32),
    Directory64(LoadConfigDirectory64),
}

#[derive(Debug, PartialEq, Eq)]
pub struct LoadConfigDirectoryKey;

impl Key for LoadConfigDirectoryKey { type Value = LoadConfigDirectory; }
