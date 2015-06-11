// Helper functions for comparison that dump various fields out as csv-ish things.

use pe::*;


macro_rules! print_field {
  ($prefix:expr, $val:expr , $field:ident, $width:expr) => {
    println!(
      concat!("{}{},0x{:0", $width, "x}"),
      $prefix,
      stringify!($field),
      $val.$field
    )
  };

  ($prefix:expr, $val:expr , $field:ident, $width:expr, $($rest:tt),+) => {
    print_field!($prefix, $val, $field, $width);
    print_field!($prefix, $val, $($rest),+)
  };
}

#[allow(dead_code)]
pub fn dump_dos_header(d: &DosHeader) {
  //trace_macros!(true);

  print_field!("DosHeader.", d,
    e_magic, 4,
    e_cblp, 4,
    e_cp, 4,
    e_crlc, 4,
    e_cparhdr, 4,
    e_minalloc, 4,
    e_maxalloc, 4,
    e_ss, 4,
    e_sp, 4,
    e_csum, 4,
    e_ip, 4,
    e_cs, 4,
    e_lfarlc, 4,
    e_ovno, 4,
    e_oemid, 4,
    e_oeminfo, 4,
    e_lfanew, 8
  );
}


#[allow(dead_code)]
pub fn dump_nt_headers(n: &NtHeaders) {
  print_field!("NtHeaders.", n,
    Signature, 8
  );

  print_field!("NtHeaders.FileHeader.", n.FileHeader,
    Machine, 4,
    NumberOfSections, 4,
    TimeDateStamp, 8,
    PointerToSymbolTable, 8,
    NumberOfSymbols, 8,
    SizeOfOptionalHeader, 4,
    Characteristics, 4
  );

  match n.OptionalHeader {
    OptionalHeader::Headers32(ref v) => {
      print_field!("NtHeaders.OptionalHeader.", v,
        Magic, 4,
        MajorLinkerVersion, 2,
        MinorLinkerVersion, 2,
        SizeOfCode, 8,
        SizeOfInitializedData, 8,
        SizeOfUninitializedData, 8,
        AddressOfEntryPoint, 8,
        BaseOfCode, 8,
        BaseOfData, 8,
        ImageBase, 8,
        SectionAlignment, 8,
        FileAlignment, 8,
        MajorOperatingSystemVersion, 4,
        MinorOperatingSystemVersion, 4,
        MajorImageVersion, 4,
        MinorImageVersion, 4,
        MajorSubsystemVersion, 4,
        MinorSubsystemVersion, 4,
        Win32VersionValue, 8,
        SizeOfImage, 8,
        SizeOfHeaders, 8,
        CheckSum, 8,
        Subsystem, 4,
        DllCharacteristics, 4,
        SizeOfStackReserve, 8,
        SizeOfStackCommit, 8,
        SizeOfHeapReserve, 8,
        SizeOfHeapCommit, 8,
        LoaderFlags, 8,
        NumberOfRvaAndSizes, 8
      );
    },

    OptionalHeader::Headers64(ref v) => {
      print_field!("NtHeaders.OptionalHeader.", v,
        Magic, 4,
        MajorLinkerVersion, 2,
        MinorLinkerVersion, 2,
        SizeOfCode, 8,
        SizeOfInitializedData, 8,
        SizeOfUninitializedData, 8,
        AddressOfEntryPoint, 8,
        BaseOfCode, 8,
        ImageBase, 16,
        SectionAlignment, 8,
        FileAlignment, 8,
        MajorOperatingSystemVersion, 4,
        MinorOperatingSystemVersion, 4,
        MajorImageVersion, 4,
        MinorImageVersion, 4,
        MajorSubsystemVersion, 4,
        MinorSubsystemVersion, 4,
        Win32VersionValue, 8,
        SizeOfImage, 8,
        SizeOfHeaders, 8,
        CheckSum, 8,
        Subsystem, 4,
        DllCharacteristics, 4,
        SizeOfStackReserve, 16,
        SizeOfStackCommit, 16,
        SizeOfHeapReserve, 16,
        SizeOfHeapCommit, 16,
        LoaderFlags, 8,
        NumberOfRvaAndSizes, 8
      );
    },

    OptionalHeader::Unknown => {},
  };
}
