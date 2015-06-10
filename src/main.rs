#![feature(trace_macros)]

extern crate ansi_term;
extern crate byteorder;
extern crate clap;
extern crate fern;
extern crate libc;
extern crate mmap;
#[macro_use] extern crate nom;
extern crate time;

// This needs to go *below* the 'nom' import, so the error! macro doesn't get
// shadowed by nom's version.
#[macro_use] extern crate log;

mod compare;
mod logger;
mod pe;

use std::fs;

use clap::{App, Arg};
use mmap::{MemoryMap, MapOption};
use nom::{IResult};

use pe::*;


// --------------------------------------------------

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[cfg(unix)]
fn get_fd(file: &fs::File) -> libc::c_int {
  file.as_raw_fd()
}

#[cfg(windows)]
fn get_fd(file: &fs::File) -> libc::HANDLE {
  file.as_raw_handle()
}

// --------------------------------------------------


fn check(fname: &str, buf: &[u8]) {
  let dos_header = match parse_dos_header(buf) {
    IResult::Done(_, header) => {
      info!("Parsed DOS header");
      debug!("{:#?}", header);

      header
    }
    e => {
      error!("Could not parse DOS header: {:?}", e);
      return;
    }
  };

  //compare::dump_dos_header(&dos_header);

  // Validate the offset into the buffer.
  let offset = {
    if dos_header.e_lfanew < 0 {
      error!("e_lfanew is negative: {}", dos_header.e_lfanew);
      return;
    }

    let val = dos_header.e_lfanew as usize;
    if val > buf.len() {
      error!("Invalid e_lfanew: {}", val);
      return;
    }

    val
  };

  // Read the PE header.
  let (mut remaining, nt_headers) = match parse_nt_headers(&buf[offset..]) {
    IResult::Done(rem, header) => {
      info!("Parsed NT headers");
      debug!("{:#?}", header);

      (rem, header)
    }
    e => {
      error!("Could not parse NT headers: {:?}", e);
      return;
    }
  };

  //compare::dump_nt_headers(&nt_headers);

  if nt_headers.OptionalHeader == OptionalHeader::Unknown {
    warn!("Cannot parse PE file - unknown machine type: 0x{:04x}",
          nt_headers.FileHeader.Machine);
    return;
  }

  // Start parsing after the NT headers.
  let mut sections = Vec::new();
  for i in 0..nt_headers.FileHeader.NumberOfSections {
    debug!("Parsing section {}", i);

    let (next, section) = match parse_section_header(remaining) {
      IResult::Done(rem, section) => (rem, section),

      e => {
        error!("Could not parse section: {:?}", e);
        return;
      },
    };

    sections.push(section);
    remaining = next;
  }

  info!("Parsed {} sections", nt_headers.FileHeader.NumberOfSections);

  // --------------------------------------------------

  let subsystem = match nt_headers.OptionalHeader {
    OptionalHeader::Headers32(ref h) => h.Subsystem,
    OptionalHeader::Headers64(ref h) => h.Subsystem,
    OptionalHeader::Unknown          => unreachable!(),
  };

  let chars = match nt_headers.OptionalHeader {
    OptionalHeader::Headers32(ref h) => h.DllCharacteristics,
    OptionalHeader::Headers64(ref h) => h.DllCharacteristics,
    OptionalHeader::Unknown          => unreachable!(),
  };

  if subsystem != IMAGE_SUBSYSTEM_NATIVE {
    if chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT == 0 {
      println!("{}:does not have NXCOMPAT bit set", fname)
    }
    if chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0 {
      println!("{}:does not have DYNAMICBASE bit set", fname)
    }
  }

  // --------------------------------------------------

  let load_config_dir = match nt_headers.OptionalHeader {
    OptionalHeader::Headers32(ref h) => &h.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG],
    OptionalHeader::Headers64(ref h) => &h.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG],
    OptionalHeader::Unknown          => unreachable!(),
  };

  if load_config_dir.VirtualAddress != 0 {
    debug!("load config directory is at VA: 0x{:04x}", load_config_dir.VirtualAddress);

    // Find the load config directory in our sections.
    let mut lcbuf = None;
    for section in sections.iter() {
      if section.contains_virtual_address(load_config_dir.VirtualAddress) {
        if !section.contains_virtual_address(load_config_dir.VirtualAddress + load_config_dir.Size) {
          error!("load config directory spans sections!");
          break;
        }

        debug!("found load config directory in section: {:?}", section.Name);

        let offset = (load_config_dir.VirtualAddress - section.VirtualAddress + section.PointerToRawData) as usize;

        lcbuf = Some(&buf[offset..]);
      }
    }

    if let Some(mbuf) = lcbuf {
      let mut security_cookie;

      if nt_headers.FileHeader.Machine == IMAGE_FILE_MACHINE_I386 {
        let load_config = match parse_load_config_directory32(mbuf) {
          IResult::Done(_, dir) => {
            info!("Parsed load config directory");
            debug!("{:#?}", dir);

            dir
          }
          e => {
            error!("Could not parse load config directory: {:?}", e);
            return;
          }
        };

        // Check for SafeSEH
        if chars & IMAGE_DLLCHARACTERISTICS_NO_SEH == 0 {
          if load_config.SEHandlerTable == 0 {
            println!("{}:does not use SAFESEH", fname)
          } else {
            debug!("Skipping SafeSEH check since image has NO_SEH bit set");
          }
        }

        security_cookie = load_config.SecurityCookie as u64;
      } else {
        let load_config = match parse_load_config_directory64(mbuf) {
          IResult::Done(_, dir) => {
            info!("Parsed load config directory");
            debug!("{:#?}", dir);

            dir
          }
          e => {
            error!("Could not parse load config directory: {:?}", e);
            return;
          }
        };

        security_cookie = load_config.SecurityCookie;
      }

      if security_cookie == 0 {
        println!("{}:does not use security cookies\n", fname)
      }
    } else {
      warn!("did not find load config directory in any section");
    }
  }

  // --------------------------------------------------
  const RW_SECTION_FLAGS: u32 = IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

  for section in sections.iter() {
    if section.Characteristics & RW_SECTION_FLAGS == RW_SECTION_FLAGS {
      println!("{}:has a R/W shared section {:?}\n", fname, section.Name)
    }
  }
}


// TODO: real error handling (std::io::Error?)
fn with_file_mmap<P, F, T>(path: P, f: F) -> T
    where P: std::convert::AsRef<std::path::Path>,
          F: Fn(&[u8]) -> T
{
  let file = fs::OpenOptions::new()
    .read(true)
    .open(path)
    .unwrap();

  // Get the size of the file.
  let len = file.metadata().unwrap().len() as usize;

  let fd = get_fd(&file);

  let chunk = MemoryMap::new(len, &[
    MapOption::MapReadable,
    MapOption::MapFd(fd),
  ]).unwrap();

  let file_data: &[u8] = unsafe {
    std::slice::from_raw_parts(chunk.data() as *const _, chunk.len())
  };

  f(file_data)
}


fn main() {
  let matches = App::new("binscope")
                          .version("0.0.1")
                          .author("Andrew Dunham <andrew@du.nham.ca>")
                          .about("Checks a PE file for potential security vulnerabilities")
                          .arg(Arg::with_name("input")
                               .help("Sets the input file(s) to check")
                               .required(true)
                               .multiple(true)
                               .index(1))
                          .arg(Arg::with_name("debug")
                               .short("d")
                               .multiple(true)
                               .help("Sets the level of debugging information"))
                          .get_matches();

  logger::init_logger_config(&matches);

  if let Some(ref input_paths) = matches.values_of("input") {
    for input_path in input_paths {
      info!("Checking file: {}", input_path);

      with_file_mmap(input_path, |buf| {
        check(input_path, buf);
      });
    }
  } else {
    warn!("No input file(s) given");
  }
}
