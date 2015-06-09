#![feature(trace_macros)]

extern crate byteorder;
extern crate libc;
extern crate mmap;
#[macro_use] extern crate nom;

mod pe;

use std::fs;

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


fn check(buf: &[u8]) {
  let dos_header = match parse_dos_header(buf) {
    IResult::Done(_, header) => {
      println!("Parsed DOS header");
      println!("{:?}", header);

      header
    }
    e => {
      println!("Could not parse DOS header: {:?}", e);
      return;
    }
  };

  // Validate the offset into the buffer.
  let offset = {
    if dos_header.e_lfanew < 0 {
      println!("e_lfanew is negative: {}", dos_header.e_lfanew);
      return;
    }

    let val = dos_header.e_lfanew as usize;
    if val > buf.len() {
      println!("Invalid e_lfanew: {}", val);
      return;
    }

    val
  };

  // Read the PE header.
  let nt_headers = match parse_nt_headers(&buf[offset..]) {
    IResult::Done(_, header) => {
      println!("Parsed NT headers");
      println!("{:?}", header);

      header
    }
    e => {
      println!("Could not parse NT headers: {:?}", e);
      return;
    }
  };
}


fn with_file_mmap<P, F, T>(path: P, f: F) -> T
    where P: std::convert::AsRef<std::path::Path>,
          F: Fn(&[u8]) -> T
{
  let file = fs::OpenOptions::new()
    .create(true)
    .read(true)
    .write(true)
    .open(path)
    .unwrap();

  let fd = get_fd(&file);

  let chunk = MemoryMap::new(1, &[
    MapOption::MapReadable,
    MapOption::MapWritable,
    MapOption::MapFd(fd),
  ]).unwrap();

  let file_data: &[u8] = unsafe {
    std::slice::from_raw_parts(chunk.data() as *const _, chunk.len())
  };

  f(file_data)
}


fn main() {
  let input_path = "test_binaries/x64/CompileFlags-no-GS.exe";

  with_file_mmap(input_path, |buf| {
    println!("Mapped the file");
    check(buf);
  });
}
