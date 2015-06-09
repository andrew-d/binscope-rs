#![feature(trace_macros)]

extern crate byteorder;
extern crate clap;
extern crate libc;
extern crate mmap;
#[macro_use] extern crate nom;

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

  if let Some(ref input_paths) = matches.values_of("input") {
    for input_path in input_paths {
      println!("Checking file: {}", input_path);

      with_file_mmap(input_path, |buf| {
        check(buf);
      });
    }
  } else {
    println!("No input file(s) given");
  }
}
