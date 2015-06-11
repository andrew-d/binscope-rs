extern crate byteorder;
#[macro_use] extern crate nom;

// This needs to go *below* the 'nom' import, so the error! macro doesn't get
// shadowed by nom's version.
#[macro_use] extern crate log;

mod consts;
mod error;
mod parsers;
mod types;
mod util;

use std::io;
use std::mem::size_of;

use nom::IResult;

use consts::*;
use error::PeError;
use parsers::*;
use types::*;
use util::*;


/// PeFile is the main structure that represents a parsed PE file.  It exposes
/// various accessor methods that allow retrieving the associated data
/// structures.
#[derive(Debug)]
pub struct PeFile {
  _foo: u8,
}


impl PeFile {
  /// Load a PE file by reading from the given source.
  pub fn parse<RS>(src: &mut RS) -> Result<PeFile, PeError>
    where RS: io::Read + io::Seek
  {
    let file_size = match Self::get_file_size(src) {
      Ok(size) => size,
      Err(err) => return Err(err),
    };

    // Read a page from the file.
    let mut first_page = Vec::new();
    first_page.extend(std::iter::repeat(0).take(PAGE_SIZE));

    match read_all(src, &mut first_page[..]) {
      Err(err) => return Err(PeError::IOError(err)),
      Ok(_)    => {},
    };

    let dos_header = match Self::get_dos_header(&first_page[..], file_size) {
      Ok(hdr)  => hdr,
      Err(err) => return Err(err),
    };

    let e_lfanew = dos_header.e_lfanew as usize;

    // If the NT headers and at least 16 section headers don't fit within the
    // first page, we read another 8KiB and use that instead.  Note that we use
    // checked addition to prevent integer overflows.
    let headers_size = e_lfanew
      .checked_add(size_of::<NtHeaders>())
      .and_then(|v| v.checked_add(16 * size_of::<SectionHeader>()));
    match headers_size {
      None      => return Err(PeError::IntegerOverflow("headers")),
      Some(end) if end > PAGE_SIZE => {
        // Read additional data for our NT headers.
      },
      Some(_)   => {/* Good - have all our headers. */}
    };

    // Validate that the offset plus the NT headers fits within the file.  We
    // do this after the overflow check above, since we want to catch integer
    // overflows first.
    if (e_lfanew + size_of::<NtHeaders>()) as u64 > file_size {
      return Err(PeError::InvalidNewOffset(dos_header.e_lfanew));
    }

    Ok(PeFile{
      _foo: 1,
    })
  }

  fn get_file_size<S: io::Seek>(s: &mut S) -> Result<u64, PeError> {
    let file_size = match size_from_seeker(s) {
      Ok(size) => size,
      Err(err) => return Err(PeError::IOError(err)),
    };

    // Validate file size.
    if file_size > std::u32::MAX as u64 {
      return Err(PeError::TooLarge(file_size));
    }
    if file_size < size_of::<DosHeader>() as u64 {
      return Err(PeError::TooSmall(file_size));
    }

    Ok(file_size)
  }

  fn get_dos_header(first_page: &[u8], file_size: u64) -> Result<DosHeader, PeError> {
    // Parse the DOS header from the buffer.
    let dos_header = match parse_dos_header(first_page) {
      IResult::Done(_, header) => {
        info!("Parsed DOS header");
        debug!("{:#?}", header);

        header
      }
      e => {
        error!("Could not parse DOS header: {:?}", e);
        return Err(PeError::InvalidDosHeader(format!("{:?}", e)));
      }
    };

    // Ensure that the size of the DOS header is valid.
    if dos_header.e_lfanew < 0 || (dos_header.e_lfanew as u64) > file_size {
      return Err(PeError::InvalidNewOffset(dos_header.e_lfanew));
    }

    Ok(dos_header)
  }
}


#[cfg(test)]
mod tests {
  use std::error::Error;
  use std::fs::File;
  use std::io;
  use std::path::Path;

  use super::*;
  use super::error::PeError;

  // Test a file that's too large.
  #[test]
  fn test_too_large() {
    const MAX_SIZE: u64 = 4294967296 + 10;
    let mut s = DummySeekerReader{pos: 0, len: MAX_SIZE as i64};

    match PeFile::parse(&mut s) {
      Err(PeError::TooLarge(m)) if m == MAX_SIZE => {},
      e                                          => panic!("Invalid response: {:?}", e),
    };
  }

  // Test a file that's too small.
  #[test]
  fn test_too_small() {
    let buf = b"toosmall";
    let mut cur = io::Cursor::new(&buf[..]);

    match PeFile::parse(&mut cur) {
      Err(PeError::TooSmall(8)) => {},
      e                         => panic!("Invalid response: {:?}", e),
    };
  }

  // Test the case where the e_lfanew value is negative.
  #[test]
  fn test_negative_lfanew() {
    let path = Path::new("test_binaries").join("bad").join("negative-lfanew.exe");

    let mut file = match File::open(&path) {
      Err(why) => panic!("Couldn't open {}: {}", path.display(), Error::description(&why)),
      Ok(file) => file,
    };

    match PeFile::parse(&mut file) {
      Err(PeError::InvalidNewOffset(-1)) => {},
      e                                  => panic!("Invalid response: {:?}", e),
    };
  }

  // Test that the NT headers fit within the file.
  #[test]
  fn test_too_large_lfanew() {
    let path = Path::new("test_binaries").join("bad").join("too-large-lfanew.exe");

    let mut file = match File::open(&path) {
      Err(why) => panic!("Couldn't open {}: {}", path.display(), Error::description(&why)),
      Ok(file) => file,
    };

    match PeFile::parse(&mut file) {
      Err(PeError::InvalidNewOffset(0x10)) => {},
      e                                    => panic!("Invalid response: {:?}", e),
    };
  }

  // --------------------------------------------------

  struct DummySeekerReader {
    pos: i64,
    len: i64,
  }

  impl io::Seek for DummySeekerReader {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
      let new_pos = match pos {
        io::SeekFrom::Start(v)                => v as i64,
        io::SeekFrom::End(v) if v <= self.len => self.len - v,
        io::SeekFrom::End(_)                  => panic!("invalid seek"),
        io::SeekFrom::Current(v)              => self.len + v,
      };

      self.pos = new_pos;
      Ok(new_pos as u64)
    }
  }

  impl io::Read for DummySeekerReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
      Ok(0)
    }
  }
}
