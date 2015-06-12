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


fn verify_image_headers(dos_header: &DosHeader, nt_headers: &NtHeaders) -> Result<(), PeError> {
    if nt_headers.Signature != IMAGE_NT_SIGNATURE {
        return Err(PeError::InvalidNtSignature(nt_headers.Signature));
    }

    if nt_headers.FileHeader.Machine == 0 &&
       nt_headers.FileHeader.SizeOfOptionalHeader == 0 {
        return Err(PeError::InvalidNtHeaders);
    }

    if nt_headers.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
        return Err(PeError::ImageIsNotExecutable);
    }

    if nt_headers.FileHeader.NumberOfSections > 95 {
        return Err(PeError::TooManySections(nt_headers.FileHeader.NumberOfSections));
    }

    macro_rules! validate_optional_header {
        ($header:expr) => {
            if $header.FileAlignment & 511 != 0 &&
               $header.FileAlignment != $header.SectionAlignment {
                return Err(PeError::InvalidNtHeaders);
            }

            if $header.FileAlignment == 0 {
                return Err(PeError::InvalidNtHeaders);
            }

            if ! $header.SectionAlignment.is_power_of_two() ||
               ! $header.FileAlignment.is_power_of_two() {
                return Err(PeError::InvalidNtHeaders);
            }

            if $header.SectionAlignment < $header.FileAlignment {
                return Err(PeError::InvalidNtHeaders);
            }

            if $header.SizeOfImage > 0x77000000 {
                return Err(PeError::InvalidNtHeaders);
            }

            if $header.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
               nt_headers.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 {
                return Err(PeError::InvalidNtHeaders);
            }

            if $header.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
               (nt_headers.FileHeader.Machine != IMAGE_FILE_MACHINE_IA64 &&
                nt_headers.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
                return Err(PeError::InvalidNtHeaders);
            }
        }
    }

    match nt_headers.OptionalHeader {
        OptionalHeader::Headers32(ref hdr) => {
            validate_optional_header!(hdr);
        },
        OptionalHeader::Headers64(ref hdr) => {
            validate_optional_header!(hdr);
        },
        OptionalHeader::Unknown => return Err(PeError::InvalidNtHeaders),
    };

    Ok(())
}


impl PeFile {
    /// Load a PE file by reading from the given source.
    pub fn parse<RS>(src: &mut RS) -> Result<PeFile, PeError>
        where RS: io::Read + io::Seek
        {
            let file_size = try!(Self::get_file_size(src));

            // Read a page from the file.
            let mut first_page = Vec::new();
            first_page.extend(std::iter::repeat(0).take(PAGE_SIZE));

            try!(read_all(src, &mut first_page[..]));

            let dos_header = try!(Self::get_dos_header(&first_page[..], file_size));
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
        let file_size = try!(size_from_seeker(s));

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
