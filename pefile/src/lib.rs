extern crate byteorder;
#[macro_use] extern crate nom;
extern crate typemap;

// This needs to go *below* the 'nom' import, so the error! macro doesn't get
// shadowed by nom's version.
#[macro_use] extern crate log;

mod consts;
mod error;
mod parsers;
mod types;
mod util;

use std::any::Any;
use std::fmt::Debug;
use std::io;
use std::mem::size_of;

use nom::IResult;
use typemap::{DebugMap, TypeMap};

use consts::*;
use error::PeError;
use parsers::*;
use types::*;
use util::*;


// Performs the verifications that Windows does upon the given NT header.
fn verify_nt_headers(nt_headers: &NtHeaders) -> Result<(), PeError> {
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

    if nt_headers.FileHeader.NumberOfSections > IMAGE_MAX_NUMBER_OF_SECTIONS {
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


/// PeFile is the main structure that represents a parsed PE file.  It exposes
/// various accessor methods that allow retrieving the associated data
/// structures.
#[derive(Debug)]
pub struct PeFile {
    dos_header: DosHeader,
    nt_headers: NtHeaders,
    directories: DebugMap,
}


impl PeFile {
    /// Load a PE file by reading from the given source.
    pub fn parse<RS>(src: &mut RS) -> Result<PeFile, PeError>
        where RS: io::Read + io::Seek
    {
        let file_size = try!(Self::get_file_size(src));

        // Read DOS header.
        let dos_header = try!(Self::get_dos_header(src));

        // Ensure that the size of the DOS header is valid.
        if dos_header.e_lfanew < 0 || (dos_header.e_lfanew as u64) > file_size {
            return Err(PeError::InvalidNewOffset(dos_header.e_lfanew));
        }

        // Read the NT headers.
        let nt_headers = try!(Self::get_nt_headers(src, &dos_header));

        // Verify the NT headers.
        try!(verify_nt_headers(&nt_headers));

        // Read the section headers.
        let section_headers_offset = 4 + size_of::<FileHeader>() + (nt_headers.FileHeader.SizeOfOptionalHeader as usize);
        let num_sections = nt_headers.FileHeader.NumberOfSections as usize;

        // Validate that the number of bytes doesn't overflow.
        let sections_end = (dos_header.e_lfanew as usize)
            .checked_add(section_headers_offset)
            .and_then(|v| v.checked_add(num_sections * size_of::<SectionHeader>()));
        if sections_end.is_none() {
            return Err(PeError::IntegerOverflow("sections"));
        }

        Ok(PeFile{
            dos_header:  dos_header,
            nt_headers:  nt_headers,
            directories: TypeMap::custom(),
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

    // Reads the DOS header from the given file.
    fn get_dos_header<RS>(src: &mut RS) -> Result<DosHeader, PeError>
        where RS: io::Read + io::Seek
    {
        // Seek to the beginning.
        try!(src.seek(io::SeekFrom::Start(0)));

        // Create an appropriately-sized buffer.
        const BUF_SIZE: usize = 1024;
        let mut buf = Vec::new();
        buf.extend(std::iter::repeat(0).take(BUF_SIZE));

        // Read into the buffer, failing if any errors.
        try!(read_all(src, &mut buf[..]));

        // Parse the DOS header from the buffer.
        let dos_header = match parse_dos_header(&buf[..]) {
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

        Ok(dos_header)
    }

    // Reads the NT header from the given file.
    fn get_nt_headers<RS>(src: &mut RS, dos_header: &DosHeader) -> Result<NtHeaders, PeError>
        where RS: io::Read + io::Seek
    {
        let e_lfanew = dos_header.e_lfanew as usize;

        // Windows validates that, if the NT headers and at least 16 section
        // headers don't fit within the first page, that they must fit within
        // an additional 2 pages.  We aren't going to be quite so picky, for now.

        // Figure out how large the NT headers are, and check for integer overflow.
        let headers_size = e_lfanew
            .checked_add(size_of::<NtHeaders>())
            .and_then(|v| v.checked_add(16 * size_of::<SectionHeader>()));
        let headers_size = match headers_size {
            None => return Err(PeError::IntegerOverflow("headers")),
            Some(x) => {
                // TODO: windows does another check like so:
                //    if (e_lfanew + size_of::<NtHeaders>()) as u64 > file_size {
                //        return Err(PeError::InvalidNewOffset(dos_header.e_lfanew));
                //    }
                //
                // What does this protect against / should we do it?

                x
            },
        };

        // We allocate a two-page-large buffer and read into this.  It's
        // important that we do it this way (with a zero-initialized buffer),
        // since the Windows loader will accept files that end before the end
        // of the NT headers (which means the final fields are zero-filled).
        let mut buf = Vec::new();
        buf.extend(std::iter::repeat(0).take(8192));

        // Seek to the right offset ...
        try!(src.seek(io::SeekFrom::Start(e_lfanew as u64)));

        // ... and read.
        try!(read_all(src, &mut buf[..]));

        // Parse the NT headers from this buffer.
        let nt_headers = match parse_nt_headers(&buf[..]) {
            IResult::Done(_, header) => {
                info!("Parsed NT header");
                debug!("{:#?}", header);

                header
            }
            e => {
                error!("Could not parse NT header: {:?}", e);

                // TODO: stash error somewhere?
                return Err(PeError::InvalidNtHeaders);
            }
        };

        Ok(nt_headers)
    }

    // ----------------------------------------------------------------------

    /// Returns the parsed DOS header.
    pub fn dos_header(&self) -> &DosHeader {
        return &self.dos_header
    }

    /// Returns the parsed NT headers.
    pub fn nt_headers(&self) -> &NtHeaders {
        return &self.nt_headers
    }

    /// Returns or parses the data directory of the given type, or None if the
    /// data directory does not exist in the image.  Panics if called with a
    /// type that is not a data directory.
    pub fn data_directory<K>(&mut self) -> Option<&K::Value>
        where K: typemap::Key + Any + Debug,
              K::Value: typemap::DebugAny
    {
        let val = self.directories.get::<K>();
        if val.is_some() {
            return val;
        }

        // TODO: get and insert

        None
    }
}


#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs::File;
    use std::io;
    use std::path::Path;

    use super::*;
    use super::types::*;
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

        // TODO: check for specific error code?
        match PeFile::parse(&mut file) {
            Err(_) => {},
            e      => panic!("Invalid response: {:?}", e),
        };
    }

    #[test]
    fn test_image_directories() {
        let path = Path::new("test_binaries").join("x64").join("with-all-directories.exe");

        let mut file = match File::open(&path) {
            Err(why) => panic!("Couldn't open {}: {}", path.display(), Error::description(&why)),
            Ok(file) => file,
        };

        let mut pe = match PeFile::parse(&mut file) {
            Err(e) => panic!("error parsing: {:?}", e),
            Ok(pe) => pe,
        };

        // TODO: assert that these parse correctly too, as opposed to just typechecking
        assert!(pe.data_directory::<LoadConfigDirectoryKey>().is_none());
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
