use std::convert::From;
use std::error;
use std::fmt;
use std::io;

/// PeError represents an error that occured while loading a PE file.
#[derive(Debug)]
pub enum PeError {
    /// Reading from the underlying reader returned an error.
    IOError(io::Error),

    /// The PE file is too large.
    TooLarge(u64),

    /// The PE file is too small.
    TooSmall(u64),

    /// The DOS header is invalid.
    InvalidDosHeader(String),
    // TODO: convert the above to contain a nom::IResult or nom::Err?

    /// The `e_lfanew` field in the DOS header is invalid.
    InvalidNewOffset(i32),

    /// An integer overflow occured during parsing.
    IntegerOverflow(&'static str),
}


impl fmt::Display for PeError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(fmt.write_str(error::Error::description(self)));

        Ok(())
    }
}


impl error::Error for PeError {
    fn description(&self) -> &str {
        match *self {
            PeError::IOError(_)          => "The underlying reader returned an error",
            PeError::TooLarge(_)         => "The PE file is too large",
            PeError::TooSmall(_)         => "The PE file is too small",
            PeError::InvalidDosHeader(_) => "The DOS header is invalid",
            PeError::InvalidNewOffset(_) => "The e_lfanew value is invalid",
            PeError::IntegerOverflow(_)  => "An integer overflow occured during parsing",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            PeError::IOError(ref err) => Some(err as &error::Error),
            _                         => None,
        }
    }
}


// Allow creating a PeError from an io::Error - helpful in the try! macro
impl From<io::Error> for PeError {
    fn from(err: io::Error) -> Self {
        PeError::IOError(err)
    }
}
