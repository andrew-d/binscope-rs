use std::io::{self, SeekFrom};

/// Return the size of the given seeker, or any error that occured.
pub fn size_from_seeker<S: io::Seek>(s: &mut S) -> io::Result<u64> {
    let orig_pos = try!(s.seek(SeekFrom::Current(0)));

    let end_pos = try!(s.seek(SeekFrom::End(0)));

    try!(s.seek(SeekFrom::Start(orig_pos)));

    Ok(end_pos)
}

/// Try reading enough bytes from the given reader to fill the input buffer,
/// returning any error or number of bytes read.
pub fn read_all<R: io::Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut len = 0;

    loop {
        match r.read(&mut buf[len..]) {
            Ok(0) => return Ok(len),
            Ok(n) => len += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {},
            Err(e) => return Err(e),
        }
    }
}


#[cfg(test)]
mod tests {
    use std::io;
    use super::*;

    #[test]
    fn test_size_from_seeker() {
        let buf: &[u8] = b"this is some text123";
        let mut cur = io::Cursor::new(buf);

        assert_eq!(20, size_from_seeker(&mut cur).unwrap());
        assert_eq!(20, size_from_seeker(&mut cur).unwrap());
    }

    #[test]
    fn test_read_all() {
        let mut r = SlowReader::new(b"foobar");
        let mut outbuf: [u8; 10] = [0; 10];

        match read_all(&mut r, &mut outbuf[..]) {
            Ok(n)  => assert_eq!(6, n),
            Err(e) => panic!("unexpected error {:?}", e),
        };
    }


    struct SlowReader<'a> {
        buf: &'a [u8],
        offset: usize,
    }

    impl<'a> SlowReader<'a> {
        pub fn new(buf: &[u8]) -> SlowReader {
            SlowReader {
                buf: buf,
                offset: 0,
            }
        }
    }

    impl<'a> io::Read for SlowReader<'a> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.offset >= self.buf.len() {
                return Ok(0);
            }

            buf[0] = self.buf[self.offset];
            self.offset += 1;
            Ok(1)
        }
    }
}
