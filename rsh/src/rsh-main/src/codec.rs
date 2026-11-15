use std::io;

pub fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new(tag: u8) -> Self {
        Writer { buf: vec![tag] }
    }

    pub fn u64(mut self, value: u64) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn bytes(mut self, value: &[u8]) -> Self {
        self.buf
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(value);
        self
    }

    pub fn str(self, value: &str) -> Self {
        self.bytes(value.as_bytes())
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.data.len())
            .ok_or_else(|| invalid("truncated message"))?;
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u64(&mut self) -> io::Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let len = self.take(4)?;
        let len = u32::from_be_bytes(len.try_into().unwrap()) as usize;
        Ok(self.take(len)?.to_vec())
    }

    pub fn string(&mut self) -> io::Result<String> {
        String::from_utf8(self.bytes()?).map_err(|_| invalid("bad utf-8 in message"))
    }

    pub fn end(&self) -> io::Result<()> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(invalid("trailing bytes in message"))
        }
    }
}
