use std::io::{self, Read, Write};

use crate::codec::invalid;

const MAX_FRAME: usize = 64 * 1024 * 1024;

pub fn write_frame(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_FRAME {
        return Err(invalid("packet too large"));
    }
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(data)?;
    w.flush()
}

pub fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(invalid("bad packet length"));
    }
    let mut data = vec![0u8; len];
    r.read_exact(&mut data)?;
    Ok(data)
}
