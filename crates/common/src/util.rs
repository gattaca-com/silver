use rcgen::{CertifiedKey, Error as RcgenError, KeyPair};

use crate::Error;

pub fn create_self_signed_certificate(label: &str) -> Result<CertifiedKey<KeyPair>, RcgenError> {
    rcgen::generate_simple_self_signed(&[label.into()])
}

/// Encode a varint into `buf`. Returns the number of bytes written.
pub fn encode_varint(mut val: u64, buf: &mut [u8]) -> Result<usize, Error> {
    let mut i = 0;
    loop {
        if i >= buf.len() {
            return Err(Error::BufferTooSmall);
        }
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            buf[i] = byte;
            return Ok(i + 1);
        }
        buf[i] = byte | 0x80;
        i += 1;
    }
}

/// Decodes a varint from the buffer at the specified position. Returns the
/// decoded value and the buffer position after the varint.
pub fn decode_varint(data: &[u8], mut pos: usize) -> Result<(u64, usize), Error> {
    let mut val: u64 = 0;
    let mut shift = 0;
    loop {
        if pos >= data.len() {
            return Err(Error::BadDer);
        }
        let b = data[pos];
        pos += 1;
        val |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok((val, pos));
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::BadDer);
        }
    }
}
