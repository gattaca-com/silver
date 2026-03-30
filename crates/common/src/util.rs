use rcgen::{CertifiedKey, Error as RcgenError, KeyPair};

use crate::Error;

pub fn create_self_signed_certificate(label: &str) -> Result<CertifiedKey<KeyPair>, RcgenError> {
    rcgen::generate_simple_self_signed(&[label.into()])
}

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
