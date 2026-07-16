use std::borrow::Cow;

use crate::merkle::B256;

pub trait SszScalar: Copy + PartialEq + Default + 'static {
    const VALS_PER_CHUNK: usize = 32 / size_of::<Self>();

    fn as_ssz_bytes(vals: &[Self]) -> Cow<'_, [u8]> {
        #[cfg(target_endian = "little")]
        let bytes = Cow::Borrowed(unsafe {
            std::slice::from_raw_parts(vals.as_ptr().cast::<u8>(), std::mem::size_of_val(vals))
        });
        #[cfg(target_endian = "big")]
        let bytes = {
            let mut out = Vec::with_capacity(std::mem::size_of_val(vals));
            Self::write_ssz_slice(vals, &mut out).expect("Vec write is infallible");
            Cow::Owned(out)
        };
        bytes
    }

    /// Decode `dst.len()` values from the little-endian SSZ byte range.
    fn read_ssz_slice(dst: &mut [Self], src: &[u8]);

    fn write_ssz_slice<W: std::io::Write>(data: &[Self], w: &mut W) -> std::io::Result<()>;

    /// SSZ-pack one chunk's `VALS_PER_CHUNK` values into its 32-byte leaf.
    #[inline]
    fn pack_leaf(vals: &[Self]) -> B256 {
        debug_assert_eq!(vals.len(), Self::VALS_PER_CHUNK);
        let mut leaf = [0u8; 32];
        let mut w: &mut [u8] = &mut leaf;
        Self::write_ssz_slice(vals, &mut w).expect("leaf holds exactly one chunk");
        leaf
    }

    #[inline]
    fn lane(group: &B256, lane: usize) -> Self {
        let sz = size_of::<Self>();
        let mut out = [Self::default()];
        Self::read_ssz_slice(&mut out, &group[lane * sz..lane * sz + sz]);
        out[0]
    }

    #[inline]
    fn set_lane(group: &mut B256, lane: usize, v: Self) {
        let sz = size_of::<Self>();
        let mut w: &mut [u8] = &mut group[lane * sz..lane * sz + sz];
        Self::write_ssz_slice(&[v], &mut w).expect("lane fits its chunk");
    }
}

impl SszScalar for u8 {
    #[inline]
    fn read_ssz_slice(dst: &mut [Self], src: &[u8]) {
        dst.copy_from_slice(src);
    }

    #[inline]
    fn write_ssz_slice<W: std::io::Write>(data: &[Self], w: &mut W) -> std::io::Result<()> {
        w.write_all(data)
    }
}

impl SszScalar for u64 {
    #[inline]
    fn read_ssz_slice(dst: &mut [Self], src: &[u8]) {
        for (i, slot) in dst.iter_mut().enumerate() {
            *slot = u64::from_le_bytes(src[i * 8..i * 8 + 8].try_into().expect("8-byte window"));
        }
    }

    #[inline]
    fn write_ssz_slice<W: std::io::Write>(data: &[Self], w: &mut W) -> std::io::Result<()> {
        for v in data {
            w.write_all(&v.to_le_bytes())?;
        }
        Ok(())
    }
}
