//! KZG cell operations of EIP-7594 (PeerDAS) over the BLS12-381 setup of
//! EIP-4844, following the executable Lean specification in
//! `ethereum/EthLib`. Point decoding goes
//! through `crate::bls`; every other curve and field operation is a blst
//! call in `blst_ops`.
#![allow(
    clippy::needless_range_loop,
    clippy::vec_resize_to_zero,
    clippy::manual_is_multiple_of,
    reason = "Aeneas translates index loops, `Vec::resize` and `%` into Lean, but not iterator \
              adaptors, `Vec::clear` or `is_multiple_of`"
)]

mod blst_ops;
mod cell_extender;
mod challenge;
mod cosets;
mod domain;
#[cfg(target_arch = "x86_64")]
mod extension_kernel;
mod fft;
#[cfg(target_arch = "x86_64")]
mod fft8;
mod fr;
#[cfg(target_arch = "x86_64")]
mod fr8;
#[cfg(target_arch = "x86_64")]
mod interpolation_kernel;
#[cfg(all(test, target_arch = "x86_64"))]
#[rustfmt::skip]
mod pairing_lines;
mod setup;
mod trusted_setup;
mod verify;

use blst::blst_fr;
pub use cell_extender::CellExtender;
pub use verify::CellBatchVerifier;

pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
pub const FIELD_ELEMENTS_PER_CELL: usize = 64;
pub const CELLS_PER_EXT_BLOB: usize = 2 * FIELD_ELEMENTS_PER_BLOB / FIELD_ELEMENTS_PER_CELL;
pub const BYTES_PER_CELL: usize = FIELD_ELEMENTS_PER_CELL * BYTES_PER_FIELD_ELEMENT;
pub const BYTES_PER_BLOB: usize = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

// Fr literals in blst's Montgomery form, a·2^256 mod r, little-endian words.
pub(crate) const FR_ZERO: blst_fr = blst_fr { l: [0; 4] };
pub(crate) const FR_ONE: blst_fr =
    blst_fr { l: [0x00000001fffffffe, 0x5884b7fa00034802, 0x998c4fefecbc4ff5, 0x1824b159acc5056f] };
/// The spec's `PRIMITIVE_ROOT_OF_UNITY`, 7.
pub(crate) const PRIMITIVE_ROOT_OF_UNITY: blst_fr =
    blst_fr { l: [0x0000000efffffff1, 0x17e363d300189c0f, 0xff9c57876f8457b0, 0x351332208fc5a8c4] };
/// 1/64, whose form is 2^256 / 2^6 = 2^250, below r.
pub(crate) const INVERSE_CELL_SIZE: blst_fr = blst_fr { l: [0, 0, 0, 0x0400_0000_0000_0000] };
/// 1/4096, whose form is 2^256 / 2^12 = 2^244, below r.
pub(crate) const INVERSE_BLOB_SIZE: blst_fr = blst_fr { l: [0, 0, 0, 0x0010_0000_0000_0000] };

#[cfg(all(test, target_arch = "x86_64"))]
mod kernel_tests;
#[cfg(all(test, feature = "spec_vectors"))]
mod spec_vectors;
#[cfg(test)]
mod tests;
