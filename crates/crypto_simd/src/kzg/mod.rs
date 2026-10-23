//! KZG cell operations of EIP-7594 (PeerDAS) over the BLS12-381 setup of
//! EIP-4844, following the executable Lean specification in
//! `ethereum/cryptography-specs`. Point decoding goes
//! through `crate::bls`, and `SimdCellExtender` computes cells with AVX-512
//! IFMA; every other curve and field operation is a blst call in `blst_ops`.
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
mod fft;
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
mod fr8;
#[cfg(target_arch = "x86_64")]
mod fr8_bytes;
#[cfg(target_arch = "x86_64")]
mod fr8_fft;
#[cfg(all(test, target_arch = "x86_64"))]
mod fr8_test_util;
mod setup;
mod simd_cell_extender;
#[cfg(test)]
mod simd_cell_extender_tests;
mod trusted_setup;
mod verify;

pub use cell_extender::CellExtender;
pub use simd_cell_extender::SimdCellExtender;
pub use verify::CellBatchVerifier;

pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
pub const FIELD_ELEMENTS_PER_CELL: usize = 64;
pub const CELLS_PER_EXT_BLOB: usize = 2 * FIELD_ELEMENTS_PER_BLOB / FIELD_ELEMENTS_PER_CELL;
pub const BYTES_PER_CELL: usize = FIELD_ELEMENTS_PER_CELL * BYTES_PER_FIELD_ELEMENT;
pub const BYTES_PER_BLOB: usize = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

#[cfg(all(test, feature = "spec_vectors"))]
mod spec_vectors;
#[cfg(test)]
mod tests;
