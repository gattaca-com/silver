//! Building blocks of a multi-scalar multiplication on G1: affine points by
//! index, and their pairwise sums batched eight lanes at a time on `Fp8`.

pub mod pairs;
pub mod store;
#[cfg(test)]
mod tests;
