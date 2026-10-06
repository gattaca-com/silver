//! BLS12-381 Fp in radix 2^52 with R = 2^416. Generated from the modulus in
//! Python; every array is little-endian limbs.

pub const LIMBS: usize = 8;
pub const LIMB_BITS: u32 = 52;
pub const MASK52: u64 = (1 << LIMB_BITS) - 1;

pub const P: [u64; LIMBS] = [
    0xeffffffffaaab,
    0xfeb153ffffb9f,
    0x6b0f6241eabff,
    0x12bf6730d2a0f,
    0x764774b84f385,
    0x1ba7b6434bacd,
    0x1ea397fe69a4b,
    0x000000001a011,
];
/// `-p^-1 mod 2^52`.
pub const P_INV52: u64 = 0x3fffcfffcfffd;
/// Montgomery one.
pub const R_MOD_P: [u64; LIMBS] = [
    0x6480ea8e9b9af,
    0x65766c8fe444f,
    0x8b540fea96f7d,
    0x3b2ee82efd422,
    0xa6723e5f0ade5,
    0xff6eb6fdd4230,
    0xe06ef23c24a25,
    0x0000000014c8e,
];
/// Multiplying a plain value by this in Montgomery form yields its Montgomery
/// form.
pub const R2_MOD_P: [u64; LIMBS] = [
    0xa5bf4cb89af51,
    0x3afbba7ca31a2,
    0x2646160ec71f1,
    0xa84d710465903,
    0x3480a4a188311,
    0x98e5907ad91f5,
    0x2075d74507266,
    0x0000000008746,
];
/// Multiplying our Montgomery form (R = 2^416) by this yields blst's (R =
/// 2^384).
pub const TWO_POW_384_MOD_P: [u64; LIMBS] = [
    0x900000002fffd,
    0x0bc40c0002760,
    0x3c758baebf400,
    0x57455f4898575,
    0xd77ce58537052,
    0x071a97a256ec6,
    0xec3fa80e4935c,
    0x0000000015f65,
];
pub const ONE_PLAIN: [u64; LIMBS] = [1, 0, 0, 0, 0, 0, 0, 0];
