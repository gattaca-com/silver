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
/// Set bits of z = 0xd201000000010000, the BLS12-381 curve parameter, high to
/// low.
pub const Z_BITS: [u32; 6] = [63, 62, 60, 57, 48, 16];
/// ψ maps x = x0 + x1·i to `PSI_X_MONT`·(x1 + x0·i): its multiplier
/// 1 / (1 + i)^((p - 1) / 3) is `PSI_X_MONT`·i. Montgomery form.
pub const PSI_X_MONT: [u64; LIMBS] = [
    0x18a5500cc654c,
    0x2e1c1e9482fe9,
    0xd5d532d24a460,
    0x023e982695377,
    0x36c99171ef509,
    0x19b0966cc23e1,
    0x44c5fb3cf7304,
    0x000000001227f,
];
/// ψ multiplies conj(y) by 1 / (1 + i)^((p - 1) / 2), Montgomery form, as
/// [c0, c1].
pub const PSI_Y_MONT: [[u64; LIMBS]; 2] = [
    [
        0x9c1a677c96161,
        0xf16c8708fcef3,
        0x94977d28093e6,
        0xa06b71c927307,
        0xb4fa740f70cc7,
        0x844ca7b844683,
        0x3f2d89b2709bb,
        0x000000000917d,
    ],
    [
        0x53e598836494a,
        0x0d44ccf702cac,
        0xd677e519e1819,
        0x7253f567ab707,
        0xc14d00a8de6bd,
        0x975b0e8b07449,
        0xdf760e4bf908f,
        0x0000000010e93,
    ],
];
/// Multiplying blst's Montgomery form (R = 2^384), loaded as plain limbs, by
/// this yields ours (R = 2^416).
pub const TWO_POW_448_MOD_P: [u64; LIMBS] = [
    0x7fde37dba9366,
    0x4e27525bc342b,
    0x1f5b1e9778489,
    0xb872b2b91b9dc,
    0xb206f497dfcaf,
    0x4137cc89a9b0b,
    0xd9d20d7e39959,
    0x000000000411c,
];
