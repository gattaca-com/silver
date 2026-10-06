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
pub const P_U64: [u64; 6] = [
    0xb9feffffffffaaab,
    0x1eabfffeb153ffff,
    0x6730d2a0f6b0f624,
    0x64774b84f38512bf,
    0x4b1ba7b6434bacd7,
    0x1a0111ea397fe69a,
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
/// Curve coefficient b = 4, Montgomery form.
pub const FOUR_MONT: [u64; LIMBS] = [
    0xc203aa3a7e6bb,
    0x99c5b63f91e5d,
    0xec2218e49b9f5,
    0xb47d6b297d25b,
    0x36f29b533dd05,
    0xaac3b92d6d85a,
    0x25d100f5559b6,
    0x0000000005208,
];
/// `(p - 1) / 2`, plain: y above it is the lexicographically larger root.
pub const HALF_P_MINUS_1: [u64; LIMBS] = [
    0xf7fffffffd555,
    0xff58a9ffffdcf,
    0xb587b120f55ff,
    0x895fb39869507,
    0xbb23ba5c279c2,
    0x8dd3db21a5d66,
    0x8f51cbff34d25,
    0x000000000d008,
];
/// `(p - 3) / 4` as 4-bit windows, least significant first; 379 bits.
pub const P_MINUS_3_OVER_4_WINDOWS: [u8; 95] = [
    10, 10, 10, 14, 15, 15, 15, 15, 15, 15, 15, 11, 15, 7, 14, 14, 15, 15, 15, 15, 4, 5, 12, 10,
    15, 15, 15, 15, 10, 10, 7, 0, 9, 8, 13, 3, 12, 10, 13, 3, 8, 10, 4, 3, 12, 12, 9, 13, 15, 10,
    4, 4, 1, 14, 12, 3, 1, 14, 2, 13, 13, 1, 9, 13, 5, 3, 11, 14, 2, 13, 0, 9, 13, 14, 9, 14, 6,
    12, 2, 9, 6, 10, 9, 15, 15, 5, 14, 8, 10, 7, 4, 4, 0, 8, 6,
];
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
/// 1/2, Montgomery form.
pub const HALF_MONT: [u64; LIMBS] = [
    0xaa4075474b22d,
    0xb213e047f1ff7,
    0xfb31b91640dbe,
    0x26f727afe7f18,
    0x0e5cd98bad0b5,
    0x8d8b36a08fe7f,
    0xff89451d47238,
    0x000000001764f,
];
