use crate::{
    bls::simd_available,
    kzg::fr8::{Fr8Soa, LANES, LIMBS},
};

pub fn available() -> bool {
    let ok = simd_available();
    assert!(
        ok || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
        "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma, or no simd feature"
    );
    ok
}

pub fn lanes(soa: &Fr8Soa) -> [[u64; LIMBS]; LANES] {
    let mut out = [[0; LIMBS]; LANES];
    for lane in 0..LANES {
        for j in 0..LIMBS {
            out[lane][j] = soa.0[j][lane];
        }
    }
    out
}
