//! blst pairing for the scalar KZG route.

use blst::{
    blst_final_exp, blst_fp12, blst_fp12_is_one, blst_miller_loop_n, blst_p1, blst_p1_affine,
    blst_p1_affine_is_inf, blst_p1_to_affine, blst_p2_affine, blst_p2_affine_is_inf,
};

/// Two Jacobian G1 points paired with affine G2 points, including infinity.
pub(crate) fn pairing_check(
    p1: &blst_p1,
    q1: &blst_p2_affine,
    p2: &blst_p1,
    q2: &blst_p2_affine,
) -> bool {
    pairing_check_affine(&g1_to_affine(p1), q1, &g1_to_affine(p2), q2)
}

pub(crate) fn g1_to_affine(a: &blst_p1) -> blst_p1_affine {
    let mut out = blst_p1_affine::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_p1_to_affine(&mut out, a) };
    out
}

/// e(p1, q1)·e(p2, q2) = 1, skipping pairs with a point at infinity, as the
/// spec's `pairingCheck` does. blst 0.3.16's `blst_miller_loop_n` skips none.
pub(crate) fn pairing_check_affine(
    p1: &blst_p1_affine,
    q1: &blst_p2_affine,
    p2: &blst_p1_affine,
    q2: &blst_p2_affine,
) -> bool {
    let mut ps: [*const blst_p1_affine; 2] = [std::ptr::null(); 2];
    let mut qs: [*const blst_p2_affine; 2] = [std::ptr::null(); 2];
    let mut n = 0;
    for (p, q) in [(p1, q1), (p2, q2)] {
        // SAFETY: valid pointers to single values.
        if !unsafe { blst_p1_affine_is_inf(p) || blst_p2_affine_is_inf(q) } {
            ps[n] = p;
            qs[n] = q;
            n += 1;
        }
    }
    if n == 0 {
        return true;
    }
    let mut miller = blst_fp12::default();
    let mut result = blst_fp12::default();
    // SAFETY: the first `n` entries of `ps` and `qs` point at valid values.
    unsafe {
        blst_miller_loop_n(&mut miller, qs.as_ptr(), ps.as_ptr(), n);
        blst_final_exp(&mut result, &miller);
        blst_fp12_is_one(&result)
    }
}
