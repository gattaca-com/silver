//! Pairing.lean, transcribed with blst's Fp12 arithmetic: the oracle the
//! pairing on lanes is tested against.
#![cfg_attr(
    not(target_arch = "x86_64"),
    allow(dead_code, reason = "off x86-64, only the pairing lines' test uses this oracle")
)]

use blst::{
    blst_fp, blst_fp_from_uint64, blst_fp_sub, blst_fp2, blst_fp6, blst_fp12, blst_fp12_conjugate,
    blst_fp12_inverse, blst_fp12_mul, blst_p1_affine_is_inf, blst_p2_affine_is_inf,
};

use crate::bls::{blst_p1_affine, blst_p2_affine};

/// The BLS parameter is x = −`X_ABS`.
const X_ABS: u64 = 0xd201_0000_0001_0000;

/// `finalExpExponent`, (p¹² − 1)/r, in hex.
const FINAL_EXPONENT: &str = concat!(
    "2ee1db5dcc825b7e1bda9c0496a1c0a89ee0193d4977b3f7d4507d07363baa13f8d14a917848517badc3a43d",
    "1073776ab353f2c30698e8cc7deada9c0aadff5e9cfee9a074e43b9a660835cc872ee83ff3a0f0f1c0ad0d61",
    "06feaf4e347aa68ad49466fa927e7bb9375331807a0dce2630d9aa4b113f414386b0e8819328148978e2b0dd",
    "39099b86e1ab656d2670d93e4d7acdd350da5359bc73ab61a0c5bf24c374693c49f570bcd2b01f3077ffb10b",
    "f24dde41064837f27611212596bc293c8d4c01f25118790f4684d0b9c40a68eb74bb22a40ee7169cdc104129",
    "6532fef459f12438dfc8e2886ef965e61a474c5c85b0129127a1b5ad0463434724538411d1676a53b5a62eb3",
    "4c05739334f46c02c3f0bd0c55d3109cd15948d0a1fad20044ce6ad4c6bec3ec03ef19592004cedd556952c6",
    "d8823b19dadd7c2498345c6e5308f1c511291097db60b1749bf9b71a9f9e0100418a3ef0bc627751bbd81367",
    "066bca6a4c1b6dcfc5cceb73fc56947a403577dfa9e13c24ea820b09c1d9f7c31759c3635de3f7a363999170",
    "8e88adce88177456c49637fd7961be1a4c7e79fb02faa732e2f3ec2bea83d196283313492caa9d4aff1c910e",
    "9622d2a73f62537f2701aaef6539314043f7bbce5b78c7869aeb2181a67e49eeed2161daf3f881bd88592d76",
    "7f67c4717489119226c2f011d4cab803e9d71650a6f80698e2f8491d12191a04406fbc8fbd5f48925f98630e",
    "68bfb24c0bcb9b55df57510",
);

/// `Embedded.Point`, away from infinity.
#[derive(Clone, Copy)]
pub(crate) struct Point {
    x: blst_fp12,
    y: blst_fp12,
}

/// The integer `n` in blst's Montgomery form.
pub(crate) fn fp(n: u64) -> blst_fp {
    let mut out = blst_fp::default();
    // SAFETY: blst reads six words from a valid array.
    unsafe { blst_fp_from_uint64(&mut out, [n, 0, 0, 0, 0, 0].as_ptr()) };
    out
}

/// blst's `Default` for Fp12 is 1; its Fp2 default is 0.
pub(crate) fn zero() -> blst_fp12 {
    blst_fp12 { fp6: [blst_fp6 { fp2: [blst_fp2::default(); 3] }; 2] }
}

fn of_fp(a: &blst_fp) -> blst_fp12 {
    let mut f = zero();
    f.fp6[0].fp2[0].fp[0] = *a;
    f
}

pub(crate) fn one() -> blst_fp12 {
    of_fp(&fp(1))
}

pub(crate) fn mul(a: &blst_fp12, b: &blst_fp12) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fp12_mul(&mut out, a, b) };
    out
}

pub(crate) fn inverse(a: &blst_fp12) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fp12_inverse(&mut out, a) };
    out
}

/// Coefficient by coefficient, since blst has no Fp12 subtraction.
fn sub(a: &blst_fp12, b: &blst_fp12) -> blst_fp12 {
    let mut out = blst_fp12::default();
    for h in 0..2 {
        for k in 0..3 {
            for c in 0..2 {
                let (a, b) = (&a.fp6[h].fp2[k].fp[c], &b.fp6[h].fp2[k].fp[c]);
                // SAFETY: valid pointers to single values.
                unsafe { blst_fp_sub(&mut out.fp6[h].fp2[k].fp[c], a, b) };
            }
        }
    }
    out
}

/// `Embedded.ofG1`.
pub(crate) fn of_g1(p: &blst_p1_affine) -> Point {
    Point { x: of_fp(&p.x), y: of_fp(&p.y) }
}

/// `Embedded.ofG2`: (X/w², Y/w³), with w⁻² = v⁻¹ and w⁻³ = (v²)⁻¹·w.
pub(crate) fn of_g2(q: &blst_p2_affine) -> Point {
    let mut v = zero();
    v.fp6[0].fp2[1].fp[0] = fp(1);
    let w_inv2 = inverse(&v);
    let mut w_inv3 = zero();
    w_inv3.fp6[1] = inverse(&mul(&v, &v)).fp6[0];
    let mut x = zero();
    x.fp6[0].fp2[0] = q.x;
    let mut y = zero();
    y.fp6[0].fp2[0] = q.y;
    Point { x: mul(&x, &w_inv2), y: mul(&y, &w_inv3) }
}

/// `Line.evalAt`: (yp − Ry) − slope·(xp − Rx).
fn eval_at(r: &Point, slope: &blst_fp12, p: &Point) -> blst_fp12 {
    sub(&sub(&p.y, &r.y), &mul(slope, &sub(&p.x, &r.x)))
}

/// `millerDouble`'s point and line, with `Line.tangentSlope`.
fn double(t: &Point, p: &Point) -> (Point, blst_fp12) {
    let (three, two) = (of_fp(&fp(3)), of_fp(&fp(2)));
    let m = mul(&mul(&mul(&three, &t.x), &t.x), &inverse(&mul(&two, &t.y)));
    let x = sub(&sub(&mul(&m, &m), &t.x), &t.x);
    let y = sub(&mul(&m, &sub(&t.x, &x)), &t.y);
    (Point { x, y }, eval_at(t, &m, p))
}

/// `millerAdd`'s point and line, with `Line.addSlope`.
fn add(t: &Point, r0: &Point, p: &Point) -> (Point, blst_fp12) {
    let m = mul(&sub(&r0.y, &t.y), &inverse(&sub(&r0.x, &t.x)));
    let x = sub(&sub(&mul(&m, &m), &t.x), &r0.x);
    let y = sub(&mul(&m, &sub(&t.x, &x)), &t.y);
    (Point { x, y }, eval_at(t, &m, p))
}

/// The lines `millerLoop X_ABS r0 p` multiplies in, in order, each with
/// whether its step doubles, and so squares f first.
fn miller_steps(r0: &Point, p: &Point) -> Vec<(bool, blst_fp12)> {
    let mut steps = Vec::new();
    let mut t = *r0;
    for bit in (0..u64::BITS - X_ABS.leading_zeros() - 1).rev() {
        let (doubled, line) = double(&t, p);
        steps.push((true, line));
        t = doubled;
        if X_ABS >> bit & 1 == 1 {
            let (sum, line) = add(&t, r0, p);
            steps.push((false, line));
            t = sum;
        }
    }
    steps
}

/// The lines `millerLoop X_ABS r0 p` multiplies in, in order.
pub(crate) fn miller_lines(r0: &Point, p: &Point) -> Vec<blst_fp12> {
    miller_steps(r0, p).into_iter().map(|(_, line)| line).collect()
}

/// `millerLoop X_ABS r0 p`.
pub(crate) fn miller_loop(r0: &Point, p: &Point) -> blst_fp12 {
    let mut f = one();
    for (doubles, line) in miller_steps(r0, p) {
        if doubles {
            f = mul(&f, &f);
        }
        f = mul(&f, &line);
    }
    f
}

pub(crate) fn conjugate(f: &blst_fp12) -> blst_fp12 {
    let mut out = *f;
    // SAFETY: a valid pointer to a single value.
    unsafe { blst_fp12_conjugate(&mut out) };
    out
}

/// `pairingCheck`'s accumulator before the final exponentiation: the
/// product of the pairs' conjugated Miller values, leaving out each pair
/// with a point at infinity.
pub(crate) fn pairing_product(pairs: &[(blst_p1_affine, blst_p2_affine)]) -> blst_fp12 {
    let mut acc = one();
    for (p, q) in pairs {
        // SAFETY: valid pointers to single values.
        if unsafe { blst_p1_affine_is_inf(p) || blst_p2_affine_is_inf(q) } {
            continue;
        }
        acc = mul(&acc, &conjugate(&miller_loop(&of_g2(q), &of_g1(p))));
    }
    acc
}

/// `finalExponentiation`: `Fp12.powNat f finalExpExponent`, over the
/// exponent's bits from the top.
pub(crate) fn final_exponentiation(f: &blst_fp12) -> blst_fp12 {
    let mut acc = one();
    for digit in FINAL_EXPONENT.chars() {
        let digit = digit.to_digit(16).expect("a hex digit");
        for bit in (0..4).rev() {
            acc = mul(&acc, &acc);
            if digit >> bit & 1 == 1 {
                acc = mul(&acc, f);
            }
        }
    }
    acc
}

/// `pairingCheck`.
pub(crate) fn pairing_check(pairs: &[(blst_p1_affine, blst_p2_affine)]) -> bool {
    final_exponentiation(&pairing_product(pairs)) == one()
}
