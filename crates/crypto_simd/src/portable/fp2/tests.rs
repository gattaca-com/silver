use blst::{blst_fp, blst_fp2, blst_fp2_mul};

use super::Fp2;
#[cfg(target_arch = "x86_64")]
use crate::bmi2_available;
use crate::portable::fp::{Fp, tests::inputs};

fn blst(a: &Fp2) -> blst_fp2 {
    blst_fp2 { fp: [blst_fp { l: a.c0.0 }, blst_fp { l: a.c1.0 }] }
}

/// Consecutive inputs, so that 0, 1 and p − 1 meet as components, and equal
/// components, whose products cancel in c0.
fn elements() -> Vec<Fp2> {
    let values = inputs();
    let mut elements = Vec::new();
    for k in 0..values.len() - 1 {
        elements.push(Fp2 { c0: values[k], c1: values[k + 1] });
        elements.push(Fp2 { c0: values[k], c1: values[k] });
    }
    elements
}

#[test]
fn products_match_blst() {
    let elements = elements();
    for a in &elements {
        for b in &elements {
            let mut product = blst_fp2::default();
            // SAFETY: valid pointers to single values.
            unsafe { blst_fp2_mul(&mut product, &blst(a), &blst(b)) };
            let expected = Fp2 { c0: Fp(product.fp[0].l), c1: Fp(product.fp[1].l) };
            assert_eq!(a.mul(b), expected, "{a:?} · {b:?}");
        }
    }
}

/// As `Fp`'s twins.
#[cfg(target_arch = "x86_64")]
#[test]
fn product_twins_agree() {
    if !bmi2_available() {
        return;
    }
    let elements = elements();
    for a in &elements {
        for b in &elements {
            // SAFETY: `bmi2_available` checked BMI2 on this CPU.
            let on_bmi2 = unsafe { a.mul_on_bmi2(b) };
            assert_eq!(on_bmi2, a.mul_on_baseline(b), "{a:?} · {b:?}");
        }
    }
}
