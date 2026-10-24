import LeanBlsSimd.LaneTower.Recombine

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

def productValues (a b : P F) : P F :=
  productRecombine (unpack9 (fun j l => pack9 (productInputs a) j l * pack9 (productInputs b) j l))

theorem mul_raw {x y : fp2x8.Fp2x8} {a b : P F}
    (hx : Normal2 (fun _ => 256, fun _ => 256) x a)
    (hy : Normal2 (fun _ => 256, fun _ => 256) y b) :
    ∃ out, fp12.Fp12.mul x y = ok out ∧
      Normal2 (fun _ => 108, fun _ => 108) out (productValues a b) := by
  obtain ⟨left, hleft, rleft⟩ := product_operands hx (by decide)
  obtain ⟨right, hright, rright⟩ := product_operands hy (by decide)
  obtain ⟨z, hz, _⟩ := raw_zero
  obtain ⟨q, hq, rq⟩ := product_loop_start rleft rright (by decide) (Array.repeat 7#usize z)
  obtain ⟨out, hout, rout⟩ := from_product_lanes rq
  refine ⟨out, ?_, rout⟩
  simp only [fp12.Fp12.mul, hleft, hright, hz, mul_loop_eq, hq, hout, bind_tc_ok]

/-- The six active lanes are ordered by cubic coordinate within each quadratic half. -/
def value (a : P F) : Bls.Fp12 :=
  ⟨⟨⟨a.1 0, a.2 0⟩, ⟨a.1 1, a.2 1⟩, ⟨a.1 2, a.2 2⟩⟩,
   ⟨⟨a.1 3, a.2 3⟩, ⟨a.1 4, a.2 4⟩, ⟨a.1 5, a.2 5⟩⟩⟩

end LeanBlsSimd.LaneTower
