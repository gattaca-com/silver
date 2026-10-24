import LeanBlsSimd.Portable.Fp.Powers
import LeanBlsSimd.Portable.Fp.Equality
import LeanBlsSimd.Proofs.G1Finite

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.Fp
set_option maxRecDepth 4096

private theorem mul_field_encoded [RuntimeFeatures] (x y : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.mul (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (Kzg.fpEncode (x*y)).l :=
  mul_encoded x y

private theorem square_field_encoded [RuntimeFeatures] (x : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.square (Kzg.fpEncode x).l = ok (Kzg.fpEncode (x*x)).l :=
  square_encoded x

private theorem eq_field_encoded (x y : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.Insts.CoreCmpPartialEqFp.eq (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (decide (x=y)) :=
  eq_encoded x y

theorem sqrt_refines [RuntimeFeatures] (x : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.sqrt (Kzg.fpEncode x).l =
      ok (if Kernel.sqrtCandidate x ^ (2 : Nat) = x then some (Kzg.fpEncode (Kernel.sqrtCandidate x)).l else none) := by
  simp only [portable.fp.Fp.sqrt,pow_p_minus_3_over_4_refines,bind_tc_ok,mul_field_encoded,
    square_field_encoded,eq_field_encoded]
  change (if decide (Kernel.sqrtCandidate x * Kernel.sqrtCandidate x = x) then
    ok (some (Kzg.fpEncode (Kernel.sqrtCandidate x)).l) else ok none) = _
  simp only [←sq,decide_eq_true_eq]
  split <;> rfl

theorem sqrt_eq_spec [RuntimeFeatures] (x : Bls.Fp) :
    portable.fp.Fp.sqrt (Kzg.fpEncode x).l = ok (match Bls.Fp.sqrt x with
      | .ok y => some (Kzg.fpEncode y).l
      | .error _ => none) := by
  rw [sqrt_refines,DecompressG1.sqrt_eq]
  generalize Kernel.sqrtCandidate x = root
  split_ifs with h1 h2
  · rfl
  · exact False.elim (h2 h1)
  · rename_i h2
    exact False.elim (h1 h2)
  · rfl

end LeanBlsSimd.Portable.Fp
