import LeanBlsSimd.Model.G1x8
import LeanBlsSimd.Proofs.Fp8
import LeanBlsSimd.Proofs.SignedLimbs

open EthLib.Cryptography.Bls

namespace LeanBlsSimd.Controls.LazyFp8

private def reduce8With (finish : Bool) (x : Fp8) : Fp8 :=
  let x := x.normalise.cond_sub (Fp8.multiple_of_p 4)
  if finish then x.cond_sub (Fp8.multiple_of_p 2) else x

example : reduce8With true = G1x8.Offsets.new.reduced_from_8p := rfl

private def sixP : Fp8 := Fp8.multiple_of_p 6

example : SignedLimbs.Normalized (sixP.lane 0) ∧
    val (sixP.lane 0) < 8 * Fp.modulus := by
  unfold SignedLimbs.Normalized
  decide +kernel

example : val ((reduce8With true sixP).lane 0) < 2 * Fp.modulus := by decide +kernel

-- Omitting the final subtraction preserves the residue but leaves a nonreduced coordinate.
example : val ((reduce8With false sixP).lane 0) = 2 * Fp.modulus ∧
    val ((reduce8With false sixP).lane 0) % Fp.modulus =
      val ((reduce8With true sixP).lane 0) % Fp.modulus := by decide +kernel

example : True := by
  fail_if_success
    have : val ((reduce8With false sixP).lane 0) < 2 * Fp.modulus := by decide +kernel
  trivial

-- The double formula's difference needs 8p: 4p cannot offset a value near 6p.
example : 0 ≤ SignedLimbs.val ((Fp8.zero.sub_raw sixP (Fp8.multiple_of_p 8)).lane 0) ∧
    SignedLimbs.val ((Fp8.zero.sub_raw sixP (Fp8.multiple_of_p 8)).lane 0) <
      10 * (Fp.modulus : ℤ) := by decide +kernel

example : SignedLimbs.val ((Fp8.zero.sub_raw sixP (Fp8.multiple_of_p 4)).lane 0) < 0 := by
  decide +kernel

example : True := by
  fail_if_success
    have : 0 ≤ SignedLimbs.val ((Fp8.zero.sub_raw sixP (Fp8.multiple_of_p 4)).lane 0) := by
      decide +kernel
  trivial

private def maxReduced : Fp8 := Fp8.splat_limbs (.ofList (limbs52 (2 * Fp.modulus - 1)))
private def triple : Fp8 := (maxReduced.add_raw maxReduced).add_raw maxReduced

example : Fp8Inv (maxReduced.lane 0) := by constructor <;> decide +kernel

example : SignedLimbs.val (triple.lane 0) < 6 * (Fp.modulus : ℤ) ∧
    ¬ SignedLimbs.val (triple.lane 0) < 4 * (Fp.modulus : ℤ) := by decide +kernel

example : True := by
  fail_if_success
    have : SignedLimbs.val (triple.lane 0) < 4 * (Fp.modulus : ℤ) := by decide +kernel
  trivial

private def halfRadix : Limbs := .ofList (limbs52 (R / 2))

-- Normalized operands alone do not imply a reduced Montgomery product.
example : SignedLimbs.Normalized halfRadix ∧
    ¬ val halfRadix * val halfRadix < R * Fp.modulus ∧
    ¬ val (Lane.mul halfRadix halfRadix) < 2 * Fp.modulus := by
  unfold SignedLimbs.Normalized
  decide +kernel

private def negativeTopCarry : Vector UInt64 8 :=
  #v[0, 0, 0, 0, 0, 0, UInt64.ofNat (2 ^ 64 - 1), 1]

example : SignedLimbs.val (SignedLimbs.normalise negativeTopCarry) =
      SignedLimbs.val negativeTopCarry ∧
    SignedLimbs.Normalized (SignedLimbs.normalise negativeTopCarry) :=
  SignedLimbs.normalise_eight_spec (by decide +kernel) (by decide +kernel) (by decide +kernel)

end LeanBlsSimd.Controls.LazyFp8
