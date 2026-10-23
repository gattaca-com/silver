import LeanBlsSimd.Model.G2x8
import LeanBlsSimd.Proofs.Fp2x8

open EthLib.Cryptography.Bls

namespace LeanBlsSimd.Controls.LazyG2

private def reduce8With (finish : Bool) (x : Fp2x8) : Fp2x8 :=
  let x := x.normalise.cond_sub (Fp8.multiple_of_p 4)
  if finish then x.cond_sub (Fp8.multiple_of_p 2) else x

example : reduce8With true = G2x8.Offsets.new.reduced_from_8p := rfl

private def reductionInput : Fp2x8 := ⟨Fp8.multiple_of_p 6, Fp8.multiple_of_p 7⟩

example : val (reductionInput.c0.lane 0) < 8 * Fp.modulus ∧
    val (reductionInput.c1.lane 0) < 8 * Fp.modulus ∧
    SignedLimbs.Normalized (reductionInput.c0.lane 0) ∧
    SignedLimbs.Normalized (reductionInput.c1.lane 0) := by
  unfold SignedLimbs.Normalized
  decide +kernel

example : Fp8Inv ((reduce8With true reductionInput).c0.lane 0) ∧
    Fp8Inv ((reduce8With true reductionInput).c1.lane 0) := by
  constructor <;> constructor <;> decide +kernel

example : val ((reduce8With false reductionInput).c0.lane 0) = 2 * Fp.modulus ∧
    val ((reduce8With false reductionInput).c1.lane 0) = 3 * Fp.modulus := by
  decide +kernel

example : True := by
  fail_if_success
    have : val ((reduce8With false reductionInput).c1.lane 0) < 2 * Fp.modulus := by
      decide +kernel
  trivial

private def zero : Fp2x8 := ⟨Fp8.zero, Fp8.zero⟩
private def x3 : Fp2x8 := ⟨Fp8.multiple_of_p 5, Fp8.multiple_of_p 5⟩

example : Fp8Inv (zero.c0.lane 0) ∧ Fp8Inv (zero.c1.lane 0) ∧
    SignedLimbs.Normalized (x3.c0.lane 0) ∧ SignedLimbs.Normalized (x3.c1.lane 0) ∧
    val (x3.c0.lane 0) < 6 * Fp.modulus ∧ val (x3.c1.lane 0) < 6 * Fp.modulus := by
  refine ⟨⟨?_, ?_⟩, ⟨?_, ?_⟩, ?_, ?_, ?_, ?_⟩ <;>
    (try unfold SignedLimbs.Normalized) <;> decide +kernel

-- The double formula subtracts x3 before reducing it from its 6p bound.
example : 0 ≤ SignedLimbs.val ((zero.sub_raw x3 G2x8.Offsets.new.eight_p).c1.lane 0) ∧
    SignedLimbs.val ((zero.sub_raw x3 G2x8.Offsets.new.eight_p).c1.lane 0) <
      10 * (Fp.modulus : ℤ) := by decide +kernel

example : SignedLimbs.val ((zero.sub_raw x3 G2x8.Offsets.new.four_p).c1.lane 0) < 0 := by
  decide +kernel

example : True := by
  fail_if_success
    have : 0 ≤ SignedLimbs.val ((zero.sub_raw x3 G2x8.Offsets.new.four_p).c1.lane 0) := by
      decide +kernel
  trivial

end LeanBlsSimd.Controls.LazyG2
