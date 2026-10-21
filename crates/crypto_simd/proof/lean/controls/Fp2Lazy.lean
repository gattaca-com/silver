import LeanBlsSimd.Proofs.Fp2x8

open EthCryptographySpecs.Bls

namespace LeanBlsSimd.Controls.LazyFp2

private def squareWith (offset : UInt64) (twice : Bool) (x : Fp2x8) : Fp2x8 :=
  let sum := (x.c0.add_raw x.c1).normalise
  let difference := (x.c0.sub_raw x.c1 (Fp8.multiple_of_p offset)).normalise
  let imag := if twice then (x.c1.add_raw x.c1).normalise else x.c1
  ⟨sum.mul difference, x.c0.mul imag⟩

example : squareWith 8 true = Fp2x8.square := rfl

example {x y : Fp2x8} {l : Fin 8} {v w : Fp2Field}
    (hx : Fp2x8.BoundRep 16 x l v) (hy : Fp2x8.BoundRep 16 y l w) :
    (x.mul y).Holds l (v * w) := hx.mul hy (by decide) (by decide)

example {x : Fp2x8} {l : Fin 8} {v : Fp2Field} (hx : Fp2x8.BoundRep 8 x l v) :
    x.square.Holds l (v ^ 2) := hx.square (by decide)

private def inputEdge : Fp8 := Fp8.splat_limbs (.ofList (limbs52 (16 * Fp.modulus - 1)))

example : SignedLimbs.Normalized (inputEdge.lane 0) ∧
    val (inputEdge.lane 0) < 16 * Fp.modulus := by
  unfold SignedLimbs.Normalized
  decide +kernel

example : SignedLimbs.Normalized ((inputEdge.add_raw inputEdge).normalise.lane 0) ∧
    val ((inputEdge.add_raw inputEdge).normalise.lane 0) < 32 * Fp.modulus := by
  unfold SignedLimbs.Normalized
  decide +kernel

example : ¬ SignedLimbs.Normalized ((inputEdge.add_raw inputEdge).lane 0) := by
  unfold SignedLimbs.Normalized
  decide +kernel

private def squareEdge : Fp2x8 := ⟨Fp8.zero, Fp8.multiple_of_p 7⟩

example : SignedLimbs.Normalized (squareEdge.c0.lane 0) ∧
    SignedLimbs.Normalized (squareEdge.c1.lane 0) ∧
    val (squareEdge.c0.lane 0) < 8 * Fp.modulus ∧
    val (squareEdge.c1.lane 0) < 8 * Fp.modulus := by
  unfold SignedLimbs.Normalized
  decide +kernel

example : 0 ≤ SignedLimbs.val
    ((squareEdge.c0.sub_raw squareEdge.c1 (Fp8.multiple_of_p 8)).lane 0) ∧
    SignedLimbs.val
      ((squareEdge.c0.sub_raw squareEdge.c1 (Fp8.multiple_of_p 8)).lane 0) <
      16 * (Fp.modulus : ℤ) := by decide +kernel

example : SignedLimbs.val
    ((squareEdge.c0.sub_raw squareEdge.c1 (Fp8.multiple_of_p 2)).lane 0) < 0 := by
  decide +kernel

example : True := by
  fail_if_success
    have : 0 ≤ SignedLimbs.val
        ((squareEdge.c0.sub_raw squareEdge.c1 (Fp8.multiple_of_p 2)).lane 0) := by
      decide +kernel
  trivial

private def onePlusI : Fp2x8 := ⟨Fp8.one, Fp8.one⟩
private def unitPair : Fp2Field := ⟨1, 1⟩

private theorem onePlusI_holds : onePlusI.Holds 0 unitPair :=
  ⟨Fp8.holds_one 0, Fp8.holds_one 0⟩

example : (squareWith 8 true onePlusI).Holds 0 (unitPair ^ 2) := onePlusI_holds.square

example : ¬ (squareWith 8 false onePlusI).Holds 0 (unitPair ^ 2) := by
  intro h
  have hi : (squareWith 8 false onePlusI).c1.Holds 0 (1 * 1) :=
    (Fp8.holds_one 0).mul (Fp8.holds_one 0)
  have he := hi.eq.symm.trans h.im.eq
  norm_num [unitPair, sq, QuadraticAlgebra.im_mul] at he
  exact (by decide +kernel : (1 : ZMod Fp.modulus) ≠ 2) he

end LeanBlsSimd.Controls.LazyFp2
