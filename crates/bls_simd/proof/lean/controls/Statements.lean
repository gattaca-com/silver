import LeanBlsSimd.Constants
import LeanBlsSimd.Spec.Fp2
import LeanBlsSimd.Spec.Scott
import LeanBlsSimd.Spec.Sqrt

/-! Negative controls for `LeanBlsSimd.Constants`, `LeanBlsSimd.Spec.Fp2`, `LeanBlsSimd.Spec.Scott`
and `LeanBlsSimd.Spec.Sqrt`. Each `fail_if_success` wraps a mutated claim or proof, which must
fail; each plain `example` must pass. -/

namespace LeanBlsSimd

open EthCryptographySpecs EthCryptographySpecs.Bls

-- A mutated proof stops at its first failing step, so the linter flags the steps after it.
set_option linter.unreachableTactic false

/-! ## Tables -/

example : True := by
  fail_if_success
    have : [0xeffffffffaaab, 0xfeb153ffffb9f, 0x6b0f6241eabff, 0x12bf6730d2a0f, 0x764774b84f385,
        0x1ba7b6434bacd, 0x1ea397fe69a4b, 0x000000001a012] = limbs52 Fp.modulus := by
      decide +kernel
  trivial

example : True := by
  fail_if_success have : R_MOD_P = limbs52 (toMont 2) := by decide +kernel
  trivial

example : True := by
  fail_if_success have : (Fp.modulus - 3) / 4 < 2 ^ (4 * 94) := by decide +kernel
  trivial

example : True := by
  fail_if_success have : (Fr.modulus : ℤ) = (z + 1) ^ 4 - (z + 1) ^ 2 + 1 := by decide +kernel
  trivial

/-! ## ψ witnesses -/

example : True := by
  fail_if_success have : powBy mulFp2 (1, 0) 381 (0, psiX + 1) 3 = (0, 1) := by decide +kernel
  trivial

example :
    mulFp2 (0, psiX + 1) (powBy mulFp2 (1, 0) 381 (1, 1) ((Fp.modulus - 1) / 3)) ≠ (1, 0) := by
  decide +kernel

/-! ## A cube in place of the non-cube 32, under the proof of its Euler fact -/

example : True := by
  fail_if_success
    have : (8 : ZMod Fp.modulus) ^ ((Fp.modulus - 1) / 3) ≠ 1 := by
      have h := (PowMod.natCast_pow_eq_one_iff Fp.modulus 381 8 ((Fp.modulus - 1) / 3)
        (by decide +kernel)).not.mpr (by decide +kernel)
      rwa [Nat.cast_ofNat] at h
  trivial

example : PowMod.powModAux 381 Fp.modulus 8 ((Fp.modulus - 1) / 3) = 1 % Fp.modulus := by
  decide +kernel

example : ¬∀ x : ZMod Fp.modulus, x ^ 3 ≠ 8 := fun h => h 2 (by norm_num)

/-! ## A square in place of the non-square −1 -/

example : True := by
  fail_if_success
    have : ∀ x : ZMod Fp.modulus, x ^ 2 ≠ 4 := fun x hx =>
      ZMod.exists_sq_eq_neg_one_iff.mp ⟨x, by rw [← hx, sq]⟩ p_mod_four
  trivial

/-! ## Fuel: (p − 1)/3 and (p − 1)/2 need 380 bits -/

example : True := by
  fail_if_success
    have : (32 : ZMod Fp.modulus) ^ ((Fp.modulus - 1) / 3) ≠ 1 := by
      have h := (PowMod.natCast_pow_eq_one_iff Fp.modulus 379 32 ((Fp.modulus - 1) / 3)
        (by decide +kernel)).not.mpr (by decide +kernel)
      rwa [Nat.cast_ofNat] at h
  trivial

example : (32 : ZMod Fp.modulus) ^ ((Fp.modulus - 1) / 3) ≠ 1 := by
  have h := (PowMod.natCast_pow_eq_one_iff Fp.modulus 380 32 ((Fp.modulus - 1) / 3)
    (by decide +kernel)).not.mpr (by decide +kernel)
  rwa [Nat.cast_ofNat] at h

example : mulFp2 psiY (powBy mulFp2 (1, 0) 379 (1, 1) ((Fp.modulus - 1) / 2)) ≠ (1, 0) := by
  decide +kernel

example : mulFp2 psiY (powBy mulFp2 (1, 0) 380 (1, 1) ((Fp.modulus - 1) / 2)) = (1, 0) := by
  decide +kernel

/-! ## The chain and its exceptions -/

example : True := by
  fail_if_success have : Step.run chainSteps 1 = blsX + 1 := by decide +kernel
  trivial

example : True := by
  fail_if_success
    have : [13, 23, 2713, 11953, 262069].map g2MeetsException =
        [false, false, false, false, false] := by
      decide +kernel
  trivial

/-! ## Fp2: the bridge into ω² = 1 in place of ω² = −1

The proof of `Fp2.toField`'s product, aimed at `QuadraticAlgebra … 1 0`, must fail at the real
part. i · i separates the two products. It uses `ring1`, which throws wherever it sits. A failing
`ring` leaves its goal open instead: directly under `fail_if_success` that counts as success, and
in a term-level `by` the goal is logged and admitted. -/

example : True := by
  fail_if_success
    have : ∀ x y : Fp2,
        (⟨(x * y).c0, (x * y).c1⟩ : QuadraticAlgebra (ZMod Fp.modulus) 1 0) =
          ⟨x.c0, x.c1⟩ * ⟨y.c0, y.c1⟩ := by
      intro x y
      have re (a b c d : ZMod Fp.modulus) : a * c - b * d = a * c + 1 * b * d := by ring1
      have im (a b c d : ZMod Fp.modulus) : a * d + b * c = a * d + b * c + 0 * b * d := by ring1
      exact QuadraticAlgebra.ext (re x.c0 x.c1 y.c0 y.c1) (im x.c0 x.c1 y.c0 y.c1)
  trivial

example :
    ((Fp2.i * Fp2.i).c0 : ZMod Fp.modulus) ≠
      (⟨0, 1⟩ * ⟨0, 1⟩ : QuadraticAlgebra (ZMod Fp.modulus) 1 0).re := by
  decide +kernel

/-! ## ψ's x multiplier without its factor i

`psiX` alone cubes to −1, not i. In its place the proof of `equation_psi` fails, and the spec's
generator maps off E′. -/

section

local notation "ω" => (QuadraticAlgebra.omega : Fp2Field)

example : True := by
  fail_if_success
    have : ∀ x y : Fp2Field, E'.Equation x y → E'.Equation (psiX * star x) (cy * star y) := by
      intro x y h
      rw [E'.equation_iff] at h ⊢
      have hs := congrArg star h
      rw [star_pow, star_add, star_pow] at hs
      linear_combination (norm := ring1)
        star y ^ 2 * cy_sq - star x ^ 3 * cx_cube + ω * hs + omega_mul_star_bTwist
  trivial

example :
    ¬∀ x y : Fp2Field, E'.Equation x y → E'.Equation (psiX * star x) (cy * star y) := by
  intro h
  have hG : E'.Equation (Fp2.toField G2.generator.x) (Fp2.toField G2.generator.y) := by
    rw [E'.equation_iff]
    decide +kernel
  have hψ := h _ _ hG
  rw [E'.equation_iff] at hψ
  revert hψ
  decide +kernel

example : E'.Equation (cx * star (Fp2.toField G2.generator.x))
    (cy * star (Fp2.toField G2.generator.y)) := by
  rw [E'.equation_iff]
  decide +kernel

end

/-! ## Soundness is blind to the sign of z

The proof of `scott_sound` goes through with −z in place of z, because only z² and z⁴ enter. So
`scott_sound` cannot detect a sign error in z; only a completeness check can, such as
`psi_generator`'s ψ(G) = [z]G. With z + 1 in place of z, the same proof fails at `ring1`. That
pins the proof step, not the statement, which holds for z + 1 because only O satisfies
ψ(P) = [z + 1]P. -/

example (P : E'.Point) (h : psi P = (-z) • P) : Fr.modulus • P = 0 := by
  rw [← natCast_zsmul, r_eq, show z ^ 4 - z ^ 2 + 1 = (-z) ^ 4 - (-z) ^ 2 + 1 by ring1]
  exact torsion_of_psi_eq_zsmul (-z) P h

example : True := by
  fail_if_success
    have : ∀ P : E'.Point, psi P = (z + 1) • P → Fr.modulus • P = 0 := by
      intro P h
      rw [← natCast_zsmul, r_eq, show z ^ 4 - z ^ 2 + 1 = (z + 1) ^ 4 - (z + 1) ^ 2 + 1 by ring1]
      exact torsion_of_psi_eq_zsmul (z + 1) P h
  trivial

/-! ## The spec's root: completeness without its −a₀ fallback

Where a₁ = 0, the root may be pure imaginary: a₀ = −d² is a square in Fp2 but not in Fp. The case
split of `Fp2.sqrt_complete`, asked for a root of a₀ in Fp alone, fails at c = 0. -/

example : True := by
  fail_if_success
    have : ∀ a0 c d : ZMod Fp.modulus, a0 = c * c - d * d → c * d = 0 → ∃ b, b * b = a0 := by
      intro a0 c d h0 hcd
      rcases mul_eq_zero.mp hcd with hc | hd
      · exact ⟨d, by rw [h0, hc]; ring1⟩
      · exact ⟨c, by rw [h0, hd]; ring1⟩
  trivial

example : IsSquare (-1 : Fp2Field) ∧ ¬IsSquare (-1 : ZMod Fp.modulus) :=
  ⟨⟨QuadraticAlgebra.omega, by rw [← sq, Fp2Field.omega_sq]⟩,
    fun ⟨r, hr⟩ => neg_one_not_square r (by rw [sq, ← hr])⟩

/-! ## The sign rule: the opposite convention

A test for the smaller root, aimed at `Fp.signBit` with the proof of `Kernel.isLargerRootFp_eq`,
fails at its `omega`; 1 separates the two. Zero has no sign, so `Fp2.signBit_neg` needs y ≠ 0. -/

example : True := by
  fail_if_success
    have : ∀ v : Fp, decide (v.val ≤ (Fp.modulus - 1) / 2) = Fp.signBit v := by
      intro v
      have hlt := v.isLt
      have hodd : Fp.modulus % 2 = 1 := by decide
      unfold Fp.signBit
      exact decide_eq_decide.mpr (by omega)
  trivial

example : Fp.signBit 1 = false ∧ decide ((1 : Fp).val ≤ (Fp.modulus - 1) / 2) = true := by
  decide +kernel

example : ¬∀ y : Fp2, Fp2.signBit (-y) = !Fp2.signBit y := fun h =>
  absurd (h Fp2.zero) (by decide +kernel)

/-! ## The kernel's root: one alignment in place of two

At x = −1, t = −1 and χ(−1) = −1, so the candidate squares to −x. The case split of
`Kernel.sqrt_snd_iff`, aimed at the candidate alone, fails where χ(t) = −1. -/

example : True := by
  fail_if_success
    have : ∀ x : Fp2Field, IsSquare x → Kernel.rootCandidate x ^ 2 = x := by
      intro x hx
      have hc := Kernel.rootCandidate_sq hx
      by_cases ht : Kernel.sqrtT x = 0
      · rw [hc, ht, quadraticChar_zero, Int.cast_zero, zero_mul,
          Kernel.eq_zero_of_sqrtT_eq_zero ht]
      · rcases quadraticChar_dichotomy ht with h1 | h1
        · rw [hc, h1, Int.cast_one, one_mul]
        · rw [hc, h1, Int.cast_neg, Int.cast_one, neg_one_mul]
  trivial

example : Kernel.sqrtT (-1) = -1 ∧ quadraticChar (ZMod Fp.modulus) (-1) = -1 ∧
    Kernel.rootCandidate (-1) = -1 := by
  have ht : Kernel.sqrtT (-1) = -1 := by
    have h : (half : ZMod Fp.modulus) * 2 = 1 := by decide +kernel
    simp only [Kernel.sqrtT, Kernel.sqrtCandidate, Kernel.powPMinus3Over4, Kernel.half,
      QuadraticAlgebra.re_neg, QuadraticAlgebra.im_neg, QuadraticAlgebra.re_one,
      QuadraticAlgebra.im_one]
    norm_num
    linear_combination h
  refine ⟨ht, quadraticChar_neg_one_iff_not_isSquare.mpr fun ⟨r, hr⟩ =>
    neg_one_not_square r (by rw [sq, ← hr]), ?_⟩
  have hr : Kernel.powPMinus3Over4 (-1) = 1 :=
    Even.neg_one_pow (Nat.even_iff.mpr (by decide +kernel))
  ext <;> simp [Kernel.rootCandidate, ht, hr, Kernel.half, QuadraticAlgebra.re_one,
    QuadraticAlgebra.im_one]

/-! ## rhs ≠ 0: 2(1 + i) in place of 4(1 + i)

N(−2(1 + i)) = 8 is a cube, so the proof of `Kernel.rhs_ne_zero` fails at its last step, and
1 − i is a root. t vanishes at 0, so `Kernel.sqrtT_rhs_ne_zero` needs rhs ≠ 0. -/

example : True := by
  fail_if_success
    have : ∀ x : Fp2Field, x ^ 2 * x + ⟨2, 2⟩ ≠ 0 := by
      intro x h
      have h3 : x ^ 3 = ⟨-2, -2⟩ := by
        have : x ^ 3 = -⟨2, 2⟩ := by linear_combination h
        rw [this]
        ext <;> simp
      apply thirtytwo_not_cube (QuadraticAlgebra.norm x)
      rw [← map_pow, h3, QuadraticAlgebra.norm_def]
      norm_num
  trivial

example : (⟨1, -1⟩ : Fp2Field) ^ 2 * ⟨1, -1⟩ + ⟨2, 2⟩ = 0 := by
  rw [sq]
  ext <;> simp <;> norm_num

example : Kernel.sqrtT 0 = 0 := by
  simp [Kernel.sqrtT, Kernel.sqrtCandidate, Kernel.half]

/-! ## The sign step with its branches swapped

`selectRoot_eq`'s proof, applied to a sign step that keeps the root where the kernel negates it,
fails at the case split on the two signs of a nonzero root. -/

def selectRootSwapped (root : Fp2Field) (largerRoot : Bool) : Fp2Field :=
  if Kernel.isLargerRoot root ^^ largerRoot then root else -root

example : True := by
  fail_if_success
    have : ∀ {root : Fp2Field} {yPos : Fp2}, root ^ 2 = Fp2.toField yPos ^ 2 → ∀ ySign : Bool,
        selectRootSwapped root ySign =
          Fp2.toField (if Fp2.signBit yPos = ySign then yPos else -yPos) := by
      intro root yPos h ySign
      by_cases h0 : Fp2.toField yPos = 0
      · have hr : root = 0 := by
          rw [h0, zero_pow two_ne_zero] at h
          exact pow_eq_zero_iff two_ne_zero |>.mp h
        unfold selectRootSwapped
        split_ifs <;> simp [hr, h0]
      · rcases sq_eq_sq_iff_eq_or_eq_neg.mp h with rfl | rfl
        · unfold selectRootSwapped
          rw [Kernel.isLargerRoot_toField]
          cases Fp2.signBit yPos <;> cases ySign <;> simp
        · unfold selectRootSwapped
          rw [← Fp2.toField_neg, Kernel.isLargerRoot_toField, Fp2.signBit_neg h0]
          cases Fp2.signBit yPos <;> cases ySign <;> simp [Fp2.toField_neg]
  trivial

example : selectRootSwapped 1 false ≠ Kernel.selectRoot 1 false := by decide +kernel

end LeanBlsSimd
