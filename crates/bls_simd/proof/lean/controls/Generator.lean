import LeanBlsSimd.Spec.Generator

/-! Negative controls for `LeanBlsSimd.Spec.Generator`. Each `example` must pass.

`psi_generator` checks the ψ constants and the sign of z together. Three mutants keep ψ a map of
E′ to itself, so each gives a statement of the same shape:

- −z in place of z;
- −c_y in place of c_y, the other square root of i. That ψ is −ψ, so its statement is the
  previous one;
- ζ·c_x in place of c_x, another cube root of i. That ψ is φ ∘ ψ.

The first examples show each mutated statement false. The last run the step of `psi_generator`'s
proof that decides, the evaluation of `scottMembership`'s comparison, on each mutant, and show it
rejects G. -/

namespace LeanBlsSimd

open EthCryptographySpecs EthCryptographySpecs.Bls Kernel WeierstrassCurve

local notation "G" => G2.toPoint G2.generator

/-! ## The mutated statements are false -/

/-- [r]G = O, so [k]G = O forces r to divide k. -/
theorem generator_ne_zero_of_coprime {k : ℤ} (hk : Int.gcd Fr.modulus k = 1) (h : k • G = 0) :
    False := by
  have hr : (Fr.modulus : ℤ) • G = 0 := by rw [natCast_zsmul, generator_torsion]
  have hG : G = 0 := by
    have hb := Int.gcd_eq_gcd_ab (Fr.modulus : ℤ) k
    rw [hk, Nat.cast_one] at hb
    calc G = (1 : ℤ) • G := (one_zsmul G).symm
      _ = (Int.gcdA Fr.modulus k) • ((Fr.modulus : ℤ) • G) +
          (Int.gcdB Fr.modulus k) • (k • G) := by
        rw [hb, add_zsmul, mul_comm, mul_zsmul, mul_comm k, mul_zsmul]
      _ = 0 := by rw [hr, h, zsmul_zero, zsmul_zero, add_zero]
  rw [toPoint_generator] at hG
  exact Affine.Point.some_ne_zero _ hG

example : psi G ≠ (-z) • G := fun h =>
  generator_ne_zero_of_coprime (k := 2 * z) (by decide +kernel) (by
    calc (2 * z) • G = z • G - (-z) • G := by module
      _ = 0 := by rw [← psi_generator, h, sub_self])

example : -psi G ≠ z • G := fun h =>
  generator_ne_zero_of_coprime (k := 2 * z) (by decide +kernel) (by
    calc (2 * z) • G = z • G - -(z • G) := by module
      _ = 0 := by rw [← psi_generator, h, psi_generator, sub_self])

example : phi (psi G) ≠ z • G := fun h =>
  generator_ne_zero_of_coprime (k := z ^ 3 + z) (by decide +kernel) (by
    have h3 : phi (psi G) = -((z ^ 3) • G) := by
      rw [← neg_neg (phi _), ← psi_psi]
      simp only [psi_generator, map_zsmul]
      module
    rw [add_zsmul, ← h, h3, add_neg_cancel])

/-! ## The decisive step rejects each mutant

`scottWith` is `scottMembership`'s verdict over the chain of `timesMinusZ_eq_formula`, with ψ's
constants and the sign of the y-test as parameters: `sx` scales x's swapped coordinates, `cyv`
multiplies ȳ, and `ySign` applies to the chain's Y. -/

def scottWith (sx : ZMod Fp.modulus) (cyv : Fp2Field) (ySign : Fp2Field → Fp2Field)
    (px py : Fp2Field) : Bool :=
  let t := (List.range Z_BITS[0]!).reverse.foldl (chainStepFormula px py) (![px, py, 1], false)
  let undecided := t.2 || decide (t.1 2 = 0)
  decide (t.1 0 = ⟨sx * px.im, sx * px.re⟩ * t.1 2 ^ 2) &&
    decide (ySign (t.1 1) = star py * cyv * (t.1 2 ^ 2 * t.1 2)) && !undecided

theorem scottWith_eq (px py : Fp2Field) :
    scottWith psiX ⟨psiY.1, psiY.2⟩ Neg.neg px py = (scottMembership px py).1 := by
  unfold scottMembership
  rw [timesMinusZ_eq_formula]
  simp only [scottWith]

example : scottWith psiX ⟨psiY.1, psiY.2⟩ Neg.neg (Fp2.toField G2.generator.x)
    (Fp2.toField G2.generator.y) = true := by
  decide +kernel

-- −z: the y-test compares Y, so it tests ψ(P) = [|z|]P = [−z]P.
example : scottWith psiX ⟨psiY.1, psiY.2⟩ id (Fp2.toField G2.generator.x)
    (Fp2.toField G2.generator.y) = false := by
  decide +kernel

-- −c_y.
example : scottWith psiX ⟨-psiY.1, -psiY.2⟩ Neg.neg (Fp2.toField G2.generator.x)
    (Fp2.toField G2.generator.y) = false := by
  decide +kernel

-- ζ·c_x: ζ = `beta` lies in Fp, so it scales both swapped coordinates.
example : scottWith (beta * psiX) ⟨psiY.1, psiY.2⟩ Neg.neg (Fp2.toField G2.generator.x)
    (Fp2.toField G2.generator.y) = false := by
  decide +kernel

end LeanBlsSimd
