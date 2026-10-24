import LeanBlsSimd.Spec.Fp12
import LeanBlsSimd.Spec.Cyclotomic.Schedule

namespace LeanBlsSimd.Cyclotomic

open EthLib.Cryptography.Bls
open Bls Schedule

noncomputable section

/-- The standard tower's cubic generator is w² in the cubic-over-quadratic model. -/
def fp6ToCubic : Fp6Field →+* T :=
  AdjoinRoot.lift (f := Fp6Field.polynomial) kembed (w u ^ 2) (by
    simp only [Fp6Field.polynomial, Polynomial.eval₂_sub, Polynomial.eval₂_pow,
      Polynomial.eval₂_X, Polynomial.eval₂_C]
    rw [← pow_mul, show 2*3=6 by rfl, w_sixth]
    simp [xi, Fp6Field.xi])

@[simp] theorem fp6ToCubic_of (a : K) : fp6ToCubic (Fp6Field.of a) = kembed a :=
  AdjoinRoot.lift_of _

@[simp] theorem fp6ToCubic_v : fp6ToCubic Fp6Field.v = w u ^ 2 :=
  AdjoinRoot.lift_root _

local instance : Algebra Fp6Field T := fp6ToCubic.toAlgebra

def toCubic : Fp12Field →+* T :=
  (QuadraticAlgebra.lift (R := Fp6Field) (a := Fp6Field.v) (b := 0) (A := T)
    ⟨w u, by
      change w u * w u = fp6ToCubic Fp6Field.v * 1 + fp6ToCubic 0 * w u
      rw [fp6ToCubic_v, map_zero, zero_mul, add_zero, mul_one, pow_two]⟩).toRingHom

@[simp] theorem toCubic_mk (a b : Fp6Field) :
    toCubic ⟨a,b⟩ = fp6ToCubic a + fp6ToCubic b * w u := by
  change fp6ToCubic a * 1 + fp6ToCubic b * w u = _
  rw [mul_one]

noncomputable def fieldDecode (x : Coeffs K) : Fp12Field :=
  ⟨Fp6Field.assemble x.c00 x.c01 x.c02, Fp6Field.assemble x.c10 x.c11 x.c12⟩

theorem fp6ToCubic_assemble (a b c : K) :
    fp6ToCubic (Fp6Field.assemble a b c) =
      kembed a + kembed b * w u ^ 2 + kembed c * w u ^ 4 := by
  simp only [Fp6Field.assemble, map_add, map_mul, map_pow, fp6ToCubic_of, fp6ToCubic_v]
  rw [← pow_mul]

theorem embed_mk (a b : K) : embed u (⟨a,b⟩ : S) = kembed a + kembed b * w u ^ 3 := by
  rw [w_cube]
  change embed u (⟨a,b⟩ : S) = embed u (j a) + embed u (j b) * embed u u
  rw [← map_mul, ← map_add]
  congr 1
  ext <;> simp

theorem toCubic_fieldDecode (x : Coeffs K) : toCubic (fieldDecode x) = decode xi x := by
  simp only [fieldDecode, toCubic_mk, fp6ToCubic_assemble, decode, assemble, ca, cb, cc,
    embed_mk]
  ring

theorem toCubic_bijective : Function.Bijective toCubic := by
  refine ⟨toCubic.injective, ?_⟩
  intro x
  obtain ⟨a,b,c,rfl⟩ := assemble_surjective u x
  refine ⟨fieldDecode ⟨a.re,c.re,b.im,b.re,a.im,c.im⟩, ?_⟩
  rw [toCubic_fieldDecode]
  rfl

/-- Reorders the six Fp2 coordinates while preserving all ring operations. -/
def fieldEquiv : Fp12Field ≃+* T := RingEquiv.ofBijective toCubic toCubic_bijective

def specCoeffs (x : Fp12) : Coeffs K :=
  ⟨Fp2.toField x.c0.c0, Fp2.toField x.c0.c1, Fp2.toField x.c0.c2,
    Fp2.toField x.c1.c0, Fp2.toField x.c1.c1, Fp2.toField x.c1.c2⟩

theorem spec_toCubic (x : Fp12) :
    fieldEquiv (Fp12.toField x) = decode xi (specCoeffs x) := by
  change toCubic (fieldDecode (specCoeffs x)) = _
  exact toCubic_fieldDecode _

theorem field_cyclotomic_square (x : Coeffs K)
    (h : fieldDecode x ^ (p^4-p^2+1) = 1) :
    fieldDecode (raw xi x) = fieldDecode x ^ 2 := by
  apply toCubic.injective
  rw [map_pow, toCubic_fieldDecode, toCubic_fieldDecode]
  apply bls_cyclotomic_square
  simpa only [map_pow, map_one, toCubic_fieldDecode] using congrArg toCubic h

theorem field_conjugate (x : Coeffs K) :
    fieldDecode (conjugate x) = fieldDecode x ^ (p^6) := by
  apply toCubic.injective
  rw [map_pow, toCubic_fieldDecode, toCubic_fieldDecode, conjugate_decode]

end
end LeanBlsSimd.Cyclotomic
