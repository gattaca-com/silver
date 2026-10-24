import LeanBlsSimd.LaneTower.Frobenius
import LeanBlsSimd.LaneTower.LineCoordinates
import LeanBlsSimd.LaneTower.CyclotomicCoordinates
import LeanBlsSimd.LaneTower.Identity
import LeanBlsSimd.Portable.Fp12.Frobenius
import LeanBlsSimd.Spec.Cyclotomic.Field
import LeanBlsSimd.Spec.FinalExponentiation

open EthLib.Cryptography.Bls LeanBlsSimd LeanBlsSimd.Cyclotomic

noncomputable section

example (a b : Fp12) : Fp12.toField (a * b) = Fp12.toField a * Fp12.toField b :=
  Fp12.toField.map_mul a b

example (a : Fp12) : Fp12.toField a.inverse = (Fp12.toField a)⁻¹ := Fp12.toField_inverse a

example (a : Fp12) : Fp12.toField a.conjugate = Fp12.toField a ^ (Fp.modulus^6) :=
  spec_conjugate a

example (a : Schedule.Coeffs Bls.K)
    (h : fieldDecode a ^ (Fp.modulus^4-Fp.modulus^2+1) = 1) :
    fieldDecode (Schedule.raw LeanBlsSimd.Fp6Field.xi a) = fieldDecode a ^ 2 := field_cyclotomic_square a h

example (a : Schedule.Coeffs Bls.K) :
    fieldDecode (frobeniusCoeffs a) = fieldDecode a ^ Fp.modulus := field_frobenius a

example (a : Fp12Field) (h : a ≠ 0) :
    fieldEasyPart a ^ (Fp.modulus^4-Fp.modulus^2+1) = 1 := field_easy_cyclotomic a h

example (a : Fp12) (h : a ≠ Fp12.zero) :
    finalExponentiationTarget a h ^ Fr.modulus = 1 := target_pow_r _

open Aeneas.Std Result silver_crypto_simd

example [RuntimeFeatures] (a b : Fp12) :
    portable.fp12.Fp12.mul (Portable.Fp12.encode a) (Portable.Fp12.encode b) =
      ok (Portable.Fp12.encode (a * b)) := Portable.Fp12.mul_encoded a b

example [RuntimeFeatures] (a : Fp12) :
    portable.fp12.Fp12.inverse (Portable.Fp12.encode a) =
      ok (Portable.Fp12.encode a.inverse) := Portable.Fp12.inverse_encoded a

example [RuntimeFeatures] (a : Fp12)
    (h : Fp12.toField a ^ (Fp.modulus ^ 4 - Fp.modulus ^ 2 + 1) = 1) :
    portable.fp12.Fp12.cyclotomic_square (Portable.Fp12.encode a) =
      ok (Portable.Fp12.encode a.square) := Portable.Fp12.cyclotomic_square_encoded a h

example [RuntimeFeatures] (a : Fp12) :
    portable.fp12.Fp12.frobenius (Portable.Fp12.encode a) =
      ok (Portable.Fp12.encode (Fp12.powNat a Fp.modulus)) := Portable.Fp12.frobenius_encoded a

example (j : Fin 6) :
    Fp2.toField ⟨Kzg.fpRead ⟨FrobeniusConstants.portableRow j 0⟩,
      Kzg.fpRead ⟨FrobeniusConstants.portableRow j 1⟩⟩ =
      Fp6Field.xi ^ (j.val * ((Fp.modulus - 1) / 6)) := FrobeniusConstants.portable_entry_decodes j

example (j : Fin 6) :
    (⟨decode (FrobeniusConstants.laneLimbs j 0),
      decode (FrobeniusConstants.laneLimbs j 1)⟩ : Fp2Field) =
      Fp6Field.xi ^ (j.val * ((Fp.modulus - 1) / 6)) := FrobeniusConstants.lane_entry_decodes j

example (h : Fin 2) (k : Fin 3) (x : Fp2Field) :
    Fp12.toField (LaneTower.value (LaneTower.single h k x)) =
      LaneTower.embed x * Fp12Field.w ^ (2 * k.val + h.val) := LaneTower.lane_basis h k x

example (x y : bls.fp2x8.Fp2x8) (a b : LaneTower.P LaneTower.F)
    (hx : LaneTower.Normal2 (fun _ => 256, fun _ => 256) x a)
    (hy : LaneTower.Normal2 (fun _ => 256, fun _ => 256) y b) :
    ∃ out, bls.fp12.Fp12.mul x y = ok out ∧
      LaneTower.Normal2 (fun _ => 108, fun _ => 108) out (LaneTower.productValues a b) :=
  LaneTower.mul_raw hx hy

example (a b : LaneTower.P LaneTower.F) :
    LaneTower.value (LaneTower.productValues a b) =
      (LaneTower.value a).mul (LaneTower.value b) := LaneTower.product_value a b

example (x y : bls.fp2x8.Fp2x8) (a b : Fp12)
    (hx : LaneTower.Rep x a) (hy : LaneTower.Rep y b) :
    ∃ out, bls.fp12.Fp12.mul x y = ok out ∧ LaneTower.Rep out (a.mul b) :=
  LaneTower.mul_refines hx hy

example (x : bls.fp2x8.Fp2x8) (a : Fp12) (hx : LaneTower.Rep x a) :
    ∃ out, bls.fp12.Fp12.square x = ok out ∧ LaneTower.Rep out a.square :=
  LaneTower.square_refines hx

example (x : bls.fp2x8.Fp2x8) (a : Fp12) (hx : LaneTower.Rep x a) :
    ∃ out, bls.fp12.Fp12.conjugate x = ok out ∧ LaneTower.Rep out a.conjugate :=
  LaneTower.conjugate_refines hx

example : ∃ out, bls.fp12.Fp12.one = ok out ∧ LaneTower.Rep out Fp12.one :=
  LaneTower.one_refines

example (x : bls.fp2x8.Fp2x8) (a : Fp12) (hx : LaneTower.Rep x a) :
    ∃ out, bls.fp12.Fp12.frobenius x = ok out ∧ LaneTower.Rep out (Fp12.powNat a Fp.modulus) :=
  LaneTower.frobenius_refines hx

example (x y : bls.fp2x8.Fp2x8) (a : Fp12) (b : LaneTower.P LaneTower.F)
    (hx : LaneTower.Rep x a) (hy : LaneTower.Strict2 256 y b) :
    ∃ out, bls.fp12.Fp12.mul_by_line x y = ok out ∧
      LaneTower.Rep out (a.mul (LaneTower.value (LaneTower.sparseLine b))) :=
  LaneTower.mul_by_line_refines hx hy

example (x : bls.fp2x8.Fp2x8) (a : Fp12) (hx : LaneTower.Rep x a)
    (h : Fp12.toField a = 0 ∨
      Fp12.toField a ^ (Fp.modulus ^ 4 - Fp.modulus ^ 2 + 1) = 1) :
    ∃ out, bls.fp12.Fp12.cyclotomic_square x = ok out ∧ LaneTower.Rep out a.square :=
  LaneTower.cyclotomic_square_refines hx h

example (x : bls.fp2x8.Fp2x8) (a : Fp12) (hx : LaneTower.Rep x a) :
    ∃ out, bls.fp12.Fp12.inverse x = ok out ∧ LaneTower.Rep out a.inverse :=
  LaneTower.inverse_refines hx

example (x : bls.fp2x8.Fp2x8) (a : Fp12) (hx : LaneTower.Rep x a) :
    bls.fp12.Fp12.is_one x = ok a.isOne := LaneTower.is_one_refines hx
