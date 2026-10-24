import LeanBlsSimd.Portable.Fp12.Frobenius
import controls.TowerField
import controls.Cyclotomic
import controls.ContractSamples

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Controls.PortableTower

open Portable
open ContractSamples (check arrayEq)

set_option maxRecDepth 4096

section

variable [RuntimeFeatures]

theorem fp2_inverse_zero :
    portable.fp2.Fp2.inverse (Fp2.encode Bls.Fp2.zero) = ok (Fp2.encode Bls.Fp2.zero) := by
  rw [Fp2.inverse_encoded]
  congr 2
  apply LeanBlsSimd.Fp2.toField.injective
  simp [LeanBlsSimd.Fp2.toField_inverse]

theorem fp6_inverse_zero :
    portable.fp6.Fp6.inverse (Fp6.encode Bls.Fp6.zero) = ok (Fp6.encode Bls.Fp6.zero) := by
  rw [Fp6.inverse_encoded, Tower.fp6_inverse_zero]

theorem fp12_inverse_zero :
    portable.fp12.Fp12.inverse (Fp12.encode Bls.Fp12.zero) = ok (Fp12.encode Bls.Fp12.zero) := by
  rw [Fp12.inverse_encoded, Tower.fp12_inverse_zero]

theorem raw_formula_needs_phi :
    ¬ ∀ a : Bls.Fp12,
      portable.fp12.Fp12.cyclotomic_square (Fp12.encode a) = ok (Fp12.encode a.square) := by
  intro h
  have hr := Fp12.cyclotomic_raw_encoded Cyclotomic.minusOne
  have he := Fp12.encode_injective (Result.ok.inj (hr.symm.trans (h _)))
  have hf := congrArg LeanBlsSimd.Fp12.toField he
  apply Cyclotomic.field_formula_wrong_without_phi
  simpa only [Fp12.ofCoeffs_field, LeanBlsSimd.Fp12.toField_square] using hf

end

def eq2 (a b : portable.fp2.Fp2) : Bool := arrayEq a.c0 b.c0 && arrayEq a.c1 b.c1

def eq6 (a b : portable.fp6.Fp6) : Bool := eq2 a.c0 b.c0 && eq2 a.c1 b.c1 && eq2 a.c2 b.c2

def eq12 (a b : portable.fp12.Fp12) : Bool := eq6 a.c0 b.c0 && eq6 a.c1 b.c1

def result2 (a : Result portable.fp2.Fp2) (want : Bls.Fp2) : Bool :=
  match a with | .ok out => eq2 out (Fp2.encode want) | _ => false

def result12 (a : Result portable.fp12.Fp12) (want : Bls.Fp12) : Bool :=
  match a with | .ok out => eq12 out (Fp12.encode want) | _ => false

def runSamples (bmi : Bool) : IO Unit :=
  letI : RuntimeFeatures := { simdAvailable := false, shaAvailable := false, bmi2Available := bmi }
  let maximum := Kzg.words 6#usize (Bls.Fp.modulus - 1)
  let high : Bls.Fp := Kzg.fpRead ⟨maximum⟩
  let ordinaryHigh : Bls.Fp2 := ⟨Bls.Fp.ofNat (Bls.Fp.modulus - 1), Bls.Fp.ofNat (Bls.Fp.modulus - 1)⟩
  let a : Bls.Fp2 := ⟨high, high⟩
  let b : Bls.Fp2 := ⟨Bls.Fp.one, high⟩
  (do
    check "maximum canonical Montgomery input" (arrayEq (Kzg.fpEncode high).l maximum)
    for (x, y) in [(a, a), (a, b), (b, a), (Bls.Fp2.zero, a), (ordinaryHigh, ordinaryHigh)] do
      check "wide Fp2 canonical boundary product"
        (result2 (portable.fp2.Fp2.mul (Fp2.encode x) (Fp2.encode y)) (x * y))
    let x : Bls.Fp12 := ⟨⟨a, b, Bls.Fp2.one⟩, ⟨b, a, Bls.Fp2.i⟩⟩
    check "portable Fp12 optimized square"
      (result12 (portable.fp12.Fp12.square (Fp12.encode x)) x.square)
    check "portable Fp12 sparse line"
      (result12 (portable.fp12.Fp12.mul_by_line (Fp12.encode x)
        (Fp2.encode a) (Fp2.encode b) (Fp2.encode Bls.Fp2.i)) (x * Fp12.line a b Bls.Fp2.i))
    check "portable Fp12 nonzero inverse"
      (result12 (portable.fp12.Fp12.inverse (Fp12.encode x)) x.inverse)
    check "portable Fp12 inverse zero"
      (result12 (portable.fp12.Fp12.inverse (Fp12.encode Bls.Fp12.zero)) Bls.Fp12.zero)
    check "portable Fp12 Frobenius"
      (result12 (portable.fp12.Fp12.frobenius (Fp12.encode x)) (Bls.Fp12.powNat x Bls.Fp.modulus))
    check "portable cyclotomic square of one"
      (result12 (portable.fp12.Fp12.cyclotomic_square (Fp12.encode Bls.Fp12.one)) Bls.Fp12.one)
    check "raw cyclotomic square wrongly accepted for minus one"
      (!(result12 (portable.fp12.Fp12.cyclotomic_square (Fp12.encode (-Bls.Fp12.one))) Bls.Fp12.one))
    : IO Unit)

#eval do
  runSamples false
  runSamples true
  IO.println "portable tower: both BMI2 branches, canonical boundaries, inverse zero and raw-formula rejection passed"

#print axioms Portable.Fp2.product_encoded
#print axioms Portable.Fp6.inverse_encoded
#print axioms Portable.Fp12.mul_by_line_encoded
#print axioms Portable.Fp12.cyclotomic_raw_encoded
#print axioms Portable.Fp12.cyclotomic_square_encoded
#print axioms Portable.Fp12.frobenius_encoded
#print axioms FrobeniusConstants.portable_entry_decodes

end LeanBlsSimd.Controls.PortableTower
