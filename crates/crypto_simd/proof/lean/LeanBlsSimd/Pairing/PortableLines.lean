import LeanBlsSimd.Pairing.FixedTableMeaning
import LeanBlsSimd.Portable.Fp12.Arithmetic

set_option maxRecDepth 2000
set_option exponentiation.threshold 4096

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd

namespace LeanBlsSimd.Pairing

abbrev Factors := Fin 2 → Fin 3 → Fp

def factorLine (step : Fin 68) (pair : Fin 2) (v : Factors) : Fp12 :=
  Portable.Fp12.line (Fp2.ofFp (v pair 0))
    (coefficient step pair 0 * Fp2.ofFp (v pair 1))
    (coefficient step pair 1 * Fp2.ofFp (v pair 2))

def pairApply (step : Fin 68) (v : Factors) (present : Array Bool 2#usize)
    (pair : Fin 2) (f : Fp12) : Fp12 :=
  if present.val[pair.val]'(by simp; omega) then f * factorLine step pair v else f

namespace PortableLines

def FactorsRep (factors : Array (Array portable.fp.Fp 3#usize) 2#usize) (v : Factors) : Prop :=
  ∀ (pair : Fin 2) (i : Fin 3),
    (factors.val[pair.val]'(by simp; omega)).val[i.val]'(by simp) = (Kzg.fpEncode (v pair i)).l

theorem coefficient_encoded {lines : portable.pairing.PairingLines}
    (h : Kzg.PortableLinesRep lines) (step : Fin 68) (pair i : Fin 2) :
    ((lines.val[step.val]'(by simp)).val[pair.val]'(by simp; omega)).val[i.val]'(by simp; omega) =
      Portable.Fp2.encode (coefficient step pair i) :=
  Portable.Fp2.rep_eq_encode (h step pair i)

theorem body_step [RuntimeFeatures] (lines : portable.pairing.PairingLines)
    (hl : Kzg.PortableLinesRep lines) (step k : Usize) (hs : step.val < 68) (hk : k.val < 2)
    (factors : Array (Array portable.fp.Fp 3#usize) 2#usize) (v : Factors)
    (hf : FactorsRep factors v) (present : Array Bool 2#usize) (f : Fp12) :
    ∃ k', k'.val = k.val + 1 ∧
      portable.pairing.PairingLines.times_lines_loop.body step factors present lines
        (Portable.Fp12.encode f) k =
        ok (cont (lines, Portable.Fp12.encode (pairApply ⟨step.val, hs⟩ v present ⟨k.val, hk⟩ f), k')) := by
  let s : Fin 68 := ⟨step.val, hs⟩
  let p : Fin 2 := ⟨k.val, hk⟩
  let row := lines.val[step.val]'(by simp; omega)
  let coefficients := row.val[k.val]'(by simp; omega)
  let fac := factors.val[k.val]'(by simp; omega)
  let b := present.val[k.val]'(by simp; omega)
  have hin : k.val + 1 < 2^UScalarTy.Usize.numBits := by
    have := two_pow_32_le_usize
    scalar_tac
  let k' : Usize := UScalar.ofNatCore (k.val + 1) hin
  have hinc : k + 1#usize = ok k' := add_ok _ _ hin
  have htest : k < 2#usize := by simpa using hk
  have hpresent : Array.index_usize present k = ok b := index_usize_eq _ _ hk
  have hrow : Array.index_usize lines step = ok row := index_usize_eq _ _ hs
  have hcoef : Array.index_usize row k = ok coefficients := index_usize_eq _ _ hk
  have hfac : Array.index_usize factors k = ok fac := index_usize_eq _ _ hk
  have hc0 := coefficient_encoded hl s p 0
  have hc1 := coefficient_encoded hl s p 1
  have hf0 := hf p 0
  have hf1 := hf p 1
  have hf2 := hf p 2
  have hzero : portable.fp.Fp.ZERO = (Kzg.fpEncode Fp.zero).l :=
    Portable.Fp.rep_eq_encode Kzg.portableFpRep_zero
  refine ⟨k', rfl, ?_⟩
  simp only [portable.pairing.PairingLines.times_lines_loop.body, htest, if_true,
    hpresent, bind_tc_ok]
  cases hb : b
  · simp only [Bool.false_eq_true, if_false, hinc, bind_tc_ok]
    apply congrArg (fun g => ok (cont (lines, Portable.Fp12.encode g, k')))
    change f = if b then f * factorLine s p v else f
    rw [hb]
    rfl
  · simp only [if_true, hrow, hcoef, hfac, bind_tc_ok,
      index_usize_eq fac 0#usize (by decide),
      index_usize_eq fac 1#usize (by decide),
      index_usize_eq fac 2#usize (by decide),
      index_usize_eq coefficients 0#usize (by decide),
      index_usize_eq coefficients 1#usize (by decide), bind_assoc_eq, bind_tc_ok]
    change (do
      let y ← portable.fp2.Fp2.mul_by_fp (coefficients.val[0]) (fac.val[1])
      let z ← portable.fp2.Fp2.mul_by_fp (coefficients.val[1]) (fac.val[2])
      let out ← portable.fp12.Fp12.mul_by_line (Portable.Fp12.encode f)
        ⟨fac.val[0], portable.fp.Fp.ZERO⟩ y z
      let k1 ← k + 1#usize
      ok (cont (lines, out, k1))) = _
    change coefficients.val[0] = Portable.Fp2.encode (coefficient s p 0) at hc0
    change coefficients.val[1] = Portable.Fp2.encode (coefficient s p 1) at hc1
    change fac.val[0] = (Kzg.fpEncode (v p 0)).l at hf0
    change fac.val[1] = (Kzg.fpEncode (v p 1)).l at hf1
    change fac.val[2] = (Kzg.fpEncode (v p 2)).l at hf2
    rw [hc0, hc1, hf0, hf1, hf2, hzero]
    change (do
      let y ← portable.fp2.Fp2.mul_by_fp (Portable.Fp2.encode (coefficient s p 0))
        (Kzg.fpEncode (v p 1)).l
      let z ← portable.fp2.Fp2.mul_by_fp (Portable.Fp2.encode (coefficient s p 1))
        (Kzg.fpEncode (v p 2)).l
      let out ← portable.fp12.Fp12.mul_by_line (Portable.Fp12.encode f)
        (Portable.Fp2.encode (Fp2.ofFp (v p 0))) y z
      let k1 ← k + 1#usize
      ok (cont (lines, out, k1))) = _
    simp only [Portable.Fp2.mul_by_fp_encoded, Portable.Fp12.mul_by_line_encoded,
      hinc, bind_tc_ok]
    apply congrArg (fun g => ok (cont (lines, Portable.Fp12.encode g, k')))
    change f * factorLine s p v = if b then f * factorLine s p v else f
    rw [hb]
    rfl

theorem times_lines [RuntimeFeatures] (lines : portable.pairing.PairingLines)
    (hl : Kzg.PortableLinesRep lines) (step : Usize) (hs : step.val < 68)
    (factors : Array (Array portable.fp.Fp 3#usize) 2#usize) (v : Factors)
    (hf : FactorsRep factors v) (present : Array Bool 2#usize) (f : Fp12) :
    portable.pairing.PairingLines.times_lines lines (Portable.Fp12.encode f)
      step factors present =
      ok (Portable.Fp12.encode (pairApply ⟨step.val, hs⟩ v present 1
        (pairApply ⟨step.val, hs⟩ v present 0 f))) := by
  let s : Fin 68 := ⟨step.val, hs⟩
  let f1 := pairApply s v present 0 f
  let f2 := pairApply s v present 1 f1
  obtain ⟨k1, hk1, h1⟩ := body_step lines hl step 0#usize hs (by decide) factors v hf present f
  have he1 : k1 = 1#usize := by scalar_tac
  subst k1
  obtain ⟨k2, hk2, h2⟩ := body_step lines hl step 1#usize hs (by decide) factors v hf present f1
  have he2 : k2 = 2#usize := by scalar_tac
  subst k2
  change portable.pairing.PairingLines.times_lines_loop lines step factors present
    (Portable.Fp12.encode f) 0#usize = ok (Portable.Fp12.encode f2)
  rw [portable.pairing.PairingLines.times_lines_loop, loop.eq_1]
  simp only [h1]
  change portable.pairing.PairingLines.times_lines_loop lines step factors present
    (Portable.Fp12.encode f1) 1#usize = ok (Portable.Fp12.encode f2)
  rw [portable.pairing.PairingLines.times_lines_loop, loop.eq_1]
  simp only [h2]
  change portable.pairing.PairingLines.times_lines_loop lines step factors present
    (Portable.Fp12.encode f2) 2#usize = ok (Portable.Fp12.encode f2)
  rw [portable.pairing.PairingLines.times_lines_loop, loop.eq_1]
  simp only [portable.pairing.PairingLines.times_lines_loop.body,
    show ¬ (2#usize < 2#usize) from by decide, if_false]

end PortableLines

end LeanBlsSimd.Pairing
