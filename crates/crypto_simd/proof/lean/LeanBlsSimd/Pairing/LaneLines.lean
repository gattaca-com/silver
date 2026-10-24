import LeanBlsSimd.Pairing.LaneLine
import LeanBlsSimd.Pairing.MillerSchedule

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.Pairing.LaneLines

open LaneTower

def FactorsRep (factors z : fp8.Fp8) (v : Factors) : Prop :=
  Normal (fun _ => 2) factors (packedFactors v) ∧
  ∃ zs, Normal (fun _ => 2) z zs ∧ zs 0 = v 0 0 ∧ zs 1 = v 1 0

def maskPresence (present : U8) : Array Bool 2#usize :=
  Array.make 2#usize [present &&& 1#u8 != 0#u8, present &&& 2#u8 != 0#u8] (by rfl)

theorem apply_line {x z : fp8.Fp8} (step : Fin 68) (pair : Fin 2) (v : Factors) (zs : V F)
    (hx : Normal (fun _ => 2) x (products step v))
    (hz : Normal (fun _ => 2) z zs) (hz0 : zs 0 = v 0 0) (hz1 : zs 1 = v 1 0)
    {f : fp2x8.Fp2x8} {a : Bls.Fp12} (ha : Rep f a) :
    ∃ out, (do
      let line ← pairing.line x z (UScalar.ofNatCore pair.val (by have := two_pow_32_le_usize; omega))
      fp12.Fp12.mul_by_line f line) = ok out ∧ Rep out (a * factorLine step pair v) := by
  obtain ⟨line, hline, rline⟩ := line_refines step pair v zs hx hz hz0 hz1
  obtain ⟨out, hout, rout⟩ := mul_by_line_refines ha rline
  refine ⟨out, ?_, ?_⟩
  · simp only [hline, bind_tc_ok, hout]
  · rw [line_value] at rout
    exact rout

theorem times_lines (step : Usize) (hs : step.val < 68)
    (factors z : fp8.Fp8) (v : Factors) (hv : FactorsRep factors z v)
    (present : U8) {f : fp2x8.Fp2x8} {a : Bls.Fp12} (ha : Rep f a) :
    ∃ out, pairing.MillerLines.times_lines kzg.pairing_lines.PAIRING_LINES f step factors z present = ok out ∧
      Rep out (applyLines v (maskPresence present) ⟨step.val, hs⟩ a) := by
  obtain ⟨hfac, zs, hz, hz0, hz1⟩ := hv
  obtain ⟨prod, hprod, rprod⟩ := raw_mul (row_normal ⟨step.val, hs⟩) hfac (by intro l; decide)
  change Normal (fun _ => 2) prod (products ⟨step.val, hs⟩ v) at rprod
  have h0 := apply_line ⟨step.val, hs⟩ 0 v zs rprod hz hz0 hz1 ha
  obtain ⟨first, hfirst, rfirst⟩ : ∃ first,
      (if present &&& 1#u8 != 0#u8 then do
        let line ← pairing.line prod z 0#usize
        fp12.Fp12.mul_by_line f line else ok f) = ok first ∧
      Rep first (pairApply ⟨step.val, hs⟩ v (maskPresence present) 0 a) := by
    by_cases h : (present &&& 1#u8 != 0#u8) = true
    · simpa only [h, if_true, pairApply, maskPresence, Array.make, List.getElem_cons_zero] using h0
    · refine ⟨f, ?_, ?_⟩
      · rw [if_neg h]
      · change Rep f (if present &&& 1#u8 != 0#u8 then a * factorLine ⟨step.val, hs⟩ 0 v else a)
        rw [if_neg h]
        exact ha
  obtain ⟨second, hsecond, rsecond⟩ : ∃ second,
      (if present &&& 2#u8 != 0#u8 then do
        let line ← pairing.line prod z 1#usize
        fp12.Fp12.mul_by_line first line else ok first) = ok second ∧
      Rep second (applyLines v (maskPresence present) ⟨step.val, hs⟩ a) := by
    by_cases h : (present &&& 2#u8 != 0#u8) = true
    · simpa only [h, if_true, applyLines, pairApply, maskPresence, Array.make,
        List.getElem_cons_succ, List.getElem_cons_zero] using
        apply_line ⟨step.val, hs⟩ 1 v zs rprod hz hz0 hz1 rfirst
    · refine ⟨first, ?_, ?_⟩
      · rw [if_neg h]
      · change Rep first (if present &&& 2#u8 != 0#u8 then
          pairApply ⟨step.val, hs⟩ v (maskPresence present) 0 a * factorLine ⟨step.val, hs⟩ 1 v
          else pairApply ⟨step.val, hs⟩ v (maskPresence present) 0 a)
        rw [if_neg h]
        exact rfirst
  refine ⟨second, ?_, rsecond⟩
  simp only [pairing.MillerLines.times_lines,
    index_usize_eq kzg.pairing_lines.PAIRING_LINES step hs, bind_tc_ok, Fp8.load_refines]
  dsimp only [loadedRow, tableRow] at hprod
  simp only [hprod, lift, bind_tc_ok, hfirst, hsecond]

end LeanBlsSimd.Pairing.LaneLines
