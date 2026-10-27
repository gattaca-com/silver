import LeanBlsSimd.Pairing.LineFactors
import LeanBlsSimd.LaneTower.LineCoordinates

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.Pairing.LaneLines

open LaneTower

set_option maxRecDepth 4000
set_option exponentiation.threshold 4096

def tableRow (step : Fin 68) : Array (Array U64 8#usize) 8#usize :=
  kzg.pairing_lines.PAIRING_LINES.val[step.val]'(by simp)

def loadedRow (step : Fin 68) : fp8.Fp8 :=
  toFp8 (Fp8.load (ofArray (ofArray ofU64) (tableRow step)))

theorem loadedRow_lane (step : Fin 68) (l : Fin 8) :
    (ofFp8 (loadedRow step)).lane l = ofArray ofU64 (Kzg.pairingRaw step l) := by
  simp only [loadedRow, ofFp8_toFp8, Fp8.lane_load, Fin.getElem_fin, getElem_ofArray]
  rfl

theorem raw_value (a : Array U64 8#usize) :
    val (ofArray ofU64 a) = Kzg.pairingRawValue a := by
  have he : a.val = [a.val[0], a.val[1], a.val[2], a.val[3], a.val[4], a.val[5], a.val[6], a.val[7]] := by
    apply List.ext_getElem
    · simp
    · intro i hi hj
      have hlt : i < 8 := by simpa using hi
      interval_cases i <;> rfl
  rw [val_eq]
  simp only [getElem_ofArray, toNat_ofU64]
  conv_rhs => unfold Kzg.pairingRawValue; rw [he]
  simp only [List.foldr_cons, List.foldr_nil]
  ring

theorem row_normal (step : Fin 68) :
    Normal (fun _ => 1) (loadedRow step) (Kzg.pairingLineValue step) := by
  intro l
  have hb := Kzg.pairingRaw_bounds step l
  constructor <;> rw [loadedRow_lane]
  · intro j
    simp only [Fin.getElem_fin, getElem_ofArray, toNat_ofU64]
    exact hb.1 _ (List.getElem_mem _)
  · rw [raw_value, one_mul]
    exact hb.2.le
  · rw [decode, raw_value, FrobeniusConstants.lane_radix]
    unfold Kzg.pairingLineValue
    rw [Fp.inverse_eq_inv]
    rfl

theorem row_load (step : Usize) (hs : step.val < 68) :
    (do
      let row ← Array.index_usize kzg.pairing_lines.PAIRING_LINES step
      fp8.Fp8.load row) = ok (loadedRow ⟨step.val, hs⟩) := by
  simp only [index_usize_eq kzg.pairing_lines.PAIRING_LINES step hs, bind_tc_ok, Fp8.load_refines]
  rfl

end LeanBlsSimd.Pairing.LaneLines
