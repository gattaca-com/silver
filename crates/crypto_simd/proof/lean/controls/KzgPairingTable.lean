import LeanBlsSimd.Kzg.PairingTable

open Aeneas Aeneas.Std
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Kzg.Controls

attribute [local irreducible] pairingLineValue fpEncode
set_option exponentiation.threshold 512

private def replaceFirst {α : Type} {n : Usize} (a : Array α n) (x : α) : Array α n :=
  ⟨a.val.set 0 x, by simp⟩

/-- Change one stored field coefficient by one; keep the remaining table entries. -/
def corruptedPairingTable (lines : portable.pairing.PairingLines) : portable.pairing.PairingLines :=
  let row := lines.val[0]'(by simp)
  let pair := row.val[0]'(by simp)
  let coefficient := pair.val[0]'(by simp)
  replaceFirst lines (replaceFirst row (replaceFirst pair
    {coefficient with c0 := (fpEncode (pairingLineValue 0 0 + 1)).l}))

theorem corrupted_pairing_table_rejected (lines : portable.pairing.PairingLines) :
    ¬ PortableLinesRep (corruptedPairingTable lines) := by
  intro h
  have hc := (h 0 0 0).1.2
  simp only [corruptedPairingTable, replaceFirst, Fin.val_zero, List.getElem_set_self] at hc
  change fpRead (fpEncode (pairingLineValue 0 0 + 1)) = pairingLineValue 0 0 at hc
  rw [fpRead_fpEncode] at hc
  exact (show ∀ x : ZMod Fp.modulus, x + 1 ≠ x from
    fun x h => one_ne_zero (add_left_cancel (h.trans (add_zero x).symm))) _ hc

theorem same_table_scratch_change_accepted
    (msm nextMsm : portable.msm.Msm)
    (words nextWords : alloc.vec.Vec (Array U64 4#usize))
    (lines : portable.pairing.PairingLines) (h : PortableLinesRep lines) :
    CurveWorkInvariant (.Portable msm lines words) ∧
      CurveWorkInvariant (.Portable nextMsm lines nextWords) := ⟨h, h⟩

theorem corrupted_table_scratch_rejected
    (msm : portable.msm.Msm) (words : alloc.vec.Vec (Array U64 4#usize))
    (lines : portable.pairing.PairingLines) :
    ¬ CurveWorkInvariant (.Portable msm (corruptedPairingTable lines) words) :=
  corrupted_pairing_table_rejected lines

end LeanBlsSimd.Kzg.Controls
