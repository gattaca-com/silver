import LeanBlsSimd.Msm8.WindowSum
import LeanBlsSimd.Msm8.PointRowsRep

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.WindowSums

open EthLib.Cryptography Bls

def entryPoint (state : msm8.buckets.Buckets) (points : ℕ → G1Spec.E.Point)
    (group bucket cursor : ℕ) (l : Fin 8) : G1Spec.E.Point :=
  let reference := referenceAt state (group * 8 + l.val) bucket cursor
  if cursor < (bucketLength state (group * 8 + l.val) bucket).val then
    if 2 ^ 31 ≤ reference.val then -points (clearSign reference).val
      else points (clearSign reference).val
  else 0

theorem loadedEntry_rep (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (points : ℕ → G1Spec.E.Point) (group bucket cursor : ℕ) (l : Fin 8)
    (hr : cursor < (bucketLength state (group * 8 + l.val) bucket).val →
      Msm8.RowRep (pointRows store)
        (clearSign (referenceAt state (group * 8 + l.val) bucket cursor)).val
        (points (clearSign (referenceAt state (group * 8 + l.val) bucket cursor)).val)) :
    EntryRep (loadedEntry state store group bucket cursor) l
      (entryPoint state points group bucket cursor l) := by
  let raw := encodeEntries (entriesModel state group bucket cursor)
  have hindex : (pointIndices raw.indices)[l] =
      (clearSign (referenceAt state (group * 8 + l.val) bucket cursor)).val := by
    change (pointIndices raw.indices)[l.val] = _
    simp only [raw, encodeEntries, pointIndices, getElem_ofArray, toArray,
      List.getElem_map, Vector.getElem_toList, id_eq, entriesModel_indices,
      Vector.getElem_ofFn]
  have hmask : (ofU8 raw.present).toNat.testBit l =
      decide (cursor < (bucketLength state (group * 8 + l.val) bucket).val) :=
    entriesModel_present state group bucket cursor l
  have hsign : (ofU8 raw.negated).toNat.testBit l =
      decide (2 ^ 31 ≤ (referenceAt state (group * 8 + l.val) bucket cursor).val) :=
    entriesModel_negated state group bucket cursor l
  change (if (ofU8 raw.present).toNat.testBit l then
    ∃ x y : Fp, (loadedCoordinate store raw.indices 0).Holds l x ∧
      (Fp8.select (ofU8 raw.negated) (loadedCoordinate store raw.indices 1)
        (loadedCoordinate store raw.indices 1).neg).Holds l y ∧
      G1.Valid ⟨x, y, Fp.one⟩ ∧
      G1.toPoint ⟨x, y, Fp.one⟩ = entryPoint state points group bucket cursor l
    else entryPoint state points group bucket cursor l = 0)
  rw [hmask]
  by_cases present : cursor < (bucketLength state (group * 8 + l.val) bucket).val
  · simp only [present, decide_true, if_true]
    have hrow : Msm8.RowRep (pointRows store) (pointIndices raw.indices)[l]
        (points (clearSign (referenceAt state (group * 8 + l.val) bucket cursor)).val) := by
      rw [hindex]
      exact hr present
    obtain ⟨x, y, hx, hy, hv, hp⟩ :=
      Msm8.load_signed_point store raw.indices (ofU8 raw.negated) l _ hrow
    refine ⟨x, y, hx, hy, hv, ?_⟩
    simpa only [hsign, decide_eq_true_eq, entryPoint, present, if_true] using hp
  · simp only [present, decide_false, Bool.false_eq_true, if_false, entryPoint]

end LeanBlsSimd.WindowSums
