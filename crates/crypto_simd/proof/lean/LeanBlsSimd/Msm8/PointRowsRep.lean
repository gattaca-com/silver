import LeanBlsSimd.Msm8.StoreHolds
import LeanBlsSimd.Spec.G1Curve
import LeanBlsSimd.Kzg.G1Arithmetic

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8

open EthLib.Cryptography Bls

theorem loadedCoordinate_lane (store : msm8.store.PointStore)
    (indices : Array U32 8#usize) (coordinate : ℕ) (l : Fin 8) :
    (loadedCoordinate store indices coordinate).lane l =
      (pointRows store)[2 * (pointIndices indices)[l] + coordinate]! := by
  ext j hj
  simp [loadedCoordinate, Fp8.lane, transpose8, indexedRows, LIMBS]

theorem loadedCoordinate_holds (store : msm8.store.PointStore)
    (indices : Array U32 8#usize) (l : Fin 8) (x y : Fp)
    (h : PointRowsHold (readPoint (pointRows store) (pointIndices indices)[l]) x y) :
    (loadedCoordinate store indices 0).Holds l x ∧
      (loadedCoordinate store indices 1).Holds l y := by
  obtain ⟨hxn, hx, hyn, hy⟩ := h
  constructor
  · constructor <;> rw [loadedCoordinate_lane]
    · exact hxn
    · exact hx
  · constructor <;> rw [loadedCoordinate_lane]
    · exact hyn
    · exact hy

def RowRep (rows : List Limbs) (index : ℕ) (P : G1Spec.E.Point) : Prop :=
  ∃ x y : Fp, PointRowsHold (readPoint rows index) x y ∧
    G1.Valid ⟨x, y, Fp.one⟩ ∧ G1.toPoint ⟨x, y, Fp.one⟩ = P

theorem signed_affine_valid (x y : Fp) (negative : Bool)
    (h : G1.Valid ⟨x, y, Fp.one⟩) :
    G1.Valid ⟨x, if negative then -y else y, Fp.one⟩ := by
  cases negative
  · exact h
  · simpa only [G1.neg, if_true] using (G1.valid_neg (P := ⟨x, y, Fp.one⟩) h)

theorem signed_affine_toPoint (x y : Fp) (negative : Bool)
    (h : G1.Valid ⟨x, y, Fp.one⟩) :
    G1.toPoint ⟨x, if negative then -y else y, Fp.one⟩ =
      if negative then -G1.toPoint ⟨x, y, Fp.one⟩ else G1.toPoint ⟨x, y, Fp.one⟩ := by
  cases negative
  · rfl
  · simpa only [G1.neg, if_true] using (G1.toPoint_neg (P := ⟨x, y, Fp.one⟩) h)

theorem load_signed_point (store : msm8.store.PointStore)
    (indices : Array U32 8#usize) (negated : Mmask8) (l : Fin 8) (P : G1Spec.E.Point)
    (h : RowRep (pointRows store) (pointIndices indices)[l] P) :
    ∃ x y : Fp, (loadedCoordinate store indices 0).Holds l x ∧
      (Fp8.select negated (loadedCoordinate store indices 1)
        (loadedCoordinate store indices 1).neg).Holds l y ∧
      G1.Valid ⟨x, y, Fp.one⟩ ∧
      G1.toPoint ⟨x, y, Fp.one⟩ = (if negated.toNat.testBit l then -P else P) := by
  obtain ⟨x, y, hr, hv, hp⟩ := h
  obtain ⟨hx, hy⟩ := loadedCoordinate_holds store indices l x y hr
  refine ⟨x, if negated.toNat.testBit l then -y else y, hx,
    hy.select negated hy.neg, signed_affine_valid x y _ hv, ?_⟩
  rw [signed_affine_toPoint x y _ hv, hp]

end LeanBlsSimd.Msm8
