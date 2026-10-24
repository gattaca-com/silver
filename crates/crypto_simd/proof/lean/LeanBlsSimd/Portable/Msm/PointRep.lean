import LeanBlsSimd.Portable.Msm.Store
import LeanBlsSimd.Msm8.PointRowsRep

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Store

/-- Only initialized, finite affine slots have this representation. -/
def PointRep (store : portable.msm.store.PointStore) (i : ℕ) (P : G1Spec.E.Point) : Prop :=
  ∃ x y : Bls.Fp, Holds store i x y ∧
    Bls.G1.Valid ⟨x,y,Bls.Fp.one⟩ ∧ Bls.G1.toPoint ⟨x,y,Bls.Fp.one⟩ = P

def coordinates (store : portable.msm.store.PointStore) (i : ℕ) : Bls.Fp × Bls.Fp :=
  let row := store.points.val[i]!
  (Kzg.fpRead ⟨row.val[0]!⟩, Kzg.fpRead ⟨row.val[1]!⟩)

theorem coordinates_eq (store : portable.msm.store.PointStore) (i : ℕ) (x y : Bls.Fp)
    (h : Holds store i x y) : coordinates store i = (x,y) := by
  have hr : store.points.val[i]! = Fp.pairEncode x y := by
    rw [getElem!_pos store.points.val i (holds_bound h)]
    exact holds_row h
  simp only [coordinates,hr]
  change (Kzg.fpRead (Kzg.fpEncode x),Kzg.fpRead (Kzg.fpEncode y)) = (x,y)
  simp only [Kzg.fpRead_fpEncode]

theorem PointRep.coordinates {store : portable.msm.store.PointStore} {i : ℕ} {P : G1Spec.E.Point}
    (h : PointRep store i P) :
    Holds store i (coordinates store i).1 (coordinates store i).2 ∧
    Bls.G1.Valid ⟨(coordinates store i).1,(coordinates store i).2,Bls.Fp.one⟩ ∧
    Bls.G1.toPoint ⟨(coordinates store i).1,(coordinates store i).2,Bls.Fp.one⟩ = P := by
  obtain ⟨x,y,hc,hv,hp⟩ := h
  rw [coordinates_eq store i x y hc]
  exact ⟨hc,hv,hp⟩

theorem PointRep.frame {before after : portable.msm.store.PointStore} {i : ℕ} {P : G1Spec.E.Point}
    (h : PointRep before i P) (he : after.points.val[i]? = before.points.val[i]?) :
    PointRep after i P := by
  obtain ⟨x,y,hc,hv,hp⟩ := h
  exact ⟨x,y,he.trans hc,hv,hp⟩

end LeanBlsSimd.Portable.Msm.Store
