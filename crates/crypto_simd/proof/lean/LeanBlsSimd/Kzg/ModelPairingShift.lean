import LeanBlsSimd.Kzg.Model
import EthLib.Cryptography.Proofs.Bls.FrZMod

open EthLib.Cryptography Bls Kzg

namespace LeanBlsSimd.Kzg.ModelPairing

private theorem list_mapM_ok {α β ε : Type} (xs : List α)
    (f : α → Except ε β) (g : α → β) (h : ∀ x ∈ xs, f x = .ok (g x)) :
    xs.mapM f = .ok (xs.map g) := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.mapM_cons, h x (by simp),
      ih (fun y hy => h y (by simp [hy])), List.map_cons]
    rfl

theorem array_mapM_ok {α β ε : Type} (xs : Array α)
    (f : α → Except ε β) (g : α → β) (h : ∀ x ∈ xs, f x = .ok (g x)) :
    xs.mapM f = .ok (xs.map g) := by
  rw [Array.mapM_eq_mapM_toList, list_mapM_ok xs.toList f g
    (fun x hx => h x (Array.mem_toList_iff.mp hx))]
  simp [← List.map_toArray]

theorem weighted_powers_eq (indices : Array Nat) (powers : Array Fr) :
    (Array.range indices.size).map (fun k =>
      powers[k]! * ((indices.map Model.cosetShift)[k]! ^ Fr.ofNat Constants.FIELD_ELEMENTS_PER_CELL)) =
      (Array.range indices.size).map fun k =>
        powers[k]! * Fr.powNat (Model.cosetShift indices[k]!) 64 := by
  apply Array.ext (by simp)
  intro k h1 _
  have hkb : k < indices.size := by simpa using h1
  simp only [Array.getElem_map, Array.getElem_range]
  rw [getElem!_pos (indices.map Model.cosetShift) k (by simpa using hkb), Array.getElem_map,
    ← getElem!_pos indices k hkb]
  simp only [Constants.FIELD_ELEMENTS_PER_CELL, Fr.hpow_ofNat_eq_pow _ (by decide : 64 < Fr.modulus),
    ← Fr.powNat_eq_pow]

end LeanBlsSimd.Kzg.ModelPairing
