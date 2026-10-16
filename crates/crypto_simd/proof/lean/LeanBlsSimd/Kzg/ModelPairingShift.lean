import LeanBlsSimd.Kzg.Model
import EthCryptographySpecs.Proofs.Bls.FrZMod

open EthCryptographySpecs Bls Kzg
open private cosetShiftForCell from EthCryptographySpecs.Kzg.Cells

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

theorem cosetShift_eq (c : Nat) (hc : c < 128) :
    cosetShiftForCell c = .ok (Model.cosetShift c) := by
  simp only [cosetShiftForCell, show Constants.CELLS_PER_EXT_BLOB = 128 from rfl,
    show ¬ c ≥ 128 from Nat.not_le.mpr hc, if_false,
    show Constants.FIELD_ELEMENTS_PER_EXT_BLOB = 8192 from rfl,
    show Constants.FIELD_ELEMENTS_PER_CELL = 64 from rfl,
    Model.cosetShift]
  rfl

theorem weighted_powers_eq (indices : Array Nat) (powers : Array Fr)
    (hi : ∀ c ∈ indices, c < 128) :
    ((Array.range indices.size).mapM fun k => do
      let shift ← cosetShiftForCell indices[k]!
      pure (powers[k]! * (shift ^ Fr.ofNat Constants.FIELD_ELEMENTS_PER_CELL)) :
        Except KzgError (Array Fr)) =
      .ok ((Array.range indices.size).map fun k =>
        powers[k]! * Fr.powNat (Model.cosetShift indices[k]!) 64) := by
  apply array_mapM_ok
  intro k hk
  have hkb : k < indices.size := by simpa using hk
  have hc : indices[k]! < 128 := by
    rw [getElem!_pos indices k hkb]
    exact hi _ (Array.getElem_mem hkb)
  rw [cosetShift_eq _ hc]
  simp only [Bind.bind, Except.bind, Pure.pure, Except.pure,
    Constants.FIELD_ELEMENTS_PER_CELL, Fr.hpow_ofNat_eq_pow _ (by decide : 64 < Fr.modulus),
    ← Fr.powNat_eq_pow]

end LeanBlsSimd.Kzg.ModelPairing
