import LeanBlsSimd.Kzg.Model
import EthLib.Cryptography.Proofs.Kzg.Polynomials
import Mathlib.Data.List.Forall2
import Aeneas

open EthLib.Cryptography Bls Kzg

open private bytesBEToNatAux_linear
  from EthLib.Cryptography.Proofs.Kzg.Polynomials

namespace LeanBlsSimd.Kzg

private theorem bytesBEToNatAux_injective (xs ys : List UInt8)
    (hlen : xs.length = ys.length)
    (hval : bytesBEToNatAux 0 xs = bytesBEToNatAux 0 ys) : xs = ys := by
  induction xs generalizing ys with
  | nil => simpa using hlen.symm
  | cons x xs ih =>
    cases ys with
    | nil => simp at hlen
    | cons y ys =>
      have hlen' : xs.length = ys.length := by simpa using hlen
      have hx : bytesBEToNatAux 0 xs < 256 ^ xs.length := by
        simpa [bytesBEToNat] using bytesBEToNat_lt ⟨xs.toArray⟩
      have hy : bytesBEToNatAux 0 ys < 256 ^ xs.length := by
        simpa [bytesBEToNat, hlen'] using bytesBEToNat_lt ⟨ys.toArray⟩
      simp only [bytesBEToNatAux, Nat.zero_shiftLeft, Nat.zero_or] at hval
      rw [bytesBEToNatAux_linear x.toNat xs, bytesBEToNatAux_linear y.toNat ys,
        ← hlen'] at hval
      have hxy : x.toNat = y.toNat := by
        have hd := congrArg (fun n => n / 256 ^ xs.length) hval
        simpa [Nat.add_div, Nat.div_eq_of_lt hx, Nat.div_eq_of_lt hy,
          Nat.mod_eq_of_lt hx, Nat.mod_eq_of_lt hy,
          Nat.not_le.mpr hx, Nat.not_le.mpr hy] using hd
      have ht : bytesBEToNatAux 0 xs = bytesBEToNatAux 0 ys := by
        rw [hxy] at hval
        exact Nat.add_left_cancel hval
      have he : x = y := UInt8.toNat_inj.mp hxy
      simp only [he, ih ys hlen' ht]

theorem bytesBEToNat_injective_of_size_eq (a b : ByteArray)
    (hlen : a.size = b.size) (hval : bytesBEToNat a = bytesBEToNat b) : a = b := by
  apply ByteArray.ext
  apply Array.toList_inj.mp
  exact bytesBEToNatAux_injective _ _ (by simpa using hlen) hval

theorem intToBytesBE_bytesBEToNat (b : ByteArray) :
    intToBytesBE (bytesBEToNat b) b.size = b := by
  apply bytesBEToNat_injective_of_size_eq
  · change (Array.ofFn (n := b.size) _).size = b.size
    exact Array.size_ofFn
  · exact bytesBEToNat_intToBytesBE_of_lt (bytesBEToNat_lt b)

theorem blsFieldToBytes_of_decode (b : ByteArray) (f : Fr)
    (h : bytesToBlsField b = .ok f) : blsFieldToBytes f = b := by
  obtain ⟨hs, hv, _⟩ := bytesToBlsField_ok h
  change intToBytesBE f.val 32 = b
  rw [hv, ← show b.size = 32 from hs]
  exact intToBytesBE_bytesBEToNat b

private theorem list_mapM_ok {α β ε : Type} (f : α → Except ε β)
    (xs : List α) (ys : List β) (h : xs.mapM f = .ok ys) :
    List.Forall₂ (fun x y => f x = .ok y) xs ys := by
  induction xs generalizing ys with
  | nil =>
    simp only [List.mapM_nil, pure, Except.pure, Except.ok.injEq] at h
    subst ys
    exact .nil
  | cons x xs ih =>
    cases hx : f x with
    | error e => simp [List.mapM_cons, hx, Bind.bind, Except.bind] at h
    | ok y =>
      cases ht : xs.mapM f with
      | error e => simp [List.mapM_cons, hx, ht, Bind.bind, Except.bind] at h
      | ok zs =>
        simp only [List.mapM_cons, hx, ht, bind, Except.bind, pure,
          Except.pure, Except.ok.injEq] at h
        subst ys
        exact .cons hx (ih zs ht)

theorem array_mapM_ok {α β ε : Type} (f : α → Except ε β)
    (xs : Array α) (ys : Array β) (h : xs.mapM f = .ok ys) :
    List.Forall₂ (fun x y => f x = .ok y) xs.toList ys.toList := by
  rw [Array.mapM_eq_mapM_toList] at h
  cases hs : xs.toList.mapM f with
  | error e => simp [hs] at h
  | ok zs =>
    simp only [hs, Functor.map, Except.map, Except.ok.injEq] at h
    subst ys
    simpa using list_mapM_ok f xs.toList zs hs

theorem array_mapM_ok_size {α β ε : Type} (f : α → Except ε β)
    (xs : Array α) (ys : Array β) (h : xs.mapM f = .ok ys) : ys.size = xs.size := by
  simpa using (array_mapM_ok f xs ys h).length_eq.symm

theorem array_mapM_ok_get {α β ε : Type} [Inhabited α] [Inhabited β]
    (f : α → Except ε β) (xs : Array α) (ys : Array β)
    (h : xs.mapM f = .ok ys) (i : Nat) (hi : i < xs.size) :
    f xs[i]! = .ok ys[i]! := by
  have hs := array_mapM_ok_size f xs ys h
  have hy : i < ys.size := by omega
  have hg := (array_mapM_ok f xs ys h).get (by simpa using hi) (by simpa using hy)
  simpa [getElem!_pos xs i hi, getElem!_pos ys i hy] using hg

private theorem foldl_of_forall₂ {α β γ : Type} {R : α → β → Prop}
    {xs : List α} {ys : List β} (h : List.Forall₂ R xs ys)
    (f : γ → α → γ) (g : γ → β → γ)
    (hf : ∀ x y, R x y → ∀ acc, f acc x = g acc y) (init : γ) :
    xs.foldl f init = ys.foldl g init := by
  induction h generalizing init with
  | nil => rfl
  | cons hxy htail ih =>
    simp only [List.foldl_cons, hf _ _ hxy]
    exact ih _

private theorem join_cell_chunks (cell : Cell) (n : Nat) :
    (List.range n).foldl
      (fun b i => b ++ cell.extract (32*i) (32*(i+1))) ByteArray.empty =
        cell.extract 0 (32*n) := by
  induction n with
  | zero => simp
  | succ n ih =>
    simp only [List.range_succ, List.foldl_append, ih, List.foldl_cons, List.foldl_nil]
    rw [ByteArray.extract_append_extract]
    congr 1
    omega

theorem cell_encoding_of_decode (cell : Cell) (evals : CosetEvals)
    (h : cellToCosetEvals cell = .ok evals) :
    evals.foldl (fun b f => b ++ blsFieldToBytes f) ByteArray.empty = cell := by
  unfold cellToCosetEvals at h
  split at h
  · cases h
  · rename_i hs
    have hr := array_mapM_ok _ _ _ h
    have hfold := foldl_of_forall₂ hr
      (fun b i => b ++ cell.extract (32*i) (32*(i+1)))
      (fun b f => b ++ blsFieldToBytes f) (by
        intro i f hf acc
        dsimp only at hf
        simp only [Kzg.Constants.BYTES_PER_FIELD_ELEMENT,
          Nat.mul_comm i 32, Nat.mul_comm (i+1) 32] at hf
        cases hd : bytesToBlsField (cell.extract (32*i) (32*(i+1))) with
        | error e => rw [hd] at hf; cases hf
        | ok g =>
          rw [hd] at hf
          cases hf
          dsimp only
          rw [blsFieldToBytes_of_decode _ _ hd]) ByteArray.empty
    rw [← Array.foldl_toList, ← hfold]
    simp only [Array.toList_range, Kzg.Constants.FIELD_ELEMENTS_PER_CELL]
    rw [join_cell_chunks]
    have hsize : cell.size = 2048 := by
      simpa [Kzg.Constants.BYTES_PER_CELL] using hs
    simp [← hsize]

theorem cell_encoding_of_decode_prefix (cell : Cell) (evals : CosetEvals)
    (h : cellToCosetEvals cell = .ok evals) (initial : ByteArray) :
    evals.foldl (fun b f => b ++ blsFieldToBytes f) initial = initial ++ cell := by
  have hh := List.foldl_hom (fun b => initial ++ b)
    (g₁ := fun b f => b ++ blsFieldToBytes f)
    (g₂ := fun b f => b ++ blsFieldToBytes f)
    (l := evals.toList) (init := ByteArray.empty)
    (by intro x y; exact ByteArray.append_assoc)
  simpa only [ByteArray.append_empty, Array.foldl_toList,
    cell_encoding_of_decode cell evals h] using hh

private theorem foldl_congr_mem {α β : Type} (xs : List α) (f g : β → α → β)
    (hf : ∀ x ∈ xs, ∀ acc, f acc x = g acc x) (init : β) :
    xs.foldl f init = xs.foldl g init := by
  induction xs generalizing init with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.foldl_cons, hf x (by simp)]
    exact ih (fun x hx => hf x (by simp [hx])) _

theorem challenge_preimage_spec (unique : Array Bytes48)
    (ci indices : Array Nat) (cells : Array Cell) (ps : Array Bytes48)
    (evals : Array CosetEvals)
    (hlen : ci.size = indices.size ∧ cells.size = indices.size ∧ ps.size = indices.size)
    (hdecode : cells.mapM cellToCosetEvals = .ok evals) :
    Fr.hashToBlsField (Model.challengePreimage unique ci indices cells ps) =
      computeVerifyCellKzgProofBatchChallenge unique ci indices evals ps := by
  have hs : evals.size = indices.size :=
    (array_mapM_ok_size _ _ _ hdecode).trans hlen.2.1
  unfold Model.challengePreimage computeVerifyCellKzgProofBatchChallenge
  simp only [Constants.FIELD_ELEMENTS_PER_BLOB, Constants.FIELD_ELEMENTS_PER_CELL, hs]
  congr 1
  simp only [← Array.foldl_toList]
  apply foldl_congr_mem
  intro k hk acc
  have hk' : k < cells.size := by
    simpa [Array.toList_range, List.mem_range, hlen.2.1] using hk
  have hd := array_mapM_ok_get _ _ _ hdecode k hk'
  rw [Array.foldl_toList]
  rw [cell_encoding_of_decode_prefix _ _ hd]

end LeanBlsSimd.Kzg
