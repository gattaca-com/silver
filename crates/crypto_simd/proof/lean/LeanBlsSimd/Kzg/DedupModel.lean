import LeanBlsSimd.Kzg.Model
import Aeneas
import Mathlib.Data.List.Nodup

namespace LeanBlsSimd.Kzg

local instance : LawfulBEq ByteArray where
  rfl := by
    intro a
    change (a.data == a.data) = true
    simp
  eq_of_beq := by
    intro a b h
    apply ByteArray.ext
    exact eq_of_beq h

private def dedupStep (state : Array ByteArray × Array Nat) (c : ByteArray) :=
  match state.1.idxOf? c with
  | some i => (state.1, state.2.push i)
  | none => (state.1.push c, state.2.push state.1.size)

private theorem dedup_fold_sizes (cs : List ByteArray) (u : Array ByteArray) (ci : Array Nat) :
    u.size ≤ (cs.foldl dedupStep (u, ci)).1.size ∧
    (cs.foldl dedupStep (u, ci)).1.size ≤ u.size + cs.length ∧
    (cs.foldl dedupStep (u, ci)).2.size = ci.size + cs.length := by
  induction cs generalizing u ci with
  | nil => simp
  | cons c cs ih =>
    simp only [List.foldl_cons, dedupStep]
    cases hs : u.idxOf? c with
    | none =>
      have h := ih (u.push c) (ci.push u.size)
      simp only [Array.size_push, List.length_cons] at h ⊢
      omega
    | some i =>
      have h := ih u (ci.push i)
      simp only [Array.size_push, List.length_cons] at h ⊢
      omega

private theorem dedup_fold_mem (cs : List ByteArray) (u : Array ByteArray)
    (ci : Array Nat) (b : ByteArray) :
    b ∈ (cs.foldl dedupStep (u, ci)).1 ↔ b ∈ u ∨ b ∈ cs := by
  induction cs generalizing u ci with
  | nil => simp
  | cons c cs ih =>
    simp only [List.foldl_cons, dedupStep]
    cases hs : u.idxOf? c with
    | none => simp [ih, or_assoc, or_left_comm, or_comm]
    | some i =>
      have hc : c ∈ u := Array.isSome_idxOf?.mp (by simp [hs])
      rw [ih]
      simp only [List.mem_cons]
      constructor
      · tauto
      · intro hb
        rcases hb with hb | rfl | hb
        · exact Or.inl hb
        · exact Or.inl hc
        · exact Or.inr hb

private theorem dedup_fold_indices (cs : List ByteArray) (u : Array ByteArray)
    (ci : Array Nat) (hci : ∀ i ∈ ci, i < u.size) :
    ∀ i ∈ (cs.foldl dedupStep (u, ci)).2,
      i < (cs.foldl dedupStep (u, ci)).1.size := by
  induction cs generalizing u ci with
  | nil => simpa using hci
  | cons c cs ih =>
    simp only [List.foldl_cons, dedupStep]
    cases hs : u.idxOf? c with
    | none =>
      apply ih
      intro i hi
      simp only [Array.mem_push, Array.size_push] at hi ⊢
      rcases hi with hi | rfl
      · exact Nat.lt_trans (hci i hi) (Nat.lt_succ_self _)
      · omega
    | some j =>
      have hj : j < u.size := by
        unfold Array.idxOf? at hs
        cases hf : u.finIdxOf? c with
        | none => simp [hf] at hs
        | some i =>
          simp only [hf, Option.map_some, Option.some.injEq] at hs
          exact hs ▸ i.isLt
      apply ih
      intro i hi
      simp only [Array.mem_push] at hi
      rcases hi with hi | rfl
      · exact hci i hi
      · exact hj

private theorem dedup_fold_nodup (cs : List ByteArray) (u : Array ByteArray)
    (ci : Array Nat) (hu : u.toList.Nodup) :
    (cs.foldl dedupStep (u, ci)).1.toList.Nodup := by
  induction cs generalizing u ci with
  | nil => exact hu
  | cons c cs ih =>
    simp only [List.foldl_cons, dedupStep]
    cases hs : u.idxOf? c with
    | none =>
      apply ih
      have hc : c ∉ u := Array.idxOf?_eq_none_iff.mp hs
      simpa using (List.Nodup.concat (by simpa using hc) hu)
    | some i => exact ih u (ci.push i) hu

theorem deduplicate_sizes (cs : Array ByteArray) :
    (Model.deduplicate cs).1.size ≤ cs.size ∧ (Model.deduplicate cs).2.size = cs.size := by
  have h := dedup_fold_sizes cs.toList #[] #[]
  simpa [Model.deduplicate, ← Array.foldl_toList, dedupStep] using h.2

theorem deduplicate_mem (cs : Array ByteArray) (b : ByteArray) :
    b ∈ (Model.deduplicate cs).1 ↔ b ∈ cs := by
  simpa [Model.deduplicate, ← Array.foldl_toList, dedupStep] using
    dedup_fold_mem cs.toList #[] #[] b

theorem deduplicate_indices (cs : Array ByteArray) :
    ∀ i ∈ (Model.deduplicate cs).2, i < (Model.deduplicate cs).1.size := by
  simpa [Model.deduplicate, ← Array.foldl_toList, dedupStep] using
    dedup_fold_indices cs.toList #[] #[] (by simp)

theorem deduplicate_nodup (cs : Array ByteArray) :
    (Model.deduplicate cs).1.toList.Nodup := by
  simpa [Model.deduplicate, ← Array.foldl_toList, dedupStep] using
    dedup_fold_nodup cs.toList #[] #[] (by simp)

theorem deduplicate_all (cs : Array ByteArray) (p : ByteArray → Bool) :
    (Model.deduplicate cs).1.all p = cs.all p := by
  apply Bool.eq_iff_iff.mpr
  simp only [Array.all_eq_true']
  constructor
  · intro h b hb
    exact h b ((deduplicate_mem cs b).mpr hb)
  · intro h b hb
    exact h b ((deduplicate_mem cs b).mp hb)

end LeanBlsSimd.Kzg
