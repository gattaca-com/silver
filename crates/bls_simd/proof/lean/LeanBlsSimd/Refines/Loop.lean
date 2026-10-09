import LeanBlsSimd.Extracted.Funs

/-!
# Range loops

Aeneas translates `for j in 0..n` into a `loop` over a `Range Usize`. When each iteration of the
body performs one step `g`, `loop_range` equates the loop with `(List.finRange n).foldl g`.
`loop_range_inv` also threads an invariant `inv j` that holds before step `j`.
-/

open Aeneas Aeneas.Std Result ControlFlow

namespace LeanBlsSimd

open core.iter.range core.ops.range

theorem next_lt (r : Range Usize) (h : r.start.val < r.end.val) :
    ∃ r' : Range Usize, r'.start.val = r.start.val + 1 ∧ r'.end = r.end ∧
      IteratorRange.next StepUsize r = ok (some r.start, r') := by
  have hs := core.num.checked_add_UScalar_bv_spec r.start 1#usize
  cases hc : core.num.checked_add_UScalar r.start 1#usize with
  | none =>
    simp only [hc] at hs
    have := r.end.hBounds
    simp only [UScalar.max, UScalarTy.numBits] at hs this
    simp at hs
    omega
  | some n =>
    simp only [hc] at hs
    refine ⟨{ r with start := n }, by simp [hs.2.1], rfl, ?_⟩
    simp only [IteratorRange.next, liftFun2, bind_tc_ok]
    simp [core.cmp.impls.PartialOrdUsize.lt, h, StepUsize.forward_checked, Usize.checked_add, hc,
      core.clone.impls.CloneUsize.clone]

theorem next_ge (r : Range Usize) (h : r.end.val ≤ r.start.val) :
    IteratorRange.next StepUsize r = ok (none, r) := by
  simp only [IteratorRange.next, liftFun2, bind_tc_ok]
  simp [core.cmp.impls.PartialOrdUsize.lt, Nat.not_lt.mpr h]

/-- Unfolds one iteration of a loop body `body` whose range step is `hn`. -/
macro "simp_body" body:ident hn:ident : tactic =>
  `(tactic| simp only [$body:ident, $hn:ident, bind_tc_ok, Function.uncurry_apply_pair])

theorem loop_range_inv {S β M : Type} {n : ℕ}
    (body : Range Usize × S → Result (ControlFlow (Range Usize × S) β))
    (stop : Usize) (hstop : stop.val = n) (enc : M → S) (g : M → Fin n → M) (fin : M → β)
    (inv : ℕ → M → Prop) (hinv : ∀ m (j : Fin n), inv j m → inv (j + 1) (g m j))
    (hdone : ∀ (r : Range Usize) (m : M), r.end = stop → r.start.val = n → inv n m →
      IteratorRange.next StepUsize r = ok (none, r) → body (r, enc m) = ok (done (fin m)))
    (hcont : ∀ (r r' : Range Usize) (m : M) (j : Fin n), r.end = stop → r.start.val = j.val →
      r'.end = stop → r'.start.val = j.val + 1 → inv j m →
      IteratorRange.next StepUsize r = ok (some r.start, r') →
      body (r, enc m) = ok (cont (r', enc (g m j))))
    (start : Usize) (m : M) (hstart : start.val ≤ n) (hm : inv start.val m) :
    loop body ({ start, «end» := stop }, enc m) =
      ok (fin (((List.finRange n).drop start.val).foldl g m)) := by
  induction hk : n - start.val generalizing start m with
  | zero =>
    have hs : start.val = n := by omega
    have hnext := next_ge { start, «end» := stop } (by simp [hstop, hs])
    rw [loop.eq_1, hdone _ m rfl hs (hs ▸ hm) hnext]
    simp [hs]
  | succ k ih =>
    have hlt : start.val < n := by omega
    obtain ⟨r', hr's, hr'e, hnext⟩ := next_lt { start, «end» := stop } (by simp [hstop, hlt])
    have hbody := hcont _ r' m ⟨start.val, hlt⟩ rfl rfl hr'e hr's hm hnext
    rw [loop.eq_1, hbody]
    simp only
    obtain ⟨s', e'⟩ := r'
    simp only at hr's hr'e
    subst hr'e
    rw [ih s' (g m ⟨start.val, hlt⟩) (by omega) (hr's ▸ hinv m ⟨start.val, hlt⟩ hm)
      (by omega)]
    rw [List.drop_eq_getElem_cons (l := List.finRange n) (i := start.val) (by simp [hlt])]
    simp [hr's]

theorem loop_range {S β M : Type} {n : ℕ}
    (body : Range Usize × S → Result (ControlFlow (Range Usize × S) β))
    (stop : Usize) (hstop : stop.val = n) (enc : M → S) (g : M → Fin n → M) (fin : M → β)
    (m : M) (target : β)
    (hdone : ∀ (r : Range Usize) (m : M), r.end = stop → r.start.val = n →
      IteratorRange.next StepUsize r = ok (none, r) → body (r, enc m) = ok (done (fin m)))
    (hcont : ∀ (r r' : Range Usize) (m : M) (j : Fin n), r.end = stop → r.start.val = j.val →
      r'.end = stop → r'.start.val = j.val + 1 →
      IteratorRange.next StepUsize r = ok (some r.start, r') →
      body (r, enc m) = ok (cont (r', enc (g m j))))
    (hfin : fin ((List.finRange n).foldl g m) = target) :
    loop body ({ start := 0#usize, «end» := stop }, enc m) = ok target := by
  rw [loop_range_inv body stop hstop enc g fin (fun _ _ => True) (fun _ _ _ => trivial)
    (fun r m he hs _ hn => hdone r m he hs hn)
    (fun r r' m j he hs he' hs' _ hn => hcont r r' m j he hs he' hs' hn) 0#usize m (by simp)
    trivial]
  simp [hfin]

theorem foldl_finRange_inv {M : Type} {n : ℕ} (g : M → Fin n → M) (inv : ℕ → M → Prop)
    (hinv : ∀ m (j : Fin n), inv j m → inv (j + 1) (g m j)) (m : M) (hm : inv 0 m) :
    inv n ((List.finRange n).foldl g m) := by
  suffices h : ∀ k (m : M), k ≤ n → inv k m → inv n (((List.finRange n).drop k).foldl g m) by
    simpa using h 0 m (Nat.zero_le _) hm
  intro k
  induction hk : n - k generalizing k with
  | zero =>
    intro m hkn hm
    have : k = n := by omega
    subst this; simpa using hm
  | succ d ih =>
    intro m hkn hm
    have hlt : k < n := by omega
    rw [List.drop_eq_getElem_cons (by simp [hlt])]
    simp only [List.foldl_cons, List.getElem_finRange]
    exact ih (k + 1) (by omega) _ (by omega) (hinv m ⟨k, hlt⟩ hm)

end LeanBlsSimd
