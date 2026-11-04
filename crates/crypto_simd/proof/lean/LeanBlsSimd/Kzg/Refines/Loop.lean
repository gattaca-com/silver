import LeanBlsSimd.Refines.Basic

/-!
# Range steps in KZG loops

`next_lt` and `next_ge` distinguish the advancing and exhausted cases of Aeneas's range
iterator. `simp_body` unfolds a loop body using a supplied range-step equation.
-/

open Aeneas Aeneas.Std Result ControlFlow

namespace LeanBlsSimd.Kzg.Refinement

open core.iter.range core.ops.range

theorem next_lt (r : Range Usize) (h : r.start.val < r.end.val) :
    ∃ r' : Range Usize, r'.start.val = r.start.val + 1 ∧ r'.end = r.end ∧
      IteratorRange.next StepUsize r = ok (some r.start, r') := by
  obtain ⟨⟨o, r'⟩, hnext, ho, hs, he⟩ := spec_imp_exists (IteratorRange.next_Usize_some_spec r h)
  subst ho
  exact ⟨r', hs, he, hnext⟩

theorem next_ge (r : Range Usize) (h : r.end.val ≤ r.start.val) :
    IteratorRange.next StepUsize r = ok (none, r) := by
  obtain ⟨⟨o, r'⟩, hnext, ho, hr⟩ := spec_imp_exists (IteratorRange.next_Usize_none_spec r h)
  subst ho hr
  exact hnext

/-- Unfolds one iteration of a loop body `body` whose range step is `hn`. -/
macro "simp_body" body:ident hn:ident : tactic =>
  `(tactic| (simp only [$body:ident, $hn:ident, bind_tc_ok, bind_ok, Function.uncurry_apply_pair, Aeneas.Std.uncurry_apply_pair]; try dsimp only))

end LeanBlsSimd.Kzg.Refinement
