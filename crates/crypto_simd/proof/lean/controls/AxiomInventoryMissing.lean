import LeanBlsSimd.AxiomInventory

/-! A Lean-only environment lacks all three pinned Aeneas declarations. -/

/--
error: missing axiom Aeneas.Data.ListN.Test.E2 (expected module Aeneas.Data.ListN)
missing axiom Aeneas.Data.ListN.Test.E3 (expected module Aeneas.Data.ListN)
missing axiom Aeneas.Std.core.slice.Slice.get_unchecked_SliceIndexUsizeSlice_spec (expected module Aeneas.Std.Slice)
-/
#guard_msgs (error, drop info) in
run_cmd LeanBlsSimd.AxiomInventory.check
