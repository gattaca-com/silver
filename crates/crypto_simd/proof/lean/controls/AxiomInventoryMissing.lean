import LeanBlsSimd.AxiomInventory

/-! A Lean-only environment lacks all fifteen pinned Aeneas declarations. -/

/--
error: missing axiom Aeneas.Data.ListN.Test.E2 (expected module Aeneas.Data.ListN)
missing axiom Aeneas.Data.ListN.Test.E3 (expected module Aeneas.Data.ListN)
missing axiom Aeneas.Std.core.panic.panic_info.PanicInfo (expected module Aeneas.Std.Core.Panic)
missing axiom Aeneas.Std.core.pin.Pin (expected module Aeneas.Std.Core.Pin)
missing axiom Aeneas.Std.core.pin.helper.PinHelper (expected module Aeneas.Std.Core.Pin)
missing axiom Aeneas.Std.core.slice.Slice.get_unchecked_SliceIndexUsizeSlice_spec (expected module Aeneas.Std.Slice)
missing axiom Aeneas.Std.core.sync.atomic.AtomicBool (expected module Aeneas.Std.Core.Atomic)
missing axiom Aeneas.Std.core.sync.atomic.AtomicU32 (expected module Aeneas.Std.Core.Atomic)
missing axiom _private.Aeneas.Command.Decompose.TestsRec.0.Aeneas.Command.Decompose.TestsRec.recAxOp (expected module Aeneas.Command.Decompose.TestsRec)
missing axiom _private.Aeneas.Tactic.Solver.BvTac.Lemmas.0.Aeneas.Std.U128.bv_mod_size._native.bv_decide.ax_1_5 (expected module Aeneas.Tactic.Solver.BvTac.Lemmas)
missing axiom _private.Aeneas.Tactic.Solver.BvTac.Lemmas.0.Aeneas.Std.U16.bv_mod_size._native.bv_decide.ax_1_5 (expected module Aeneas.Tactic.Solver.BvTac.Lemmas)
missing axiom _private.Aeneas.Tactic.Solver.BvTac.Lemmas.0.Aeneas.Std.U32.bv_mod_size._native.bv_decide.ax_1_5 (expected module Aeneas.Tactic.Solver.BvTac.Lemmas)
missing axiom _private.Aeneas.Tactic.Solver.BvTac.Lemmas.0.Aeneas.Std.U64.bv_mod_size._native.bv_decide.ax_1_5 (expected module Aeneas.Tactic.Solver.BvTac.Lemmas)
missing axiom _private.Aeneas.Tactic.Solver.BvTac.Lemmas.0.Aeneas.Std.U8.bv_mod_size._native.bv_decide.ax_1_5 (expected module Aeneas.Tactic.Solver.BvTac.Lemmas)
missing axiom _private.Aeneas.Tactic.Step.StepArraySpec.0.Aeneas.StepArraySpec.Tests.const_array_spec._native.native_decide.ax_1_1 (expected module Aeneas.Tactic.Step.StepArraySpec)
-/
#guard_msgs (error, drop info) in
run_cmd LeanBlsSimd.AxiomInventory.check
