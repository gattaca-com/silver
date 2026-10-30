import Lean

/-! The declared-axiom inventory is separate from the per-theorem proof allow-list. -/

open Lean Elab Command

namespace LeanBlsSimd.AxiomInventory

private def pin (declaration origin : String) : Name × Name := (declaration.toName, origin.toName)

/-- Exact declaration names; defining modules explain missing entries. -/
def expected : Array (Name × Name) := #[
  -- Recovery stub from a rejected positivity test.
  pin "Aeneas.Data.ListN.Test.E2" "Aeneas.Data.ListN",
  -- Recovery stub from a rejected positivity test.
  pin "Aeneas.Data.ListN.Test.E3" "Aeneas.Data.ListN",
  -- Opaque Rust panic-information model type.
  pin "Aeneas.Std.core.panic.panic_info.PanicInfo" "Aeneas.Std.Core.Panic",
  -- Opaque Rust Pin model type.
  pin "Aeneas.Std.core.pin.Pin" "Aeneas.Std.Core.Pin",
  -- Opaque Rust Pin helper model type.
  pin "Aeneas.Std.core.pin.helper.PinHelper" "Aeneas.Std.Core.Pin",
  -- Rust unchecked-slice indexing contract.
  pin "Aeneas.Std.core.slice.Slice.get_unchecked_SliceIndexUsizeSlice_spec" "Aeneas.Std.Slice",
  -- Opaque Rust atomic Boolean model type.
  pin "Aeneas.Std.core.sync.atomic.AtomicBool" "Aeneas.Std.Core.Atomic",
  -- Opaque Rust atomic U32 model type.
  pin "Aeneas.Std.core.sync.atomic.AtomicU32" "Aeneas.Std.Core.Atomic",
  -- Classical choice is a standard proof axiom.
  pin "Classical.choice" "Init.Prelude",
  -- Lean compiler primitive for quotient-lift erasure.
  pin "Quot.lcInv" "Init.Prelude",
  -- Quotient soundness is a standard proof axiom.
  pin "Quot.sound" "Init.Prelude",
  -- Aeneas recursive-decomposition test operation.
  pin "_private.Aeneas.Command.Decompose.TestsRec.0.Aeneas.Command.Decompose.TestsRec.recAxOp" "Aeneas.Command.Decompose.TestsRec",
  -- Native certificate for an unsigned scalar bit-vector lemma.
  pin "_private.Aeneas.Tactic.Solver.BvTac.Lemmas.0.Aeneas.Std.U128.bv_mod_size._native.bv_decide.ax_1_5" "Aeneas.Tactic.Solver.BvTac.Lemmas",
  -- Native certificate for an unsigned scalar bit-vector lemma.
  pin "_private.Aeneas.Tactic.Solver.BvTac.Lemmas.0.Aeneas.Std.U16.bv_mod_size._native.bv_decide.ax_1_5" "Aeneas.Tactic.Solver.BvTac.Lemmas",
  -- Native certificate for an unsigned scalar bit-vector lemma.
  pin "_private.Aeneas.Tactic.Solver.BvTac.Lemmas.0.Aeneas.Std.U32.bv_mod_size._native.bv_decide.ax_1_5" "Aeneas.Tactic.Solver.BvTac.Lemmas",
  -- Native certificate for an unsigned scalar bit-vector lemma.
  pin "_private.Aeneas.Tactic.Solver.BvTac.Lemmas.0.Aeneas.Std.U64.bv_mod_size._native.bv_decide.ax_1_5" "Aeneas.Tactic.Solver.BvTac.Lemmas",
  -- Native certificate for an unsigned scalar bit-vector lemma.
  pin "_private.Aeneas.Tactic.Solver.BvTac.Lemmas.0.Aeneas.Std.U8.bv_mod_size._native.bv_decide.ax_1_5" "Aeneas.Tactic.Solver.BvTac.Lemmas",
  -- Native certificate for an Aeneas constant-array test.
  pin "_private.Aeneas.Tactic.Step.StepArraySpec.0.Aeneas.StepArraySpec.Tests.const_array_spec._native.native_decide.ax_1_1" "Aeneas.Tactic.Step.StepArraySpec",
  -- Lean runtime primitive for tagged scalar objects.
  pin "isScalarObj" "Init.Prelude",
  -- Lean compiler primitive for erased type dependencies.
  pin "lcAny" "Init.Prelude",
  -- Lean compiler primitive for cast erasure.
  pin "lcCast" "Init.Prelude",
  -- Lean compiler marker for erased values.
  pin "lcErased" "Init.Prelude",
  -- Lean compiler primitive for proof erasure.
  pin "lcProof" "Init.Prelude",
  -- Lean compiler marker for unreachable code.
  pin "lcUnreachable" "Init.Prelude",
  -- Lean compiler representation of Void.
  pin "lcVoid" "Init.Prelude",
  -- Propositional extensionality is a standard proof axiom.
  pin "propext" "Init.Core",
  -- Lean declares proof placeholders; reported uses remain rejected.
  pin "sorryAx" "Init.Prelude"]

/-- Reject extra or missing axiom declarations, independent of their reported reachability. -/
def check : CommandElabM Unit := do
  let env ← getEnv
  let actual := env.constants.fold (init := #[]) fun found n info =>
    if info matches .axiomInfo _ then found.push n else found
  let expectedNames := expected.map Prod.fst
  let extra := (actual.filter (!expectedNames.contains ·)).qsort (fun a b => a.toString < b.toString)
  let missing := (expected.filter (fun e => !actual.contains e.1)).qsort
    (fun a b => a.1.toString < b.1.toString)
  let mut errors : Array MessageData := #[]
  for n in extra do
    let origin := match env.getModuleIdxFor? n with
      | some i => env.header.modules[i.toNat]!.module
      | none => env.header.mainModule
    errors := errors.push m!"unexpected axiom {n} (module {origin})"
  for (n, origin) in missing do
    errors := errors.push m!"missing axiom {n} (expected module {origin})"
  unless errors.isEmpty do throwError MessageData.joinSep errors.toList "\n"
  logInfo m!"axiom inventory: exactly {actual.size} declarations"

end LeanBlsSimd.AxiomInventory
