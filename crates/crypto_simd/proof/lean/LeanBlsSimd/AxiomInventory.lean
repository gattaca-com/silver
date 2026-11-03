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
  -- Rust unchecked-slice indexing contract.
  pin "Aeneas.Std.core.slice.Slice.get_unchecked_SliceIndexUsizeSlice_spec" "Aeneas.Std.Slice",
  -- Classical choice is a standard proof axiom.
  pin "Classical.choice" "Init.Prelude",
  -- Lean compiler primitive for quotient-lift erasure.
  pin "Quot.lcInv" "Init.Prelude",
  -- Quotient soundness is a standard proof axiom.
  pin "Quot.sound" "Init.Prelude",
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
