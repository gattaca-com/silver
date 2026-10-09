import LeanBlsSimd.Constants
import LeanBlsSimd.Spec.Fp2
import LeanBlsSimd.Spec.G2Curve
import LeanBlsSimd.Spec.Scott
import LeanBlsSimd.Spec.Sqrt
import LeanBlsSimd.Spec.G2Group
import LeanBlsSimd.Proofs.Pow
import LeanBlsSimd.Proofs.Convert
import LeanBlsSimd.Proofs.Kernel

/-!
Fails the build if any theorem under `LeanBlsSimd` uses an axiom outside `propext`,
`Classical.choice`, `Quot.sound` and `acceptedAxioms`. `controls/AxiomLog.lean` lists each
theorem's axioms; it is the source of `axioms.txt`.

An allow-list, because native evaluation enters a proof under more than one name. On Lean v4.29.1
and v4.31.0, `native_decide` and `bv_decide` each add a fresh axiom per use. Their names are
`<theorem>._native.native_decide.ax_…` and `<theorem>._native.bv_decide.ax_…`. A direct
`Lean.ofReduceBool` adds `Lean.ofReduceBool` and `Lean.trustCompiler`.

The check runs Lean's own `CollectAxioms.collect` over all theorems with one shared visited set,
which gives the exact union of their axioms and walks Mathlib's shared dependencies once. A union
holding a disallowed axiom fails the check. To name the offenders, it walks that closure's edges
backwards from the disallowed axioms, then collects each theorem reached separately.
-/

open Lean Elab Command

namespace LeanBlsSimd

/-- The native axioms accepted in the trust base, by exact name. Each entry is a decision to
trust one evaluation, so it belongs next to a note saying why. -/
def acceptedAxioms : List Name := []

def libraryTheorems : CommandElabM (Array Name) := do
  let theorems := (← getEnv).constants.fold (init := #[]) fun found name info =>
    if (`LeanBlsSimd).isPrefixOf name && !name.isInternal && info matches .thmInfo _ then
      found.push name
    else found
  if theorems.isEmpty then throwError "no theorems under LeanBlsSimd"
  return theorems.qsort (·.toString < ·.toString)

/-- The constants `CollectAxioms.collect` visits from `c`. -/
def collectDeps (env : Environment) (c : Name) : Array Name :=
  let used (e : Expr) := e.getUsedConstants
  match env.checked.get.find? c with
  | some (.axiomInfo v) => used v.type
  | some (.defnInfo v) => used v.type ++ used v.value
  | some (.thmInfo v) => used v.type ++ used v.value
  | some (.opaqueInfo v) => used v.type ++ used v.value
  | some (.ctorInfo v) => used v.type
  | some (.recInfo v) => used v.type
  | some (.inductInfo v) => used v.type ++ v.ctors.toArray
  | _ => #[]

/-- The constants of `visited` from which `collect` reaches one of `targets`, found by walking
the dependency edges backwards. Exact on cycles, unlike a per-constant cache. -/
def reaching (env : Environment) (visited : NameSet) (targets : Array Name) : NameSet := Id.run do
  let mut users : NameMap (Array Name) := {}
  for c in visited do
    for d in collectDeps env c do
      users := users.insert d (((users.get? d).getD #[]).push c)
  let mut found : NameSet := {}
  let mut todo := targets
  while h : todo.size > 0 do
    let c := todo[todo.size - 1]
    todo := todo.pop
    unless found.contains c do
      found := found.insert c
      todo := todo ++ (users.get? c).getD #[]
  return found

/-- Fails unless every theorem under `LeanBlsSimd` uses only the standard axioms and `accepted`. -/
def checkAxioms (accepted : List Name) : CommandElabM Unit := do
  let allowed := [``propext, ``Classical.choice, ``Quot.sound] ++ accepted
  let theorems ← libraryTheorems
  let env ← getEnv
  let (_, union) := ((theorems.forM CollectAxioms.collect).run env).run {}
  if union.axioms.all allowed.contains then
    logInfo m!"{theorems.size} theorems; axioms used: {union.axioms.toList}"
    return
  let disallowed := union.axioms.filter (!allowed.contains ·)
  let suspects := reaching env union.visited disallowed
  let mut offenders := #[]
  for name in theorems.filter suspects.contains do
    let extra := (← collectAxioms name).filter (!allowed.contains ·)
    unless extra.isEmpty do offenders := offenders.push m!"{name} depends on {extra.toList}"
  if offenders.isEmpty then
    throwError m!"no theorem found to reach the disallowed axioms {disallowed.toList}"
  throwError MessageData.joinSep offenders.toList "\n"

def logAxioms : CommandElabM Unit := do
  for name in ← libraryTheorems do
    logInfo m!"{name}: {(← collectAxioms name).toList}"

elab "#assert_standard_axioms" : command => checkAxioms acceptedAxioms

elab "#log_axioms" : command => logAxioms

end LeanBlsSimd

#assert_standard_axioms
