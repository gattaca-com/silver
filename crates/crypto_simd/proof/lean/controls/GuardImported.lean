import controls.GuardCycle.Imported
import LeanBlsSimd.Axioms

/-!
The invariant requires rejection of disallowed axioms reached through imported Silver constructor cycles.
Lean 4.35's exported per-declaration lists can miss these dependencies.
The direct module-owned walk must reject both a type-only use and an explicit constructor use.
-/

/--
error: LeanBlsSimd.importedConstructorCycleControl depends on [LeanBlsSimd.cycleAx]
LeanBlsSimd.importedCycleControl depends on [LeanBlsSimd.cycleAx]
-/
#guard_msgs (error, drop info) in
#assert_standard_axioms

#guard_msgs (error, drop info) in
run_cmd LeanBlsSimd.assertAxioms [``LeanBlsSimd.cycleAx]
