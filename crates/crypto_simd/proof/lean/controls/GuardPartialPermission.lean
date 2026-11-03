import LeanBlsSimd.Axioms

/-! Explicit permission for one dependency must not permit another dependency of the same theorem. -/

axiom LeanBlsSimd.partialLeftAx : Nat
axiom LeanBlsSimd.partialRightAx : Nat

theorem LeanBlsSimd.partialPermissionControl :
    (LeanBlsSimd.partialLeftAx, LeanBlsSimd.partialRightAx) =
      (LeanBlsSimd.partialLeftAx, LeanBlsSimd.partialRightAx) := rfl

/--
error: LeanBlsSimd.partialPermissionControl depends on [LeanBlsSimd.partialRightAx]
-/
#guard_msgs (error, drop info) in
run_cmd LeanBlsSimd.assertAxioms [``LeanBlsSimd.partialLeftAx]

#guard_msgs (error, drop info) in
run_cmd LeanBlsSimd.assertAxioms [``LeanBlsSimd.partialLeftAx, ``LeanBlsSimd.partialRightAx]
