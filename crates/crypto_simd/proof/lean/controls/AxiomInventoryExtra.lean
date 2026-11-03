import LeanBlsSimd

/-! A declared axiom is rejected even when no checked theorem uses it. -/

axiom InventoryControl.extra : Nat

/--
error: unexpected axiom InventoryControl.extra (module controls.AxiomInventoryExtra)
-/
#guard_msgs (error, drop info) in
run_cmd LeanBlsSimd.AxiomInventory.check
