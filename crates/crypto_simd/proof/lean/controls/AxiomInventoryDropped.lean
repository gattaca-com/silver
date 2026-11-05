import LeanBlsSimd
import Aeneas.Std.Core.Panic

/-! Reimporting a dropped dependency axiom must fail the production inventory. -/

/--
error: unexpected axiom Aeneas.Std.core.panic.panic_info.PanicInfo (module Aeneas.Std.Core.Panic)
-/
#guard_msgs (error, drop info) in
run_cmd LeanBlsSimd.AxiomInventory.check
