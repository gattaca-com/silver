import Lean

axiom LeanBlsSimd.cycleAx : Nat

namespace GuardCycleFixture

def CycleProp : Prop := LeanBlsSimd.cycleAx = LeanBlsSimd.cycleAx

-- These names select the module-export order exercised by the imported-cache control.
inductive CycleType9 : Type where
  | mk (h : CycleProp) : CycleType9

theorem cycleControl9 : Nonempty (CycleType9 → CycleType9) := ⟨id⟩

end GuardCycleFixture
