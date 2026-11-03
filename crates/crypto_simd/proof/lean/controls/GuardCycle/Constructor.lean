import controls.GuardCycle.Fixture

namespace GuardCycleFixture

inductive ConstructorCycle : Type where
  | mk (h : CycleProp) : ConstructorCycle

def constructorFirst : CycleProp → ConstructorCycle := ConstructorCycle.mk

theorem constructorControl : Nonempty ConstructorCycle := ⟨constructorFirst rfl⟩

end GuardCycleFixture
