import controls.GuardCycle.Fixture
import controls.GuardCycle.Constructor

theorem LeanBlsSimd.importedCycleControl :
    Nonempty (GuardCycleFixture.CycleType9 → GuardCycleFixture.CycleType9) :=
  GuardCycleFixture.cycleControl9

theorem LeanBlsSimd.importedConstructorCycleControl : Nonempty GuardCycleFixture.ConstructorCycle :=
  GuardCycleFixture.constructorControl
