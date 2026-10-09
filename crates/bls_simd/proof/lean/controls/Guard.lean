import Std.Tactic.BVDecide
import LeanBlsSimd.Axioms

/-! Controls for `#assert_standard_axioms`: one theorem per form of native evaluation. The
unlisted forms must fail; `#assert_accepting` runs the same check with a chosen accepted list. -/

open Lean Elab Command in
elab "#assert_accepting " names:ident* : command =>
  LeanBlsSimd.checkAxioms (names.map (·.getId)).toList

theorem LeanBlsSimd.nativeControl : 2 ^ 64 % 7 = 2 := by native_decide

theorem LeanBlsSimd.bvControl (x : BitVec 16) : x * 5 = (x <<< 2) + x := by bv_decide

def LeanBlsSimd.reduceBoolAux : Bool := 2 ^ 64 % 7 == 2

set_option linter.deprecated false in
theorem LeanBlsSimd.reduceBoolControl : LeanBlsSimd.reduceBoolAux = true :=
  Lean.ofReduceBool LeanBlsSimd.reduceBoolAux true rfl

/--
error: LeanBlsSimd.bvControl depends on [LeanBlsSimd.bvControl._native.bv_decide.ax_1_5]
LeanBlsSimd.nativeControl depends on [LeanBlsSimd.nativeControl._native.native_decide.ax_1_1]
LeanBlsSimd.reduceBoolControl depends on [Lean.ofReduceBool, Lean.trustCompiler]
-/
#guard_msgs (error, drop info) in
#assert_standard_axioms

-- Positive control: listing every axiom of all three controls passes.
#guard_msgs (error, drop info) in
#assert_accepting LeanBlsSimd.bvControl._native.bv_decide.ax_1_5
  LeanBlsSimd.nativeControl._native.native_decide.ax_1_1 Lean.ofReduceBool Lean.trustCompiler

-- Listing one control's axiom excuses that control only.
/--
error: LeanBlsSimd.bvControl depends on [LeanBlsSimd.bvControl._native.bv_decide.ax_1_5]
LeanBlsSimd.reduceBoolControl depends on [Lean.ofReduceBool, Lean.trustCompiler]
-/
#guard_msgs (error, drop info) in
#assert_accepting LeanBlsSimd.nativeControl._native.native_decide.ax_1_1

-- A partial list for one theorem leaves its other axioms offending.
/--
error: LeanBlsSimd.bvControl depends on [LeanBlsSimd.bvControl._native.bv_decide.ax_1_5]
LeanBlsSimd.nativeControl depends on [LeanBlsSimd.nativeControl._native.native_decide.ax_1_1]
LeanBlsSimd.reduceBoolControl depends on [Lean.trustCompiler]
-/
#guard_msgs (error, drop info) in
#assert_accepting Lean.ofReduceBool

/-! An axiom that a theorem reaches only through the constructor of an inductive type it names.
A cache of per-constant axiom sets can miss it, when its walk finishes the type before the
constructor; the guard's shared walk must not. -/

axiom LeanBlsSimd.cycleAx : Nat

def LeanBlsSimd.CycleProp : Prop := LeanBlsSimd.cycleAx = LeanBlsSimd.cycleAx

inductive LeanBlsSimd.CycleType : Type where
  | mk (h : LeanBlsSimd.CycleProp) : LeanBlsSimd.CycleType

theorem LeanBlsSimd.cycleControl : Nonempty (LeanBlsSimd.CycleType → LeanBlsSimd.CycleType) :=
  ⟨id⟩

/--
error: LeanBlsSimd.CycleType.mk.sizeOf_spec depends on [LeanBlsSimd.cycleAx]
LeanBlsSimd.bvControl depends on [LeanBlsSimd.bvControl._native.bv_decide.ax_1_5]
LeanBlsSimd.cycleControl depends on [LeanBlsSimd.cycleAx]
LeanBlsSimd.nativeControl depends on [LeanBlsSimd.nativeControl._native.native_decide.ax_1_1]
LeanBlsSimd.reduceBoolControl depends on [Lean.ofReduceBool, Lean.trustCompiler]
-/
#guard_msgs (error, drop info) in
#assert_standard_axioms
