module

public import Aeneas.Std.Alloc
public import Aeneas.Std.Array
public import Aeneas.Std.Std
public import Aeneas.Std.StringIter
public import Aeneas.Std.Target
public import Aeneas.Std.RangeIter
public import Aeneas.Std.Core.Alloc
public import Aeneas.Std.Core.CoreOption
public import Aeneas.Std.Core.CoreResult
public import Aeneas.Std.Core.Discriminant
public import Aeneas.Std.Core.Error
public import Aeneas.Std.Core.FmtWithSlice
public import Aeneas.Std.Core.Marker
public import Aeneas.Data
public import Aeneas.Tactic.Conv
public import Aeneas.Tactic.Elab
public import Aeneas.Tactic.Misc
public import Aeneas.Tactic.RustAttributes
public import Aeneas.Tactic.Setup
public import Aeneas.Tactic.Simp.SimpBoolProp
public import Aeneas.Tactic.Simp.RingEqNF

public section

namespace LeanBlsSimd

open Aeneas.Data.ListN

universe u

/-- Carry the length index so compiled constructors do not recompute each suffix length. -/
def listNFromListAux {α : Type u} (n : Nat) (xs : List α) (h : xs.length = n) : ListN α n :=
  match n, xs with
  | 0, _ => .nil
  | n + 1, x :: xs => .cons x (listNFromListAux n xs (Nat.succ.inj h))
  | _ + 1, [] => by cases h

theorem listNFromListAux_toList {α : Type u} (n : Nat) (xs : List α) (h : xs.length = n) :
    (listNFromListAux n xs h).toList = xs := by
  induction n generalizing xs with
  | zero =>
    cases xs with
    | nil => rfl
    | cons x xs => cases h
  | succ n ih =>
    cases xs with
    | nil => cases h
    | cons x xs =>
      change x :: (listNFromListAux n xs (Nat.succ.inj h)).toList = x :: xs
      exact congrArg (List.cons x) (ih xs (Nat.succ.inj h))

def listNFromList {α : Type u} (xs : List α) : ListN α xs.length :=
  listNFromListAux xs.length xs rfl

@[csimp] theorem fromList_eq_fast : @ListN.fromList = @listNFromList := by
  funext α xs
  apply ListN.toList_inj
  rw [ListN.from_to_inverse]
  exact (listNFromListAux_toList xs.length xs rfl).symm

open Aeneas.Std

/-- Compile the conversion with the linear `fromList` replacement in scope. -/
def sliceFromList {α : Type u} (xs : List α) (h : xs.length ≤ Usize.max) : Slice α :=
  { leng := xs.length, list := ListN.fromList xs, bound := h }

@[csimp] theorem sliceFrom_eq_fast : @Slice.from = @sliceFromList := by rfl

def vecPush {α : Type u} (v : alloc.vec.Vec α) (x : α) : Result (alloc.vec.Vec α) :=
  let nlen := List.length v.val + 1
  if h : nlen ≤ U32.max || nlen ≤ Usize.max then
    .ok { slice := Slice.from (List.concat v.val x) (by simp; scalar_tac) }
  else
    .fail .maximumSizeExceeded

@[csimp] theorem vecPush_eq_fast : @alloc.vec.Vec.push = @vecPush := by
  funext α v x
  unfold alloc.vec.Vec.push vecPush
  rfl

end LeanBlsSimd
