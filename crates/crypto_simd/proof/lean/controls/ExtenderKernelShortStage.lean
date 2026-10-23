import LeanBlsSimd.Refines.Fr8Lazy
import LeanBlsSimd.Refines.Fr8
import LeanBlsSimd.Model.Fr8

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Controls.ShortStage

def shortBodyWithOffset (offset : Usize)
  (v : alloc.vec.Vec kzg.fr8.Fr8) (h : Std.Usize) (product_bound : kzg.fr8.Fr8)
  (t : Array kzg.fr8.Fr8 8#usize) (pending_at : Std.Usize)
  (pending : Array core.core_arch.x86.__m512i 11#usize) (group : Std.Usize)
  (j : Std.Usize) :
  Result (ControlFlow ((Array kzg.fr8.Fr8 8#usize) × Std.Usize × (Array
    core.core_arch.x86.__m512i 11#usize) × Std.Usize × Std.Usize) ((Array
    kzg.fr8.Fr8 8#usize) × Std.Usize × (Array core.core_arch.x86.__m512i
    11#usize)))
  := do
  if j = h
  then
    let i ← 2#usize * h
    let group1 ← group + i
    if group1 >= kzg.fr8.LANES
    then ok (done (t, pending_at, pending))
    else
      let i1 ← group1 + 1#usize
      let i2 ← i1 + h
      let f ← Array.index_usize t i2
      let b ← kzg.fr8.Fr8.normalise f
      let i3 ← h - offset
      let i4 ← i3 + 1#usize
      let f1 ←
        alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice kzg.fr8.Fr8)
          v i4
      let (product, next) ← kzg.fr8.Fr8.reduce_while_multiplying pending b f1
      let (s, to_slice_mut_back) ← lift (Array.to_slice_mut t)
      let s1 ← kzg.fft8.dit_finish s pending_at h product product_bound
      let j1 ← 1#usize + 1#usize
      let t1 := to_slice_mut_back s1
      ok (cont (t1, i1, next, group1, j1))
  else
    let i ← group + j
    let i1 ← i + h
    let f ← Array.index_usize t i1
    let b ← kzg.fr8.Fr8.normalise f
    let i2 ← h - offset
    let i3 ← i2 + j
    let f1 ←
      alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice kzg.fr8.Fr8) v
        i3
    let (product, next) ← kzg.fr8.Fr8.reduce_while_multiplying pending b f1
    let (s, to_slice_mut_back) ← lift (Array.to_slice_mut t)
    let s1 ← kzg.fft8.dit_finish s pending_at h product product_bound
    let j1 ← j + 1#usize
    let t1 := to_slice_mut_back s1
    ok (cont (t1, i, next, group, j1))


example : shortBodyWithOffset 1#usize = fft8.Fft8.dit_short_loop1.body := rfl

private def splatNat (n : Nat) : fr8.Fr8 :=
  ⟨List.ofFn (fun j : Fin 5 => Vector.replicate 8 (UInt64.ofNat (n / 2^(52*j.val) % 2^52))),
    by simp⟩

private def table : alloc.vec.Vec fr8.Fr8 :=
  ⟨(List.replicate 7 (splatNat 0)).set 4 (splatNat 1), by simp; scalar_tac⟩

private def inputs : Array fr8.Fr8 8#usize :=
  (Array.repeat 8#usize (splatNat 0)).set 6#usize (splatNat 1)

private def firstLane (r : Result (ControlFlow
    (Array fr8.Fr8 8#usize × Usize × Array M512 11#usize × Usize × Usize)
    (Array fr8.Fr8 8#usize × Usize × Array M512 11#usize))) : UInt64 :=
  match r with
  | .ok (.cont (_, _, next, _, _)) => (next.val[0]!)[0]
  | _ => 42

private def run (offset : Usize) :=
  shortBodyWithOffset offset table 4#usize (splatNat (2 * Fr.modulus)) inputs
    1#usize (Array.repeat 11#usize (Vector.replicate 8 0)) 0#usize 2#usize

example : ∀ l : Fin 8,
    (∀ j : Fin FrModel.LIMBS,
      ((FrModel.ofFr8 (splatNat 1)).lane l)[j].toNat < 2^52) ∧
    FrModel.val ((FrModel.ofFr8 (splatNat 1)).lane l) = 1 := by decide +kernel

private theorem original_first : firstLane (run 1#usize) = 0 := by
  unfold run shortBodyWithOffset
  simp (disch := scalar_tac) only [FrModel.Fr8.normalise_refines,
    FrModel.Fr8.reduce_while_multiplying_refines, FrModel.Fr8.add_raw_refines,
    FrModel.Fr8.sub_raw_refines, fft8.dit_finish, bind_tc_ok,
    usize_add_ok, usize_mul_ok, sub_ok, index_usize_eq,
    UScalar.ofNatCore_val_eq, Array.to_slice_mut, lift,
    show 2#usize ≠ 4#usize by scalar_tac, if_neg,
    table, inputs, Array.repeat,
    Array.to_slice, Array.from_slice, Slice.index_usize, Slice.update,
    Function.uncurry_apply_pair]
  decide +kernel

private theorem mutated_first : firstLane (run 2#usize) = 1 := by
  unfold run shortBodyWithOffset
  simp (disch := scalar_tac) only [FrModel.Fr8.normalise_refines,
    FrModel.Fr8.reduce_while_multiplying_refines, FrModel.Fr8.add_raw_refines,
    FrModel.Fr8.sub_raw_refines, fft8.dit_finish, bind_tc_ok,
    usize_add_ok, usize_mul_ok, sub_ok, index_usize_eq,
    UScalar.ofNatCore_val_eq, Array.to_slice_mut, lift,
    show 2#usize ≠ 4#usize by scalar_tac, if_neg,
    table, inputs, Array.repeat,
    Array.to_slice, Array.from_slice, Slice.index_usize, Slice.update,
    Function.uncurry_apply_pair]
  decide +kernel

example : shortBodyWithOffset 2#usize ≠ fft8.Fft8.dit_short_loop1.body := by
  intro h
  have hrun : run 2#usize = run 1#usize := by
    unfold run
    rw [h]
    rfl
  have hbad : firstLane (run 2#usize) ≠ firstLane (run 1#usize) := by
    rw [mutated_first, original_first]
    decide
  exact hbad (congrArg firstLane hrun)

end LeanBlsSimd.Kzg.Extender.Controls.ShortStage
