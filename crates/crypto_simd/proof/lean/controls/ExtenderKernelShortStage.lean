import LeanBlsSimd.Refines.Fr8Lazy
import LeanBlsSimd.Refines.Fr8
import LeanBlsSimd.Model.Fr8

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Controls.ShortStage

def shortBodyWithSkip (skip : Usize)
  (h : Std.Usize) (input_bound : kzg.fr8.Fr8) (product_bound : kzg.fr8.Fr8)
  (group : Std.Usize) (self : kzg.fft8.Fft8) (t : Array kzg.fr8.Fr8 8#usize)
  (j : Std.Usize) :
  Result (ControlFlow (kzg.fft8.Fft8 × (Array kzg.fr8.Fr8 8#usize) ×
    Std.Usize) (kzg.fft8.Fft8 × (Array kzg.fr8.Fr8 8#usize)))
  := do
  if j < h
  then
    let i ← group + j
    let a ← Array.index_usize t i
    let i1 ← i + h
    let b ← Array.index_usize t i1
    let (self1, product, bound) ←
      if j = skip
      then ok (self, b, input_bound)
      else
        do
        let f ← kzg.fr8.Fr8.normalise b
        let i2 ← h - 1#usize
        let i3 ← i2 + j
        let f1 ←
          alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice
            kzg.fr8.Fr8) self.short i3
        let f2 ← kzg.fr8.Fr8.mul f f1
        ok (self, f2, product_bound)
    let f ← kzg.fr8.Fr8.add_raw a product
    let t1 ← Array.update t i f
    let f1 ← kzg.fr8.Fr8.sub_raw a product bound
    let i2 ← i + h
    let a1 ← Array.update t1 i2 f1
    let j1 ← j + 1#usize
    ok (cont (self1, a1, j1))
  else ok (done (self, t))


example : shortBodyWithSkip 0#usize = fft8.Fft8.dit_short_loop0_loop0.body := rfl

private def splatNat (n : Nat) : fr8.Fr8 :=
  ⟨List.ofFn (fun j : Fin 5 => Vector.replicate 8 (UInt64.ofNat (n / 2^(52*j.val) % 2^52))),
    by simp⟩

private def table : fft8.Fft8 :=
  { vectors := 8#usize
    wide := ⟨[], by simp⟩
    short := ⟨List.replicate 7 (splatNat 0), by simp; scalar_tac⟩ }

private def inputs : Array fr8.Fr8 8#usize :=
  (Array.repeat 8#usize (splatNat 0)).set 3#usize (splatNat 1)

private def firstLane (r : Result (ControlFlow
    (fft8.Fft8 × Array fr8.Fr8 8#usize × Usize)
    (fft8.Fft8 × Array fr8.Fr8 8#usize))) : UInt64 :=
  match r with
  | .ok (.cont (_, t, _)) => ((t.val[1]!).val[0]!)[0]
  | _ => 42

private def run (skip : Usize) :=
  shortBodyWithSkip skip 2#usize (splatNat (4 * Fr.modulus))
    (splatNat (2 * Fr.modulus)) 0#usize table inputs 1#usize

example : ∀ l : Fin 8,
    (∀ j : Fin FrModel.LIMBS,
      ((FrModel.ofFr8 (splatNat 1)).lane l)[j].toNat < 2^52) ∧
    FrModel.val ((FrModel.ofFr8 (splatNat 1)).lane l) = 1 := by decide +kernel

example : ∀ l : Fin 8,
    (∀ j : Fin FrModel.LIMBS,
      ((FrModel.ofFr8 (splatNat 0)).lane l)[j].toNat < 2^52) ∧
    FrModel.val ((FrModel.ofFr8 (splatNat 0)).lane l) = 0 := by decide +kernel

-- At j = 1, the stored multiplier is zero and the second input is one.
private theorem original_first : firstLane (run 0#usize) = 0 := by
  unfold run shortBodyWithSkip
  simp only [FrModel.Fr8.normalise_refines, FrModel.Fr8.mul_refines,
    FrModel.Fr8.add_raw_refines, FrModel.Fr8.sub_raw_refines, bind_tc_ok]
  simp (disch := scalar_tac) only [usize_add_ok, sub_ok, index_usize_eq, update_eq,
    UScalar.ofNatCore_val_eq, bind_tc_ok,
    show 1#usize < 2#usize by scalar_tac, show 1#usize ≠ 0#usize by scalar_tac,
    if_pos, if_neg]
  decide +kernel

private theorem mutated_first : firstLane (run 1#usize) = 1 := by
  unfold run shortBodyWithSkip
  simp only [FrModel.Fr8.normalise_refines, FrModel.Fr8.mul_refines,
    FrModel.Fr8.add_raw_refines, FrModel.Fr8.sub_raw_refines, bind_tc_ok]
  simp (disch := scalar_tac) only [usize_add_ok, sub_ok, index_usize_eq, update_eq,
    UScalar.ofNatCore_val_eq, bind_tc_ok,
    show 1#usize < 2#usize by scalar_tac, if_pos]
  decide +kernel

example : shortBodyWithSkip 1#usize ≠ fft8.Fft8.dit_short_loop0_loop0.body := by
  intro h
  have hrun : run 1#usize = run 0#usize := by
    unfold run
    rw [h]
    rfl
  have hbad : firstLane (run 1#usize) ≠ firstLane (run 0#usize) := by
    rw [mutated_first, original_first]
    decide
  exact hbad (congrArg firstLane hrun)

end LeanBlsSimd.Kzg.Extender.Controls.ShortStage
