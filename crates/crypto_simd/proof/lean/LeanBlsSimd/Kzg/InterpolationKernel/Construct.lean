import LeanBlsSimd.Kzg.Fr.Arithmetic
import LeanBlsSimd.Kzg.CosetsRep
import LeanBlsSimd.Kzg.InterpolationKernel.Basic
import LeanBlsSimd.Kzg.Extender.Kernel.Fft

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthLib.Cryptography.Bls.Fr

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.InterpolationKernel

open Extender Extender.Kernel

private def Factors (factors : Array blst.blst_fr 64#usize) (column count : Nat) : Prop :=
  ∀ j : Fin 64, j.val < count →
    factors.val[j.val]! = frEncode (shiftFactor column j.val * Fr.ofNat 16)

private theorem factors_loop
    (cs : cosets.Cosets) (hcs : CosetsRep cs) (column : Usize) (hc : column.val < 128)
    (factors : Array blst.blst_fr 64#usize) (i : Usize) (hi : i.val ≤ 64)
    (hf : Factors factors column.val i.val) :
    ∃ out, interpolation_kernel.InterpolationKernel.new_loop0_loop0 cs.shift_inverse factors
      column (frEncode (shiftFactor column.val i.val)) i = ok out ∧
      Factors out column.val 64 := by
  induction hrem : 64 - i.val generalizing i factors with
  | zero =>
    have he : i.val = 64 := by omega
    refine ⟨factors, ?_, by simpa only [he] using hf⟩
    rw [interpolation_kernel.InterpolationKernel.new_loop0_loop0, loop.eq_1]
    simp [interpolation_kernel.InterpolationKernel.new_loop0_loop0.body,
      FIELD_ELEMENTS_PER_CELL, UScalar.lt_equiv, he]
  | succ rem ih =>
    have hlt : i.val < 64 := by omega
    let i' : Usize := UScalar.ofNatCore (i.val + 1) (by scalar_tac)
    have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
    have hinc : i + 1#usize = ok i' := scalar_add_ok i 1#usize (by scalar_tac)
    have hlookup : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice blst.blst_fr)
        cs.shift_inverse column = ok (frEncode (Model.cosetShift column.val).inverse) := by
      simp [alloc.vec.Vec.index_usize, hcs.2.2.1, hc]
    have hproduct : fr.fr_mul (frEncode (shiftFactor column.val i.val))
        (frEncode (Model.cosetShift column.val).inverse) =
        ok (frEncode (shiftFactor column.val i'.val)) := by
      simpa only [hi', shiftFactor, pow_succ, mul_assoc] using
        FrScalar.fr_mul_refines (shiftFactor column.val i.val) (Model.cosetShift column.val).inverse
    have hmultiplier := (multiplier_refinement (shiftFactor column.val i.val)).1
    let next := Aeneas.Std.Array.set factors i (frEncode (shiftFactor column.val i.val * Fr.ofNat 16))
    have hupdate : Array.update factors i (frEncode (shiftFactor column.val i.val * Fr.ofNat 16)) =
        ok next := by
      have hb : i.val < factors.val.length := by simpa only [factors.property] using hlt
      simp [Array.update, List.getElem?_eq_getElem hb, next, Aeneas.Std.Array.set]
    have hprefix : Factors next column.val i'.val := by
      intro j hj
      by_cases he : j.val = i.val
      · rw [he]
        simp [next, Aeneas.Std.Array.set, factors.property, hlt]
      · rw [show next.val = factors.val.set i.val
          (frEncode (shiftFactor column.val i.val * Fr.ofNat 16)) from rfl,
          List.getElem!_set_ne _ _ _ _ (by omega)]
        exact hf j (by omega)
    obtain ⟨out, hout, ho⟩ := ih next i' (by omega) hprefix (by omega)
    refine ⟨out, ?_, ho⟩
    have hbody : interpolation_kernel.InterpolationKernel.new_loop0_loop0.body
        cs.shift_inverse column factors (frEncode (shiftFactor column.val i.val)) i =
        ok (cont (next, frEncode (shiftFactor column.val i'.val), i')) := by
      simp only [interpolation_kernel.InterpolationKernel.new_loop0_loop0.body,
        FIELD_ELEMENTS_PER_CELL, UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hlt, if_true,
        hmultiplier, hupdate, hlookup, hproduct, hinc, bind_tc_ok]
    rw [interpolation_kernel.InterpolationKernel.new_loop0_loop0, loop.eq_1]
    simpa only [hbody] using hout

private def Prefix (shift columns : alloc.vec.Vec fr8.Fr8) (count : Nat) : Prop :=
  shift.val.length = count ∧ columns.val.length = count ∧
    ∀ (c : Fin 128) (v : Fin 8), c.val * 8 + v.val < count →
      MultiplierRep shift.val[c.val * 8 + v.val]!
        (fun lane => shiftFactor c.val (8 * v.val + lane.val))

private theorem vectors_loop
    (column : Nat) (hc : column < 128) (factors : Array blst.blst_fr 64#usize)
    (hf : Factors factors column 64) (shift columns : alloc.vec.Vec fr8.Fr8)
    (v : Usize) (hv : v.val ≤ 8) (hp : Prefix shift columns (column * 8 + v.val)) :
    ∃ finalShift finalColumns,
      interpolation_kernel.InterpolationKernel.new_loop0_loop1 8#usize shift columns factors v =
        ok (finalShift, finalColumns) ∧ Prefix finalShift finalColumns ((column + 1) * 8) := by
  induction hrem : 8 - v.val generalizing shift columns v with
  | zero =>
    have he : v.val = 8 := by omega
    refine ⟨shift, columns, ?_, ?_⟩
    · rw [interpolation_kernel.InterpolationKernel.new_loop0_loop1, loop.eq_1]
      simp [interpolation_kernel.InterpolationKernel.new_loop0_loop1.body, UScalar.lt_equiv, he]
    · convert hp using 1; omega
  | succ rem ih =>
    have hlt : v.val < 8 := by omega
    let offset : Usize := UScalar.ofNatCore (v.val * 8) (by scalar_tac)
    have hoffset : offset.val = v.val * 8 := UScalar.ofNatCore_val_eq _
    have hmul : v * fr8.LANES = ok offset := by
      simpa only [fr8.LANES] using scalar_mul_ok v 8#usize (by scalar_tac)
    obtain ⟨factor, hload, hfactor⟩ := load_multiplier_refinement
      (Array.to_slice factors) offset (fun lane => shiftFactor column (8 * v.val + lane.val))
      (by simp [Array.to_slice, factors.property, hoffset]; omega)
      (by intro lane; simpa only [Array.to_slice, hoffset, Nat.mul_comm v.val 8] using
        hf ⟨8 * v.val + lane.val, by omega⟩ (by omega))
    obtain ⟨zero, hzero, hzeroRep⟩ := zero_refinement
    have hsBound : shift.val.length + 1 ≤ Usize.max := by rw [hp.1]; scalar_tac
    have hdBound : columns.val.length + 1 ≤ Usize.max := by rw [hp.2.1]; scalar_tac
    let shift' : alloc.vec.Vec fr8.Fr8 := ⟨shift.val ++ [factor], by simpa using hsBound⟩
    let columns' : alloc.vec.Vec fr8.Fr8 := ⟨columns.val ++ [zero], by simpa using hdBound⟩
    let v' : Usize := UScalar.ofNatCore (v.val + 1) (by scalar_tac)
    have hv' : v'.val = v.val + 1 := UScalar.ofNatCore_val_eq _
    have hsPush : alloc.vec.Vec.push shift factor = ok shift' := by
      simp [alloc.vec.Vec.push, hsBound, shift']
    have hdPush : alloc.vec.Vec.push columns zero = ok columns' := by
      simp [alloc.vec.Vec.push, hdBound, columns']
    have hinc : v + 1#usize = ok v' := scalar_add_ok v 1#usize (by scalar_tac)
    have hprefix : Prefix shift' columns' (column * 8 + v'.val) := by
      refine ⟨by simp [shift', hp.1, hv', Nat.add_assoc],
        by simp [columns', hp.2.1, hv', Nat.add_assoc], ?_⟩
      intro c w hw
      by_cases hj : c.val * 8 + w.val < column * 8 + v.val
      · change MultiplierRep (shift.val ++ [factor])[c.val * 8 + w.val]! _
        rw [List.getElem!_append_left _ _ _ (by rw [hp.1]; exact hj)]
        exact hp.2.2 c w hj
      · have he : c.val * 8 + w.val = column * 8 + v.val := by omega
        have hec : c.val = column := by omega
        have hev : w.val = v.val := by omega
        change MultiplierRep (shift.val ++ [factor])[c.val * 8 + w.val]! _
        rw [List.getElem!_append_right _ _ _ (by rw [hp.1, he])]
        simpa only [hp.1, he, Nat.sub_self, List.getElem!_cons_zero, hec, hev] using hfactor
    obtain ⟨finalShift, finalColumns, hout, ho⟩ := ih shift' columns' v'
      (by omega) hprefix (by omega)
    refine ⟨finalShift, finalColumns, ?_, ho⟩
    have hbody : interpolation_kernel.InterpolationKernel.new_loop0_loop1.body
        8#usize factors shift columns v = ok (cont (shift', columns', v')) := by
      simp only [interpolation_kernel.InterpolationKernel.new_loop0_loop1.body,
        UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hlt, if_true, lift, bind_tc_ok,
        hmul, hload, hsPush, hzero, hdPush, hinc]
    rw [interpolation_kernel.InterpolationKernel.new_loop0_loop1, loop.eq_1]
    simpa only [hbody] using hout

private theorem columns_loop
    (cs : cosets.Cosets) (hcs : CosetsRep cs)
    (shift columns : alloc.vec.Vec fr8.Fr8) (used : alloc.vec.Vec Bool)
    (factors : Array blst.blst_fr 64#usize) (c : Usize) (hc : c.val ≤ 128)
    (hp : Prefix shift columns (c.val * 8)) (hu : used.val.length = c.val) :
    ∃ finalShift finalColumns finalUsed,
      interpolation_kernel.InterpolationKernel.new_loop0 128#usize 8#usize cs
        shift columns used factors c = ok (cs, finalShift, finalColumns, finalUsed) ∧
      Prefix finalShift finalColumns 1024 ∧ finalUsed.val.length = 128 := by
  induction hrem : 128 - c.val generalizing shift columns used factors c with
  | zero =>
    have he : c.val = 128 := by omega
    refine ⟨shift, columns, used, ?_, by simpa only [he] using hp, by omega⟩
    rw [interpolation_kernel.InterpolationKernel.new_loop0, loop.eq_1]
    simp [interpolation_kernel.InterpolationKernel.new_loop0.body, UScalar.lt_equiv, he]
  | succ rem ih =>
    have hlt : c.val < 128 := by omega
    obtain ⟨factors', hfactors, hf⟩ := factors_loop cs hcs c hlt factors
      0#usize (by decide) (by intro j hj; exact (Nat.not_lt_zero _ hj).elim)
    have hscale : frEncode (shiftFactor c.val (0#usize).val) = cs.inverse_size := by
      rw [hcs.2.1]
      change frEncode ((Fr.ofNat 64).inverse * (Model.cosetShift c.val).inverse ^ (0 : Nat)) = _
      rw [pow_zero]
      congr 1
      apply Fin.ext
      change ((Fr.ofNat 64).inverse.val * 1) % Fr.modulus = (Fr.ofNat 64).inverse.val
      simp only [Nat.mul_one, Nat.mod_eq_of_lt (Fr.ofNat 64).inverse.isLt]
    rw [hscale] at hfactors
    obtain ⟨shift', columns', hvectors, hp'⟩ := vectors_loop c.val hlt factors' hf
      shift columns 0#usize (by decide) (by simpa using hp)
    have huBound : used.val.length + 1 ≤ Usize.max := by rw [hu]; scalar_tac
    let used' : alloc.vec.Vec Bool := ⟨used.val ++ [false], by simpa using huBound⟩
    have huPush : alloc.vec.Vec.push used false = ok used' := by
      simp [alloc.vec.Vec.push, huBound, used']
    let c' : Usize := UScalar.ofNatCore (c.val + 1) (by scalar_tac)
    have hc' : c'.val = c.val + 1 := UScalar.ofNatCore_val_eq _
    have hinc : c + 1#usize = ok c' := scalar_add_ok c 1#usize (by scalar_tac)
    obtain ⟨finalShift, finalColumns, finalUsed, hout, ho⟩ := ih shift' columns' used'
      factors' c' (by omega) (by simpa only [hc'] using hp')
      (by simp [used', hu, hc']) (by omega)
    refine ⟨finalShift, finalColumns, finalUsed, ?_, ho⟩
    have hbody : interpolation_kernel.InterpolationKernel.new_loop0.body
        128#usize 8#usize cs shift columns used factors c =
        ok (cont (shift', columns', used', factors', c')) := by
      simp only [interpolation_kernel.InterpolationKernel.new_loop0.body,
        UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hlt, if_true, hfactors, hvectors,
        bind_tc_ok, huPush, hinc, Function.uncurry_apply_pair]
    rw [interpolation_kernel.InterpolationKernel.new_loop0, loop.eq_1]
    simpa only [hbody] using hout

private theorem sample_cell (roots : _root_.Array Fr) (hsize : roots.size = 64) :
    sampleRoots roots 64 = roots := by
  apply _root_.Array.ext
  · simpa only [sampleRoots, _root_.Array.size_ofFn] using hsize.symm
  · intro i hi hj
    simp only [sampleRoots, _root_.Array.getElem_ofFn, hsize, Nat.div_self (by decide : 0 < 64),
      Nat.mul_one, getElem!_pos roots i hj]

theorem new_refinement
    (cs : cosets.Cosets) (hcs : CosetsRep cs) :
    ∃ kernel, interpolation_kernel.InterpolationKernel.new cs = ok kernel ∧ StateInvariant kernel := by
  let empty := alloc.vec.Vec.with_capacity fr8.Fr8 1024#usize
  let unused := alloc.vec.Vec.with_capacity Bool 128#usize
  let factors := Array.repeat 64#usize (frEncode 0)
  have hempty : Prefix empty empty (0#usize).val := by
    refine ⟨rfl, rfl, ?_⟩
    intro c v h
    exact (Nat.not_lt_zero _ h).elim
  obtain ⟨shift, columns, used, hconstruct, hp, hu⟩ := columns_loop cs hcs
    empty empty unused factors 0#usize (by decide) (by simpa using hempty) rfl
  have hn : TransformSize (64#usize).val := ⟨6, by decide, by decide, by decide⟩
  have hrs : (Model.inverseRoots (Model.roots 6)).size = 64 := by
    simp [Model.inverseRoots, Model.roots]
  obtain ⟨inverse, hiNew, hiInv⟩ := fft_new_refinement
    (alloc.vec.Vec.deref cs.inverse_roots) (Model.inverseRoots (Model.roots 6))
    64#usize hn (by omega) (by simp only [hrs, UScalar.ofNatCore_val_eq]) hcs.1
  rw [show (64#usize).val = 64 from rfl, sample_cell _ hrs] at hiInv
  let kernel : interpolation_kernel.InterpolationKernel := ⟨inverse, shift, columns, used⟩
  refine ⟨kernel, ?_, ⟨hiInv, hp.1, hp.2.1, hu, ?_⟩⟩
  · dsimp only [empty, unused, factors] at hconstruct
    have hcells : CELLS_PER_EXT_BLOB = ok 128#usize := by
      have hmul : 2#usize * 4096#usize = ok 8192#usize := by
        simpa using scalar_mul_ok 2#usize 4096#usize (by scalar_tac)
      obtain ⟨out, hout, hv⟩ := UScalar.div_spec 8192#usize (y := 64#usize) (by simp)
      have he : out = 128#usize := by
        apply UScalar.eq_of_val_eq
        simpa only [UScalar.ofNatCore_val_eq] using hv
      unfold CELLS_PER_EXT_BLOB
      simpa only [FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL, hmul, bind_tc_ok, he]
        using hout
    have hcapacity : 128#usize * 8#usize = ok 1024#usize := by
      simpa using scalar_mul_ok 128#usize 8#usize (by scalar_tac)
    simp only [interpolation_kernel.InterpolationKernel.new, hcells, vectors_per_cell_eq, hcapacity,
      bind_tc_ok, fr_zero_eq, UScalar.ofNatCore_val_eq,
      show Fr.ofNat 0 = 0 from rfl, hconstruct, FIELD_ELEMENTS_PER_CELL, hiNew,
      Function.uncurry_apply_pair, kernel]
  · intro c v
    exact hp.2.2 c v (by omega)

end LeanBlsSimd.Kzg.InterpolationKernel
