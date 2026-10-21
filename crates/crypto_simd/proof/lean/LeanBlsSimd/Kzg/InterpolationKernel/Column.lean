import LeanBlsSimd.Kzg.InterpolationKernel.Basic
import LeanBlsSimd.Kzg.Extender.Kernel.Fft
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg Kzg.BitReversal
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthCryptographySpecs.Bls.Fr

namespace LeanBlsSimd.Kzg.InterpolationKernel

open Extender Extender.Kernel

def columnCoefficients (values : _root_.Array Fr) : _root_.Array Fr :=
  fftFieldAux (bitReversalPermutation values) (Model.inverseRoots (Model.roots 6))

def columnStep (column : Nat) (totals values : _root_.Array Fr) : _root_.Array Fr :=
  _root_.Array.ofFn (n := 64) fun i =>
    totals[i.val]! + (columnCoefficients values)[i.val]! * shiftFactor column i.val

private def SumPrefix (sums : Array fr8.Fr8 8#usize)
    (column : Nat) (totals values : _root_.Array Fr) (count : Nat) : Prop :=
  ∀ v : Fin 8, Represents sums.val[v.val]!
    (fun lane => if v.val < count then
      totals[8*v.val+lane.val]! + values[8*v.val+lane.val]! * shiftFactor column (8*v.val+lane.val)
    else totals[8*v.val+lane.val]!)

private theorem sum_loop (kernel : interpolation_kernel.InterpolationKernel)
    (hk : StateInvariant kernel) (column : Usize) (hc : column.val < 128)
    (data : alloc.vec.Vec fr8.Fr8) (hdlen : data.val.length = 1024)
    (values totals : _root_.Array Fr)
    (hd : ∀ v : Fin 8, LazyRep 34 370 data.val[column.val*8+v.val]!
      (fun lane => values[8*v.val+lane.val]!))
    (sums : Array fr8.Fr8 8#usize) (at1 i : Usize) (hat : at1.val = column.val*8)
    (hi : i.val ≤ 8) (hs : SumPrefix sums column.val totals values i.val) :
    ∃ out, interpolation_kernel.InterpolationKernel.add_column_loop
      8#usize kernel.shift data sums at1 i = ok out ∧
      SumPrefix out column.val totals values 8 := by
  induction hrem : 8-i.val generalizing sums i with
  | zero =>
    have he : i.val = 8 := by omega
    refine ⟨sums, ?_, by simpa only [he] using hs⟩
    rw [interpolation_kernel.InterpolationKernel.add_column_loop, loop.eq_1]
    simp [interpolation_kernel.InterpolationKernel.add_column_loop.body, UScalar.lt_equiv, he]
  | succ rem ih =>
    have hit : i.val < 8 := by omega
    have hil : i.val < sums.val.length := by simpa only [sums.property] using hit
    let index : Usize := UScalar.ofNatCore (column.val*8+i.val) (by scalar_tac)
    have hindexval : index.val = column.val*8+i.val := UScalar.ofNatCore_val_eq _
    have hindexbound : index.val < data.val.length := by rw [hdlen, hindexval]; omega
    have hshiftbound : index.val < kernel.shift.val.length := by rw [hk.2.1, hindexval]; omega
    obtain ⟨norm, scaled, hnorm, hmul, hscaled⟩ := normalise_mul_multiplier_refinement
      data.val[column.val*8+i.val]! kernel.shift.val[column.val*8+i.val]!
      (fun lane => values[8*i.val+lane.val]!)
      (fun lane => shiftFactor column.val (8*i.val+lane.val))
      (hd ⟨i.val, hit⟩) (by decide) (by decide) (hk.2.2.2.2 ⟨column.val, hc⟩ ⟨i.val, hit⟩)
    have hsrep : Represents sums.val[i.val]! (fun lane => totals[8*i.val+lane.val]!) := by
      simpa only [lt_self_iff_false, if_false] using hs ⟨i.val, hit⟩
    obtain ⟨sum, hsum, hsumrep⟩ := add_lazy_representation _ _ _ _ hsrep.lazy hscaled
      (by decide) (by decide)
    let next := sums.set i sum
    have hnext : SumPrefix next column.val totals values (i.val+1) := by
      intro v
      by_cases he : v.val = i.val
      · have hve : v = ⟨i.val, hit⟩ := Fin.ext he
        subst v
        change Represents ((sums.val.set i.val sum)[i.val]!) _
        rw [List.getElem!_set _ _ _ hil]
        simpa using hsumrep
      · have heq : (v.val < i.val+1) = (v.val < i.val) := propext (by omega)
        change Represents ((sums.val.set i.val sum)[v.val]!) _
        rw [List.getElem!_set_ne _ _ _ _ (by omega)]
        simpa only [heq] using hs v
    let i' : Usize := UScalar.ofNatCore (i.val+1) (by scalar_tac)
    have hi' : i'.val = i.val+1 := UScalar.ofNatCore_val_eq _
    obtain ⟨out, hout, ho⟩ := ih next i' (by omega) (by simpa only [hi'] using hnext) (by omega)
    have hadd : i+1#usize = ok i' := scalar_add_ok i 1#usize (by scalar_tac)
    have hatadd : at1+i = ok index := by
      simpa only [hat, index] using scalar_add_ok at1 i (by scalar_tac)
    have hdataindex : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice fr8.Fr8)
        data index = ok data.val[column.val*8+i.val]! := by
      have hb : column.val*8+i.val < data.val.length := by omega
      simp [alloc.vec.Vec.index_usize, hindexval, List.getElem?_eq_getElem hb]
    have hshiftindex : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice fr8.Fr8)
        kernel.shift index = ok kernel.shift.val[column.val*8+i.val]! := by
      have hb : column.val*8+i.val < kernel.shift.val.length := by omega
      simp [alloc.vec.Vec.index_usize, hindexval, List.getElem?_eq_getElem hb]
    have hsindex : Array.index_usize sums i = ok sums.val[i.val]! := by
      simp [Array.index_usize, List.getElem?_eq_getElem hil]
    have hupdate : Array.update sums i sum = ok next := by
      simp [Array.update, next, List.getElem?_eq_getElem hil]
      rfl
    have hlt : i < 8#usize := by simpa only [UScalar.lt_equiv] using hit
    refine ⟨out, ?_, ho⟩
    rw [interpolation_kernel.InterpolationKernel.add_column_loop, loop.eq_1]
    simpa only [interpolation_kernel.InterpolationKernel.add_column_loop.body,
      hlt, if_true, hatadd, hdataindex, hnorm, hshiftindex, hmul, hsindex, hsum,
      hupdate, hadd, bind_tc_ok] using hout

theorem add_column_refinement (kernel : interpolation_kernel.InterpolationKernel)
    (column : Usize) (sums : Array fr8.Fr8 8#usize) (columnValues totals : _root_.Array Fr)
    (hk : StateInvariant kernel) (hc : column.val < 128)
    (hsize : columnValues.size = 64)
    (hroots : RootsValid (Model.inverseRoots (Model.roots 6)))
    (hcolumn : ∀ v : Fin 8, Represents kernel.columns.val[column.val*8+v.val]!
      (fun lane => columnValues[8*v.val+lane.val]!))
    (hsums : DataRep (Array.to_slice sums) totals) :
    ∃ next sums', interpolation_kernel.InterpolationKernel.add_column kernel column sums =
        ok (next, sums') ∧ StateInvariant next ∧ SameTables kernel next ∧
      next.used = kernel.used ∧
      (∀ i, i < column.val*8 ∨ column.val*8+8 ≤ i →
        next.columns.val[i]! = kernel.columns.val[i]!) ∧
      DataRep (Array.to_slice sums') (columnStep column.val totals columnValues) := by
  let at1 : Usize := UScalar.ofNatCore (column.val*8) (by scalar_tac)
  let stop : Usize := UScalar.ofNatCore (column.val*8+8) (by scalar_tac)
  have hat : at1.val = column.val*8 := UScalar.ofNatCore_val_eq _
  have hstop : stop.val = column.val*8+8 := UScalar.ofNatCore_val_eq _
  let block : Slice fr8.Fr8 := ⟨kernel.columns.val.slice at1.val stop.val,
    le_trans (List.slice_length_le _ _ _) kernel.columns.property⟩
  have hblocklen : block.val.length = 8 := by
    simp only [block, List.slice, List.length_take, List.length_drop, hk.2.2.1, hat, hstop]
    omega
  have hblockrep : DataRep block columnValues := by
    refine ⟨by rw [hsize, hblocklen], ?_⟩
    intro v
    have hv : v.val < 8 := by simpa only [hblocklen] using v.isLt
    have he : block.val[v.val] = kernel.columns.val[column.val*8+v.val]! := by
      simp only [block, List.slice, List.getElem_take, List.getElem_drop, hat]
      exact (getElem!_pos _ _ (by rw [hk.2.2.1]; omega)).symm
    rw [he]
    exact hcolumn ⟨v.val, hv⟩
  have hrootsize : (Model.inverseRoots (Model.roots 6)).size = 64 := by
    simp [Model.inverseRoots, Model.roots]
  obtain ⟨transformed, hfft, ht⟩ := dit_refinement kernel.inverse block columnValues
    (Model.inverseRoots (Model.roots 6)) hk.1 (hsize.trans hrootsize.symm) hroots hblockrep
  have htlen : transformed.val.length = 8 := by
    have hh := ht.1
    simp only [size_fftFieldAux, size_bitReversalPermutation, hsize] at hh
    omega
  let data := kernel.columns.setSlice! at1.val transformed.val
  have hdlen : data.val.length = 1024 := by
    simp only [data, alloc.vec.Vec.setSlice!, List.length_setSlice!, hk.2.2.1]
  have hd : ∀ v : Fin 8, LazyRep 34 370 data.val[column.val*8+v.val]!
      (fun lane => (columnCoefficients columnValues)[8*v.val+lane.val]!) := by
    intro v
    have hv : v.val < transformed.val.length := by rw [htlen]; exact v.isLt
    have he : data.val[column.val*8+v.val]! = transformed.val[v.val] := by
      simp only [data, alloc.vec.Vec.setSlice!, hat]
      rw [List.getElem!_setSlice!_middle _ _ _ _ (by rw [htlen, hk.2.2.1]; omega)]
      simp only [Nat.add_sub_cancel_left, getElem!_pos transformed.val v.val hv]
    rw [he]
    exact ht.2 ⟨v.val, hv⟩
  have hs : SumPrefix sums column.val totals (columnCoefficients columnValues) 0 := by
    intro v
    have hv : v.val < (Array.to_slice sums).val.length := by
      simpa only [Array.to_slice, sums.property] using v.isLt
    simpa only [Nat.not_lt_zero, if_false, Array.to_slice, getElem!_pos sums.val v.val hv]
      using hsums.2 ⟨v.val, hv⟩
  obtain ⟨sums', hloop, hs'⟩ := sum_loop kernel hk column hc data hdlen
    (columnCoefficients columnValues) totals hd sums at1 0#usize hat (by decide) hs
  let next := { kernel with columns := data }
  have hnext : StateInvariant next := by
    exact ⟨hk.1, hk.2.1, hdlen, hk.2.2.2⟩
  have hmul : column*8#usize = ok at1 := scalar_mul_ok column 8#usize (by scalar_tac)
  have hadd : at1+8#usize = ok stop := by
    simpa only [hat, stop] using scalar_add_ok at1 8#usize (by scalar_tac)
  have hmut : alloc.vec.Vec.index_mut (core.slice.index.SliceIndexRangeUsizeSlice fr8.Fr8)
      kernel.columns { start := at1, «end» := stop } =
      ok (block, fun s => kernel.columns.setSlice! at1.val s.val) := by
    simp only [alloc.vec.Vec.index_mut, core.slice.index.SliceIndexRangeUsizeSlice.index_mut,
      UScalar.le_equiv]
    rw [if_pos (by simp only [Slice.length, hat, hstop, hk.2.2.1]; omega)]
    rfl
  refine ⟨next, sums', ?_, hnext, ⟨rfl, rfl⟩, rfl, ?_, ?_⟩
  · simp only [interpolation_kernel.InterpolationKernel.add_column, vectors_per_cell_eq,
      hmul, hadd, hmut, bind_tc_ok]
    dsimp only [data] at hloop
    simp only [Function.uncurry_apply_pair, hfft, hloop, bind_tc_ok, next, data]
  · intro i hi
    change (kernel.columns.val.setSlice! at1.val transformed.val)[i]! = _
    exact List.getElem!_setSlice!_same _ _ _ _ (by simpa only [hat, htlen] using hi)
  · refine ⟨by simp only [columnStep, _root_.Array.size_ofFn, Array.to_slice, sums'.property]; rfl, ?_⟩
    intro v
    have hv : v.val < 8 := by simpa only [Array.to_slice, sums'.property] using v.isLt
    have hindex (lane : Fin 8) : 8*v.val+lane.val < 64 := by omega
    simpa only [hv, if_true, columnStep, _root_.Array.getElem!_ofFn, hindex,
      _root_.dite_true, Array.to_slice, getElem!_pos sums'.val v.val v.isLt] using hs' ⟨v.val, hv⟩

end LeanBlsSimd.Kzg.InterpolationKernel
