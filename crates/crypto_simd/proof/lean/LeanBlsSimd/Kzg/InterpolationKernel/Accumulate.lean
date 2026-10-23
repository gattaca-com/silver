import LeanBlsSimd.Kzg.InterpolationKernel.Aggregate

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.InterpolationKernel

open Extender Extender.Kernel

theorem CellsRep.row_sizes {cells : Slice (Array U8 2048#usize)}
    {values : _root_.Array (_root_.Array Fr)} (h : CellsRep cells values) :
    ∀ row ∈ values.toList, row.size = 64 := by
  intro row hr
  obtain ⟨j, hj, rfl⟩ := List.mem_iff_getElem.mp hr
  have hjc : j < cells.val.length := by simpa only [_root_.Array.length_toList, ← h.1] using hj
  have hjv : j < values.size := by simpa only [_root_.Array.length_toList] using hj
  have hrep := h.2 ⟨j, hjc⟩
  simpa only [getElem!_pos values j hjv, _root_.Array.getElem_toList] using hrep.1

private theorem accumulate_loop [e : KzgExternals] (hblst : BlstCorrect e)
    (cells : Slice (Array U8 2048#usize)) (indices : Slice U64) (powers : Slice blst.blst_fr)
    (values : _root_.Array (_root_.Array Fr)) (weights : List Fr)
    (hvalues : CellsRep cells values) (hindices : indices.val.length = cells.val.length)
    (hpowers : powers.val = weights.map frEncode) (hweights : cells.val.length ≤ weights.length)
    (hindicesBound : ∀ i ∈ indices.val, i.val < 128)
    (kernel : interpolation_kernel.InterpolationKernel) (hk : StateInvariant kernel)
    (columns : List Fr) (used : List Bool) (hcolumns : ColumnsRep kernel columns used)
    (k : Usize) (hklen : k.val ≤ cells.val.length) :
    ∃ next, interpolation_kernel.InterpolationKernel.interpolate_loop1 kernel cells indices powers k = ok next ∧
      StateInvariant next ∧
      let expected := ((List.range cells.val.length).drop k.val).foldl
        (Interpolation.aggregateStep (values.toList.flatMap _root_.Array.toList) weights
          (indices.val.map (·.val))) (columns, used)
      ColumnsRep next expected.1 expected.2 := by
  induction hrem : cells.val.length - k.val generalizing kernel columns used k with
  | zero =>
    have he : k.val = cells.val.length := by omega
    refine ⟨kernel, ?_, hk, ?_⟩
    · rw [interpolation_kernel.InterpolationKernel.interpolate_loop1, loop.eq_1]
      simp only [interpolation_kernel.InterpolationKernel.interpolate_loop1.body,
        UScalar.lt_equiv, Slice.len_val, Slice.length, he, lt_self_iff_false, if_false]
    · have hdrop : (List.range cells.val.length).drop cells.val.length = [] :=
        List.drop_eq_nil_of_le (by simp only [List.length_range, le_refl])
      simpa only [he, hdrop, List.foldl_nil] using hcolumns
  | succ rem ih =>
    have hkt : k.val < cells.val.length := by omega
    have hki : k.val < indices.val.length := by omega
    have hkw : k.val < weights.length := by omega
    let raw := indices.val[k.val]'hki
    let column : Usize := UScalar.cast .Usize raw
    have hraw : raw.val < 128 := hindicesBound raw (List.getElem_mem hki)
    have hcval : column.val = raw.val := by
      rw [UScalar.cast_val_eq]
      apply Nat.mod_eq_of_lt
      scalar_tac
    let cell := cells.val[k.val]'hkt
    have hcell : CellRep cell values[k.val]! := hvalues.2 ⟨k.val, hkt⟩
    have hsize : values.size = cells.val.length := hvalues.1.symm
    have hflat : ∀ j : Fin 64,
        (values.toList.flatMap _root_.Array.toList)[k.val * 64 + j.val]! = (values[k.val]!)[j.val]! := by
      intro j
      simpa only [_root_.Array.getElem!_toList] using
        Interpolation.flat_evals_get values.toList hvalues.row_sizes k.val j.val
          (by simp only [_root_.Array.length_toList]; omega) j.isLt
    obtain ⟨next, hcellcall, hn, hrep⟩ := add_cell_columns hblst kernel hk cell column k.val
      (values.toList.flatMap _root_.Array.toList) weights columns used values[k.val]!
      (by omega) hcell hcolumns hflat
    let k' : Usize := UScalar.ofNatCore (k.val + 1) (by
      have := cells.property
      scalar_tac)
    have hk' : k'.val = k.val + 1 := UScalar.ofNatCore_val_eq _
    have hinc : k + 1#usize = ok k' := scalar_add_ok k 1#usize (by
      have := cells.property
      scalar_tac)
    have hcellindex : Slice.index_usize cells k = ok cell := by simp [Slice.index_usize, hkt, cell]
    have hindex : Slice.index_usize indices k = ok raw := by simp [Slice.index_usize, hki, raw]
    have hpower : Slice.index_usize powers k = ok (frEncode weights[k.val]!) := by
      simp [Slice.index_usize, hpowers, getElem!_pos, hkw]
    have hbody : interpolation_kernel.InterpolationKernel.interpolate_loop1.body cells indices powers kernel k =
        ok (cont (next, k')) := by
      simp only [interpolation_kernel.InterpolationKernel.interpolate_loop1.body,
        UScalar.lt_equiv, Slice.len_val, Slice.length, hkt, if_true, hcellindex, hindex,
        bind_tc_ok, lift, hpower, hcellcall, hinc, column]
    obtain ⟨out, hout, ho, houtrep⟩ := ih next hn
      (Interpolation.aggregateCell (values.toList.flatMap _root_.Array.toList) weights k.val column.val columns)
      (used.set column.val true) hrep k' (by omega) (by omega)
    refine ⟨out, ?_, ho, ?_⟩
    · rw [interpolation_kernel.InterpolationKernel.interpolate_loop1, loop.eq_1]
      simpa only [hbody] using hout
    · have hget : (indices.val.map (·.val))[k.val]! = column.val := by
        simp [getElem!_pos, hki, hcval, raw]
      rw [List.drop_eq_getElem_cons (by simp only [List.length_range]; exact hkt)]
      simpa only [List.foldl_cons, List.getElem_range, hk', Interpolation.aggregateStep, hget] using houtrep

theorem accumulate_refinement [e : KzgExternals] (hblst : BlstCorrect e)
    (kernel : interpolation_kernel.InterpolationKernel) (hk : StateInvariant kernel)
    (cells : Slice (Array U8 2048#usize)) (indices : Slice U64) (powers : Slice blst.blst_fr)
    (values : _root_.Array (_root_.Array Fr)) (weights : List Fr)
    (hvalues : CellsRep cells values) (hindices : indices.val.length = cells.val.length)
    (hpowers : powers.val = weights.map frEncode) (hweights : cells.val.length ≤ weights.length)
    (hindicesBound : ∀ i ∈ indices.val, i.val < 128)
    (hcolumns : ColumnsRep kernel (List.replicate 8192 Fr.zero) (List.replicate 128 false)) :
    ∃ next, interpolation_kernel.InterpolationKernel.interpolate_loop1 kernel cells indices powers 0#usize = ok next ∧
      StateInvariant next ∧
      let expected := Interpolation.aggregateColumns (values.toList.flatMap _root_.Array.toList) weights
        (indices.val.map (·.val)) (List.replicate 8192 Fr.zero) (List.replicate 128 false)
      ColumnsRep next expected.1 expected.2 := by
  simpa only [UScalar.ofNatCore_val_eq, List.drop_zero, Interpolation.aggregateColumns,
    List.length_map, hindices] using
    accumulate_loop hblst cells indices powers values weights hvalues hindices hpowers hweights
      hindicesBound kernel hk _ _ hcolumns 0#usize (by simp)

end LeanBlsSimd.Kzg.InterpolationKernel
