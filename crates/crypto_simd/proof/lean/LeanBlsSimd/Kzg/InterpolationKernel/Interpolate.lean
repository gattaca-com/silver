import LeanBlsSimd.Kzg.InterpolationKernel.Accumulate
import LeanBlsSimd.Kzg.InterpolationKernel.Model
import LeanBlsSimd.Kzg.InterpolationKernel.Roots
import LeanBlsSimd.Kzg.InterpolationKernel.Store

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.InterpolationKernel

open Extender Extender.Kernel

private def RemainingColumns (kernel : interpolation_kernel.InterpolationKernel)
    (columns : List Fr) (used : List Bool) (count : Nat) : Prop :=
  kernel.used.val = used ∧ ∀ d : Fin 128, count ≤ d.val → used[d.val]! = true →
    ∀ v : Fin 8, Represents kernel.columns.val[d.val*8+v.val]!
      (fun lane => (Interpolation.columnView columns d.val)[8*v.val+lane.val]!)

private theorem columns_loop (kernel : interpolation_kernel.InterpolationKernel)
    (hk : StateInvariant kernel) (columns total : List Fr) (used : List Bool)
    (ht : total.length = 64) (c : Usize) (hc : c.val ≤ 128)
    (hr : RemainingColumns kernel columns used c.val)
    (sums : Array fr8.Fr8 8#usize) (hs : DataRep (Array.to_slice sums) total.toArray) :
    ∃ next sums', interpolation_kernel.InterpolationKernel.interpolate_loop2 kernel c sums =
        ok (next, sums') ∧ StateInvariant next ∧
      DataRep (Array.to_slice sums')
        (((List.range 128).drop c.val).foldl (Interpolation.totalStep columns used) total).toArray := by
  induction hrem : 128-c.val generalizing kernel total sums c with
  | zero =>
    have hc128 : c.val = 128 := by omega
    refine ⟨kernel, sums, ?_, hk, ?_⟩
    · rw [interpolation_kernel.InterpolationKernel.interpolate_loop2, loop.eq_1]
      simp only [interpolation_kernel.InterpolationKernel.interpolate_loop2.body,
        cells_per_ext_blob_eq, bind_tc_ok, UScalar.lt_equiv, UScalar.ofNatCore_val_eq,
        hc128, lt_self_iff_false, if_false]
    · simpa only [hc128, List.length_range, List.drop_length, List.foldl_nil] using hs
  | succ rem ih =>
    have hct : c.val < 128 := by omega
    have hcl : c.val < kernel.used.val.length := by rw [hk.2.2.2.1]; exact hct
    let c' : Usize := UScalar.ofNatCore (c.val+1) (by scalar_tac)
    have hc' : c'.val = c.val+1 := UScalar.ofNatCore_val_eq _
    have hinc : c+1#usize = ok c' := scalar_add_ok c 1#usize (by scalar_tac)
    obtain ⟨after, sumsAfter, hstep, ha, hremaining, hsum⟩ :
        ∃ after sumsAfter,
          (if used[c.val]! then interpolation_kernel.InterpolationKernel.add_column kernel c sums
            else ok (kernel, sums)) = ok (after, sumsAfter) ∧ StateInvariant after ∧
          RemainingColumns after columns used c'.val ∧
          DataRep (Array.to_slice sumsAfter) (Interpolation.totalStep columns used total c.val).toArray := by
      cases hflag : used[c.val]! with
      | false =>
        refine ⟨kernel, sums, by simp only [Bool.false_eq_true, if_false], hk,
          ⟨hr.1, fun d hd hu => hr.2 d (by omega) hu⟩, ?_⟩
        simpa only [Interpolation.totalStep, hflag, Bool.false_eq_true, if_false] using hs
      | true =>
        obtain ⟨next, sums', hcall, hn, _, hu, hframe, hrep⟩ :=
          add_column_refinement kernel c sums (Interpolation.columnView columns c.val) total.toArray
            hk hct (Interpolation.columnView_size columns c.val) cell_roots_valid.2
            (hr.2 ⟨c.val, hct⟩ (Nat.le_refl _) hflag) hs
        refine ⟨next, sums', by simpa only [hflag, if_true] using hcall, hn, ?_, ?_⟩
        · refine ⟨by rw [hu]; exact hr.1, ?_⟩
          intro d hd hused v
          rw [hframe (d.val*8+v.val) (Or.inr (by omega))]
          exact hr.2 d (by omega) hused v
        · rw [columnStep_eq_totalStep columns total used c.val ht hflag] at hrep
          exact hrep
    have hindex : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Bool)
        kernel.used c = ok used[c.val]! := by
      have hget : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Bool)
          kernel.used c = ok kernel.used.val[c.val]! := by
        simp [alloc.vec.Vec.index_usize, List.getElem?_eq_getElem hcl]
      simpa only [hr.1] using hget
    have hbody : interpolation_kernel.InterpolationKernel.interpolate_loop2.body kernel c sums =
        ok (cont (after, c', sumsAfter)) := by
      simp only [interpolation_kernel.InterpolationKernel.interpolate_loop2.body,
        cells_per_ext_blob_eq, bind_tc_ok, UScalar.lt_equiv, UScalar.ofNatCore_val_eq,
        hct, if_true, hindex, hstep, Function.uncurry_apply_pair, hinc]
    obtain ⟨next, sums', hloop, hn, hrep⟩ := ih after ha
      (Interpolation.totalStep columns used total c.val)
      (Interpolation.totalStep_length columns used total c.val ht) c' (by omega)
      hremaining sumsAfter hsum (by omega)
    refine ⟨next, sums', ?_, hn, ?_⟩
    · rw [interpolation_kernel.InterpolationKernel.interpolate_loop2, loop.eq_1]
      simpa only [hbody] using hloop
    · rw [List.drop_eq_getElem_cons (by simp only [List.length_range]; exact hct)]
      simpa only [List.foldl_cons, List.getElem_range, hc'] using hrep

private theorem zero_sums (zero : fr8.Fr8) (hz : Represents zero (fun _ => 0)) :
    DataRep (Array.to_slice (Array.repeat 8#usize zero))
      (List.replicate 64 Fr.zero).toArray := by
  constructor
  · simp only [Array.to_slice, Array.repeat, List.length_replicate, List.size_toArray]
    rfl
  · intro v
    have hv : v.val < 8 := by simpa only [Array.to_slice, Array.repeat, List.length_replicate] using v.isLt
    have hi (lane : Fin 8) : 8*v.val+lane.val < 64 := by omega
    simpa only [Array.to_slice, Array.repeat, List.getElem_replicate,
      List.getElem!_toArray, List.getElem!_replicate, hi] using hz

theorem interpolate_refinement [e : KzgExternals] (hblst : BlstCorrect e)
    (kernel : interpolation_kernel.InterpolationKernel) (hk : StateInvariant kernel)
    (cells : Slice (Array U8 2048#usize)) (indices : Slice U64)
    (powers coefficients : Slice blst.blst_fr) (evals : _root_.Array CosetEvals)
    (weights : _root_.Array Fr) (hcell : CellsRep cells evals)
    (hs : Model.RliInputs (indices.val.map (·.val)).toArray evals weights)
    (hp : powers.val = weights.toList.map frEncode) (ho : coefficients.val.length = 64) :
    ∃ next out, interpolation_kernel.InterpolationKernel.interpolate kernel cells indices powers coefficients =
        ok (next, out) ∧ StateInvariant next ∧
      out.val = (Model.columnRli (indices.val.map (·.val)).toArray evals weights).toList.map frEncode := by
  have hindices : indices.val.length = cells.val.length := by
    have hh := hs.1
    simp only [List.size_toArray, List.length_map] at hh
    simpa only [hcell.1] using hh
  have hweights : cells.val.length ≤ weights.toList.length := by
    have hh := hs.2.1
    simp only [List.size_toArray, List.length_map] at hh
    simp only [_root_.Array.length_toList]
    omega
  have hib : ∀ i ∈ indices.val, i.val < 128 := by
    intro i hi
    exact hs.2.2.1 i.val (by simpa only [List.mem_toArray] using List.mem_map.mpr ⟨i, hi, rfl⟩)
  obtain ⟨cleared, hclear, hcleared, hcolumns⟩ := clear_refinement kernel hk
  obtain ⟨aggregated, hacc, ha, har⟩ := accumulate_refinement hblst cleared hcleared
    cells indices powers evals weights.toList hcell hindices hp hweights hib hcolumns
  let model := Interpolation.aggregateColumns (evals.toList.flatMap _root_.Array.toList)
    weights.toList (indices.val.map (·.val)) (List.replicate 8192 Fr.zero) (List.replicate 128 false)
  change ColumnsRep aggregated model.1 model.2 at har
  have hr : RemainingColumns aggregated model.1 model.2 0 :=
    ⟨har.2.2.1, fun d _ hu => (har.2.2.2 d).1 hu⟩
  obtain ⟨zero, hzero, hz⟩ := zero_refinement
  obtain ⟨next, sums, hloop, hn, hrep⟩ := columns_loop aggregated ha model.1
    (List.replicate 64 Fr.zero) model.2 (List.length_replicate ..) 0#usize (by decide) hr
    (Array.repeat 8#usize zero) (zero_sums zero hz)
  have hmodel : ((List.range 128).foldl (Interpolation.totalStep model.1 model.2)
      (List.replicate 64 Fr.zero)).toArray =
      Model.columnRli (indices.val.map (·.val)).toArray evals weights := by
    simpa only [List.toList_toArray, model] using
      Interpolation.aggregate_columnRli (indices.val.map (·.val)).toArray evals weights hs
  simp only [UScalar.ofNatCore_val_eq, List.drop_zero, hmodel] at hrep
  obtain ⟨out, hstore, hout⟩ := store_canonical_refinement hblst sums _ hrep coefficients ho
  refine ⟨next, out, ?_, hn, hout⟩
  simp only [interpolation_kernel.InterpolationKernel.interpolate, hclear, hacc,
    hzero, hloop, hstore, bind_tc_ok, Function.uncurry_apply_pair]

end LeanBlsSimd.Kzg.InterpolationKernel
