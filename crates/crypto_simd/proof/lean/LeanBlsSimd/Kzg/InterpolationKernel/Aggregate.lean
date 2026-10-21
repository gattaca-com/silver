import LeanBlsSimd.Kzg.InterpolationKernel.AddCell
import LeanBlsSimd.Kzg.Refines.Cosets

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.InterpolationKernel

open Extender Extender.Kernel

def ColumnsRep (kernel : interpolation_kernel.InterpolationKernel)
    (columns : List Fr) (used : List Bool) : Prop :=
  columns.length = 8192 ∧ used.length = 128 ∧ kernel.used.val = used ∧
  ∀ c : Fin 128,
    (used[c.val]! = true → ∀ v : Fin 8,
      Represents kernel.columns.val[c.val * 8 + v.val]!
        (fun lane => (Interpolation.columnView columns c.val)[8 * v.val + lane.val]!)) ∧
    (used[c.val]! = false → ∀ j : Fin 64, (Interpolation.columnView columns c.val)[j.val]! = 0)

private theorem weighted_column (evaluations powers columns : List Fr) (k c d : Nat)
    (values : _root_.Array Fr) (hlen : columns.length = 8192) (hc : c < 128) (hd : d < 128)
    (hvalues : ∀ j : Fin 64, evaluations[k * 64 + j.val]! = values[j.val]!) :
    Interpolation.columnView (Interpolation.aggregateCell evaluations powers k c columns) d =
      if d = c then weightedCell (Interpolation.columnView columns d) values powers[k]!
      else Interpolation.columnView columns d := by
  rw [Interpolation.columnView_aggregateCell _ _ _ _ _ _ hlen hc hd]
  split
  · apply _root_.Array.ext
    · simp [weightedCell]
    · intro j hj hj'
      have hj64 : j < 64 := by simpa using hj
      simp only [_root_.Array.getElem_ofFn, weightedCell, hvalues ⟨j, hj64⟩]
  · rfl

theorem add_cell_columns [e : KzgExternals] (hblst : BlstCorrect e)
    (kernel : interpolation_kernel.InterpolationKernel) (hk : StateInvariant kernel)
    (cell : Array U8 2048#usize) (column : Usize) (k : Nat)
    (evaluations powers columns : List Fr) (used : List Bool) (values : _root_.Array Fr)
    (hc : column.val < 128) (hcell : CellRep cell values) (hcolumns : ColumnsRep kernel columns used)
    (hvalues : ∀ j : Fin 64, evaluations[k * 64 + j.val]! = values[j.val]!) :
    ∃ next, interpolation_kernel.InterpolationKernel.add_cell kernel cell column (frEncode powers[k]!) = ok next ∧
      StateInvariant next ∧ ColumnsRep next
        (Interpolation.aggregateCell evaluations powers k column.val columns) (used.set column.val true) := by
  obtain ⟨next, hcall, hn, _, hu, hr, hframe⟩ := add_cell_refinement hblst kernel hk
    cell column powers[k]! values (Interpolation.columnView columns column.val) hc hcell
    (by simpa only [hcolumns.2.2.1] using (hcolumns.2.2.2 ⟨column.val, hc⟩).1)
    (by simpa only [hcolumns.2.2.1] using (hcolumns.2.2.2 ⟨column.val, hc⟩).2)
  refine ⟨next, hcall, hn, by simpa only [Interpolation.aggregateCell_length] using hcolumns.1,
    by simpa only [List.length_set] using hcolumns.2.1, by simpa only [hcolumns.2.2.1] using hu, ?_⟩
  intro c
  rw [weighted_column evaluations powers columns k column.val c.val values hcolumns.1 hc c.isLt hvalues]
  by_cases he : c.val = column.val
  · have hused : (used.set column.val true)[c.val]! = true := by
      simp only [List.getElem!_set, he, hcolumns.2.1, hc]
    rw [hused]
    simp only [he, if_true, Bool.true_eq_false, false_implies, true_implies, and_true]
    exact hr
  · have hused : (used.set column.val true)[c.val]! = used[c.val]! :=
      List.getElem!_set_ne used column.val c.val true (by omega)
    simp only [he, if_false, hused]
    refine ⟨?_, (hcolumns.2.2.2 c).2⟩
    intro htrue v
    rw [hframe (c.val * 8 + v.val) (by omega)]
    exact (hcolumns.2.2.2 c).1 htrue v

private theorem clear_loop (kernel : interpolation_kernel.InterpolationKernel)
    (hk : StateInvariant kernel) (c : Usize) (hc : c.val ≤ 128)
    (hclear : ∀ i : Fin 128, i.val < c.val → kernel.used.val[i.val]! = false) :
    ∃ next, interpolation_kernel.InterpolationKernel.interpolate_loop0 kernel c = ok next ∧
      StateInvariant next ∧ next.used.val = List.replicate 128 false := by
  induction hrem : 128 - c.val generalizing kernel c with
  | zero =>
    have he : c.val = 128 := by omega
    refine ⟨kernel, ?_, hk, ?_⟩
    · rw [interpolation_kernel.InterpolationKernel.interpolate_loop0, loop.eq_1]
      simp only [interpolation_kernel.InterpolationKernel.interpolate_loop0.body,
        cells_per_ext_blob_eq, bind_tc_ok, UScalar.lt_equiv, UScalar.ofNatCore_val_eq,
        he, lt_self_iff_false, if_false]
    · apply List.ext_getElem
      · simpa using hk.2.2.2.1
      · intro i hi hj
        have hi128 : i < 128 := by simpa only [hk.2.2.2.1] using hi
        rw [List.getElem_replicate]
        simpa only [getElem!_pos kernel.used.val i hi] using hclear ⟨i, hi128⟩ (by omega)
  | succ rem ih =>
    have hct : c.val < 128 := by omega
    have hcl : c.val < kernel.used.val.length := by rw [hk.2.2.2.1]; exact hct
    let next := { kernel with used := alloc.vec.Vec.set kernel.used c false }
    let c' : Usize := UScalar.ofNatCore (c.val + 1) (by scalar_tac)
    have hc' : c'.val = c.val + 1 := UScalar.ofNatCore_val_eq _
    have hn : StateInvariant next :=
      ⟨hk.1, hk.2.1, hk.2.2.1, by simpa [next, alloc.vec.Vec.set] using hk.2.2.2.1,
        hk.2.2.2.2⟩
    have hp : ∀ i : Fin 128, i.val < c'.val → next.used.val[i.val]! = false := by
      intro i hi
      by_cases he : i.val = c.val
      · simp only [next, alloc.vec.Vec.set, he, List.getElem!_set, hcl]
      · rw [show next.used.val = kernel.used.val.set c.val false from rfl,
          List.getElem!_set_ne kernel.used.val c.val i.val false (by omega)]
        exact hclear i (by omega)
    have hmut : alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice Bool) kernel.used c =
        ok (kernel.used.val[c.val]!, alloc.vec.Vec.set kernel.used c) := by
      simp [alloc.vec.Vec.index_mut_usize, alloc.vec.Vec.index_usize, getElem!_pos, hcl]
    have hinc : c + 1#usize = ok c' := scalar_add_ok c 1#usize (by scalar_tac)
    obtain ⟨out, hout, ho, hu⟩ := ih next hn c' (by omega) hp (by omega)
    refine ⟨out, ?_, ho, hu⟩
    rw [interpolation_kernel.InterpolationKernel.interpolate_loop0, loop.eq_1]
    have hbody : interpolation_kernel.InterpolationKernel.interpolate_loop0.body kernel c =
        ok (cont (next, c')) := by
      simp only [interpolation_kernel.InterpolationKernel.interpolate_loop0.body,
        cells_per_ext_blob_eq, bind_tc_ok, UScalar.lt_equiv, UScalar.ofNatCore_val_eq,
        hct, if_true, hmut, Function.uncurry_apply_pair, hinc, next]
    simpa only [hbody] using hout

theorem clear_refinement (kernel : interpolation_kernel.InterpolationKernel)
    (hk : StateInvariant kernel) :
    ∃ next, interpolation_kernel.InterpolationKernel.interpolate_loop0 kernel 0#usize = ok next ∧
      StateInvariant next ∧ ColumnsRep next (List.replicate 8192 Fr.zero) (List.replicate 128 false) := by
  obtain ⟨next, hcall, hn, hu⟩ := clear_loop kernel hk 0#usize (by simp) (by simp)
  refine ⟨next, hcall, hn, List.length_replicate .., List.length_replicate .., hu, ?_⟩
  intro c
  have hflag : (List.replicate 128 false)[c.val]! = false := by
    rw [getElem!_pos (List.replicate 128 false) c.val (by simpa only [List.length_replicate] using c.isLt),
      List.getElem_replicate]
  refine ⟨by intro h; rw [hflag] at h; contradiction, ?_⟩
  intro _ j
  rw [Interpolation.columnView_zero c.val c.isLt]
  simp only [_root_.Array.getElem!_replicate, j.isLt]
  rfl

end LeanBlsSimd.Kzg.InterpolationKernel
