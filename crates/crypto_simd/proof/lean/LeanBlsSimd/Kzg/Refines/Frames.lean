import LeanBlsSimd.Kzg.Refines.Cells

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

open private LeanBlsSimd.Kzg.cellVerdict LeanBlsSimd.Kzg.decode_cell_body LeanBlsSimd.Kzg.cell_add_ok
  from LeanBlsSimd.Kzg.Refines.Cells

namespace LeanBlsSimd.Kzg

private theorem decode_cell_loop_frame [e : KzgExternals] (h : ExternalsCorrect e)
    (self : verify.CellBatchVerifier) (cell : Aeneas.Std.Array U8 2048#usize) (j : Usize)
    (hj : j.val ≤ 64) (next : verify.CellBatchVerifier) (stop : Usize)
    (hcall : verify.CellBatchVerifier.decode_cell_loop self cell j = ok (next, stop)) :
    next = { self with evaluations := next.evaluations } := by
  induction hn : 64 - j.val generalizing self j with
  | zero =>
    have hstop : ¬ j < FIELD_ELEMENTS_PER_CELL := by
      simp only [FIELD_ELEMENTS_PER_CELL, UScalar.lt_equiv, UScalar.ofNatCore_val_eq]
      omega
    rw [verify.CellBatchVerifier.decode_cell_loop, loop.eq_1] at hcall
    simp only [verify.CellBatchVerifier.decode_cell_loop.body, hstop, if_false] at hcall
    cases hcall
    rfl
  | succ n ih =>
    have hlt : j.val < 64 := by omega
    let j' : Usize := UScalar.ofNatCore (j.val + 1) (by scalar_tac)
    have hj' : j'.val = j.val + 1 := UScalar.ofNatCore_val_eq _
    have hbody := LeanBlsSimd.Kzg.decode_cell_body h cell self j j' hlt hj'
    rw [verify.CellBatchVerifier.decode_cell_loop, loop.eq_1] at hcall
    simp only [hbody] at hcall
    cases hv : LeanBlsSimd.Kzg.cellVerdict cell j.val with
    | none =>
      simp only [hv] at hcall
      cases hcall
      rfl
    | some f =>
      cases hp : alloc.vec.Vec.push self.evaluations (frEncode f) with
      | fail err => simp only [hv, hp, bind_tc_fail] at hcall; cases hcall
      | div => simp only [hv, hp, bind_tc_div] at hcall; cases hcall
      | ok vs =>
        simp only [hv, hp, bind_tc_ok] at hcall
        have hf := ih { self with evaluations := vs } j' (by omega) hcall (by omega)
        exact hf

private theorem decode_cell_frame [e : KzgExternals] (h : ExternalsCorrect e)
    (self : verify.CellBatchVerifier) (cell : Aeneas.Std.Array U8 2048#usize)
    (b : Bool) (next : verify.CellBatchVerifier)
    (hcall : verify.CellBatchVerifier.decode_cell self cell = ok (b, next)) :
    next = { self with evaluations := next.evaluations } := by
  unfold verify.CellBatchVerifier.decode_cell at hcall
  cases hc : verify.CellBatchVerifier.decode_cell_loop self cell 0#usize with
  | fail err => simp only [hc, bind_tc_fail] at hcall; cases hcall
  | div => simp only [hc, bind_tc_div] at hcall; cases hcall
  | ok pair =>
    rcases pair with ⟨out, stop⟩
    simp only [hc, bind_tc_ok, Function.uncurry_apply_pair, Result.ok.injEq,
      Prod.mk.injEq] at hcall
    rcases hcall with ⟨_, rfl⟩
    exact decode_cell_loop_frame h self cell 0#usize (by decide) out stop hc

private theorem decode_cells_loop_frame [e : KzgExternals] (h : ExternalsCorrect e)
    (self : verify.CellBatchVerifier) (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (k : Usize) (hk : k.val ≤ cells.val.length) (next : verify.CellBatchVerifier) (stop : Usize)
    (hcall : verify.CellBatchVerifier.decode_cells_loop self cells k = ok (next, stop)) :
    next = { self with evaluations := next.evaluations } := by
  induction hn : cells.val.length - k.val generalizing self k with
  | zero =>
    have hstop : ¬ k < Slice.len cells := by
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [verify.CellBatchVerifier.decode_cells_loop, loop.eq_1] at hcall
    simp only [verify.CellBatchVerifier.decode_cells_loop.body, hstop, if_false] at hcall
    cases hcall
    rfl
  | succ n ih =>
    have hlt : k.val < cells.val.length := by omega
    have htest : k < Slice.len cells := by simpa using hlt
    have hkBound : k.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have hmax := (Slice.len cells).hBounds
      simp only [Slice.len_val, Slice.length] at hmax
      omega
    let k' : Usize := UScalar.ofNatCore (k.val + 1) hkBound
    have hk' : k'.val = k.val + 1 := UScalar.ofNatCore_val_eq _
    have hadd : k + 1#usize = ok k' := LeanBlsSimd.Kzg.cell_add_ok k 1#usize hkBound
    let cell := cells.val[k.val]'hlt
    have hindex : Slice.index_usize cells k = ok cell := by
      simp [Slice.index_usize, hlt, cell]
    rw [verify.CellBatchVerifier.decode_cells_loop, loop.eq_1] at hcall
    simp only [verify.CellBatchVerifier.decode_cells_loop.body, htest, if_true,
      hindex, bind_tc_ok] at hcall
    cases hc : verify.CellBatchVerifier.decode_cell self cell with
    | fail err => simp only [hc, bind_tc_fail] at hcall; cases hcall
    | div => simp only [hc, bind_tc_div] at hcall; cases hcall
    | ok pair =>
      rcases pair with ⟨b, out⟩
      have hf := decode_cell_frame h self cell b out hc
      cases b with
      | false =>
        simp only [hc, bind_tc_ok, Function.uncurry_apply_pair, Bool.false_eq_true,
          if_false] at hcall
        cases hcall
        exact hf
      | true =>
        simp only [hc, bind_tc_ok, Function.uncurry_apply_pair, if_true, hadd] at hcall
        have hrec := ih out k' (by omega) hcall (by omega)
        rw [hf] at hrec
        exact hrec

theorem decode_cells_frame [e : KzgExternals] (h : ExternalsCorrect e)
    (self : verify.CellBatchVerifier) (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (b : Bool) (next : verify.CellBatchVerifier)
    (hcall : verify.CellBatchVerifier.decode_cells self cells = ok (b, next)) :
    next = { self with evaluations := next.evaluations } := by
  cases hkernel : self.kernel with
  | some kernel =>
    simp only [verify.CellBatchVerifier.decode_cells, hkernel,
      InterpolationKernel.check_refinement, bind_tc_ok, Result.ok.injEq,
      Prod.mk.injEq] at hcall
    rcases hcall with ⟨_, rfl⟩
    rw [← hkernel]
  | none =>
    let empty := alloc.vec.Vec.new blst.blst_fr
    have hclear (f : blst.blst_fr) :
        alloc.vec.Vec.resize blst.blst_fr.Insts.CoreCloneClone self.evaluations 0#usize f =
          ok empty := by
      simp [alloc.vec.Vec.resize, blst.blst_fr.Insts.CoreCloneClone.clone,
        List.resize, empty, alloc.vec.Vec.new]
    let initial := { self with evaluations := empty }
    unfold verify.CellBatchVerifier.decode_cells at hcall
    simp only [hkernel, blst_ops.fr_from_u64, h.blst.fr_u64, bind_tc_ok, hclear] at hcall
    have hcall' : (do
      let (out, stop) ← verify.CellBatchVerifier.decode_cells_loop initial cells 0#usize
      ok (decide (stop = Slice.len cells), out)) = ok (b, next) := by
      simpa only [initial, hkernel] using hcall
    cases hc : verify.CellBatchVerifier.decode_cells_loop initial cells 0#usize with
    | fail err => simp only [hc, bind_tc_fail] at hcall'; cases hcall'
    | div => simp only [hc, bind_tc_div] at hcall'; cases hcall'
    | ok pair =>
      rcases pair with ⟨out, stop⟩
      simp only [hc, bind_tc_ok, Function.uncurry_apply_pair, Result.ok.injEq,
        Prod.mk.injEq] at hcall'
      rcases hcall' with ⟨_, rfl⟩
      simpa only [initial, hkernel] using
        decode_cells_loop_frame h initial cells 0#usize (by simp) out stop hc

end LeanBlsSimd.Kzg
