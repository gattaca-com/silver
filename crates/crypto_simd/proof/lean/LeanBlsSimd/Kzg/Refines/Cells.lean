import LeanBlsSimd.Kzg.InterpolationKernel.Check

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

set_option maxHeartbeats 2000000

private def cellVerdict (cell : Aeneas.Std.Array U8 2048#usize) (j : Nat) : Option Fr :=
  (bytesToBlsField ((arrayBytes cell).extract (32*j) (32*(j+1)))).toOption

private def cellVerdicts (cell : Aeneas.Std.Array U8 2048#usize) : List (Option Fr) :=
  (List.range 64).map (cellVerdict cell)

private theorem cell_tryMk_ok {ty : UScalarTy} (n : Nat) (hn : n < 2 ^ ty.numBits) :
    UScalar.tryMk ty n = ok (UScalar.ofNatCore n hn) := by
  simp [UScalar.tryMk, UScalar.tryMkOpt, hn, Result.ofOption]

private theorem cell_add_ok {ty : UScalarTy} (a b : UScalar ty)
    (h : a.val + b.val < 2 ^ ty.numBits) :
    a + b = ok (UScalar.ofNatCore (a.val + b.val) h) := cell_tryMk_ok _ h

private theorem cell_mul_ok {ty : UScalarTy} (a b : UScalar ty)
    (h : a.val * b.val < 2 ^ ty.numBits) :
    a * b = ok (UScalar.ofNatCore (a.val * b.val) h) := cell_tryMk_ok _ h

private def cellChunk (cell : Aeneas.Std.Array U8 2048#usize) (j : Nat) (hj : j < 64) :
    Aeneas.Std.Array U8 32#usize :=
  ⟨cell.val.slice (32*j) (32*(j+1)), by
    simp [List.slice, cell.property]
    omega⟩

private theorem cellChunk_bytes (cell : Aeneas.Std.Array U8 2048#usize)
    (j : Nat) (hj : j < 64) :
    arrayBytes (cellChunk cell j hj) = (arrayBytes cell).extract (32*j) (32*(j+1)) := by
  apply ByteArray.ext
  rw [ByteArray.data_extract]
  apply _root_.Array.toList_inj.mp
  simp only [arrayBytes, bytes, cellChunk, List.toList_toArray, _root_.Array.toList_extract]
  simp [List.extract_eq_take_drop, List.slice, List.map_take, List.map_drop]

private theorem decode_cell_body [e : KzgExternals] (h : ExternalsCorrect e)
    (cell : Aeneas.Std.Array U8 2048#usize) (self : verify.CellBatchVerifier)
    (j j' : Usize) (hj : j.val < 64) (hj' : j'.val = j.val + 1) :
    verify.CellBatchVerifier.decode_cell_loop.body cell self j =
      (match cellVerdict cell j.val with
      | none => ok (done (self, j))
      | some value => do
          let vs ← alloc.vec.Vec.push self.evaluations (frEncode value)
          ok (cont ({ self with evaluations := vs }, j'))) := by
  have hadd : j + 1#usize = ok j' := by
    rw [cell_add_ok j 1#usize (by scalar_tac)]
    congr 1
    apply UScalar.eq_of_val_eq
    simpa using hj'.symm
  let start : Usize := UScalar.ofNatCore (j.val * 32) (by scalar_tac)
  let stop : Usize := UScalar.ofNatCore (j'.val * 32) (by scalar_tac)
  have hstart : j * BYTES_PER_FIELD_ELEMENT = ok start := by
    simpa [BYTES_PER_FIELD_ELEMENT, start] using
      cell_mul_ok j 32#usize (by scalar_tac)
  have hstop : j' * BYTES_PER_FIELD_ELEMENT = ok stop := by
    simpa [BYTES_PER_FIELD_ELEMENT, stop] using
      cell_mul_ok j' 32#usize (by scalar_tac)
  let chunk := cellChunk cell j.val hj
  let src : Slice U8 := Array.to_slice chunk
  have hindex : core.array.Array.index
      (core.ops.index.IndexSlice (core.slice.index.SliceIndexRangeUsizeSlice U8)) cell
      { start, «end» := stop } = ok src := by
    have hstopn : 32 * (j.val + 1) ≤ 2048 := by omega
    simp [core.array.Array.index, core.ops.index.IndexSlice, core.slice.index.Slice.index,
      core.slice.index.SliceIndexRangeUsizeSlice.index, start, stop,
      hj', src, chunk, cellChunk, Array.to_slice, Nat.mul_comm, hstopn]
  have hcopy : core.slice.Slice.copy_from_slice core.marker.CopyU8
      (Array.to_slice (Array.repeat 32#usize 0#u8)) src = ok src := by
    simp [core.slice.Slice.copy_from_slice, UScalar.eq_equiv, src,
      Array.to_slice, chunk.property]
  have hback : Array.from_slice (Array.repeat 32#usize 0#u8) src = chunk := by
    apply Subtype.ext
    simp [src, Array.to_slice, chunk.property]
  have hdecode := h.blst.fr_bytes chunk
  dsimp only [chunk] at hdecode
  rw [cellChunk_bytes] at hdecode
  unfold verify.CellBatchVerifier.decode_cell_loop.body
  simp only [FIELD_ELEMENTS_PER_CELL, UScalar.lt_equiv, UScalar.ofNatCore_val_eq,
    hj, if_true, lift, bind_tc_ok, Array.to_slice_mut, Function.uncurry_apply_pair,
    hstart, hadd, hstop, hindex, hcopy, hback, blst_ops.fr_from_bytes]
  rw [hdecode]
  unfold cellVerdict
  cases (bytesToBlsField ((arrayBytes cell).extract (32*j.val) (32*(j.val+1)))).toOption <;> rfl

private def cellAccepted (xs : List (Option Fr)) : List blst.blst_fr :=
  ((xs.takeWhile Option.isSome).filterMap id).map frEncode

private theorem cellAccepted_some (f : Fr) (xs : List (Option Fr)) :
    cellAccepted (some f :: xs) = frEncode f :: cellAccepted xs := rfl

private theorem cellAccepted_length (xs : List (Option Fr)) :
    (cellAccepted xs).length ≤ xs.length := by
  induction xs with
  | nil => simp [cellAccepted]
  | cons x xs ih =>
    cases x with
    | none => simp [cellAccepted]
    | some f => simpa [cellAccepted] using Nat.succ_le_succ ih

private theorem cellAccepted_append (xs ys : List (Option Fr)) :
    cellAccepted (xs ++ ys) =
      if xs.all Option.isSome then cellAccepted xs ++ cellAccepted ys else cellAccepted xs := by
  induction xs with
  | nil => simp [cellAccepted]
  | cons x xs ih =>
    cases x with
    | none => simp [cellAccepted]
    | some f =>
      simp only [List.cons_append, List.all_cons, Option.isSome_some, Bool.true_and,
        cellAccepted_some]
      rw [ih]
      split <;> rfl

private theorem decode_cell_loop_eq [e : KzgExternals] (h : ExternalsCorrect e)
    (self : verify.CellBatchVerifier) (cell : Aeneas.Std.Array U8 2048#usize) (j : Usize)
    (hj : j.val ≤ 64) (hb : self.evaluations.val.length + (64 - j.val) ≤ Usize.max) :
    ∃ next stop, verify.CellBatchVerifier.decode_cell_loop self cell j = ok (next, stop) ∧
      decide (stop = FIELD_ELEMENTS_PER_CELL) =
        ((cellVerdicts cell).drop j.val).all Option.isSome ∧
      next.evaluations.val = self.evaluations.val ++ cellAccepted ((cellVerdicts cell).drop j.val) ∧
      next.setup = self.setup ∧ next.cosets = self.cosets ∧ next.kernel = self.kernel := by
  induction hk : 64 - j.val generalizing self j with
  | zero =>
    have he : j.val = 64 := by omega
    have hstop : ¬ j < FIELD_ELEMENTS_PER_CELL := by simp [FIELD_ELEMENTS_PER_CELL, he]
    refine ⟨self, j, ?_, ?_, ?_, rfl, rfl, rfl⟩
    · rw [verify.CellBatchVerifier.decode_cell_loop, loop.eq_1]
      simp only [verify.CellBatchVerifier.decode_cell_loop.body, hstop, if_false]
    · simp [cellVerdicts, he, FIELD_ELEMENTS_PER_CELL, UScalar.eq_equiv]
    · simp [cellVerdicts, he, cellAccepted]
  | succ k ih =>
    have hlt : j.val < 64 := by omega
    let j' : Usize := UScalar.ofNatCore (j.val + 1) (by scalar_tac)
    have hj' : j'.val = j.val + 1 := UScalar.ofNatCore_val_eq _
    have hdrop : (cellVerdicts cell).drop j.val =
        cellVerdict cell j.val :: (cellVerdicts cell).drop j'.val := by
      rw [List.drop_eq_getElem_cons (by simp [cellVerdicts, hlt])]
      simp [cellVerdicts, hj']
    have hbody := decode_cell_body h cell self j j' hlt hj'
    cases hv : cellVerdict cell j.val with
    | none =>
      refine ⟨self, j, ?_, ?_, ?_, rfl, rfl, rfl⟩
      · rw [verify.CellBatchVerifier.decode_cell_loop, loop.eq_1]
        simp only [hbody, hv]
      · have hne : j ≠ FIELD_ELEMENTS_PER_CELL := by
          intro he
          have := congrArg UScalar.val he
          simp only [FIELD_ELEMENTS_PER_CELL, UScalar.ofNatCore_val_eq] at this
          omega
        simp [hdrop, hv, hne]
      · simp [hdrop, hv, cellAccepted]
    | some f =>
      have hpushBound : self.evaluations.val.length + 1 ≤ Usize.max := by omega
      let vs : alloc.vec.Vec blst.blst_fr :=
        ⟨self.evaluations.val ++ [frEncode f], by simpa using hpushBound⟩
      let self' := { self with evaluations := vs }
      have hpush : alloc.vec.Vec.push self.evaluations (frEncode f) = ok vs := by
        simp [alloc.vec.Vec.push, hpushBound, vs]
      obtain ⟨next, stop, hloop, hresult, hval, hs, hc, hkernel⟩ := ih self' j' (by omega)
        (by simp [self', vs]; omega) (by omega)
      refine ⟨next, stop, ?_, ?_, ?_, hs, hc, hkernel⟩
      · rw [verify.CellBatchVerifier.decode_cell_loop, loop.eq_1]
        simp only [hbody, hv, hpush, bind_tc_ok]
        exact hloop
      · simpa [hdrop, hv] using hresult
      · simpa [self', vs, hdrop, hv, cellAccepted, List.append_assoc] using hval

private theorem decode_cell_eq [e : KzgExternals] (h : ExternalsCorrect e)
    (self : verify.CellBatchVerifier) (cell : Aeneas.Std.Array U8 2048#usize)
    (hb : self.evaluations.val.length + 64 ≤ Usize.max) :
    ∃ next, verify.CellBatchVerifier.decode_cell self cell =
        ok ((cellVerdicts cell).all Option.isSome, next) ∧
      next.evaluations.val = self.evaluations.val ++ cellAccepted (cellVerdicts cell) ∧
      next.setup = self.setup ∧ next.cosets = self.cosets ∧ next.kernel = self.kernel := by
  obtain ⟨next, stop, hloop, hresult, hval, hs, hc, hkernel⟩ :=
    decode_cell_loop_eq h self cell 0#usize (by decide) (by simpa using hb)
  refine ⟨next, ?_, by simpa using hval, hs, hc, hkernel⟩
  unfold verify.CellBatchVerifier.decode_cell
  rw [hloop]
  simpa only [bind_tc_ok, Function.uncurry_apply_pair, UScalar.ofNatCore_val_eq,
    List.drop_zero] using congrArg (fun b => ok (b, next)) hresult

private theorem decode_cells_loop_eq [e : KzgExternals] (h : ExternalsCorrect e)
    (self : verify.CellBatchVerifier) (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (k : Usize) (hk : k.val ≤ cells.val.length)
    (hb : self.evaluations.val.length + (cells.val.length - k.val) * 64 ≤ Usize.max) :
    ∃ next stop, verify.CellBatchVerifier.decode_cells_loop self cells k = ok (next, stop) ∧
      decide (stop = Slice.len cells) =
        (decodedCellElements (cells.val.drop k.val)).all Option.isSome ∧
      next.evaluations.val = self.evaluations.val ++
        cellAccepted (decodedCellElements (cells.val.drop k.val)) ∧
      next.setup = self.setup ∧ next.cosets = self.cosets ∧ next.kernel = self.kernel := by
  induction hn : cells.val.length - k.val generalizing self k with
  | zero =>
    have he : k.val = cells.val.length := by omega
    have hstop : ¬ k < Slice.len cells := by simp [he]
    refine ⟨self, k, ?_, ?_, ?_, rfl, rfl, rfl⟩
    · rw [verify.CellBatchVerifier.decode_cells_loop, loop.eq_1]
      simp only [verify.CellBatchVerifier.decode_cells_loop.body, hstop, if_false]
    · simp [he, decodedCellElements, UScalar.eq_equiv]
    · simp [he, decodedCellElements, cellAccepted]
  | succ n ih =>
    have hlt : k.val < cells.val.length := by omega
    have htest : k < Slice.len cells := by simpa using hlt
    have hkBound : k.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have hmax := (Slice.len cells).hBounds
      simp only [Slice.len_val, Slice.length] at hmax
      omega
    let k' : Usize := UScalar.ofNatCore (k.val + 1) hkBound
    have hk' : k'.val = k.val + 1 := UScalar.ofNatCore_val_eq _
    have hadd : k + 1#usize = ok k' := cell_add_ok k 1#usize hkBound
    let cell := cells.val[k.val]'hlt
    have hindex : Slice.index_usize cells k = ok cell := by
      simp [Slice.index_usize, hlt, cell]
    have hdrop : decodedCellElements (cells.val.drop k.val) =
        cellVerdicts cell ++ decodedCellElements (cells.val.drop k'.val) := by
      rw [hk']
      unfold decodedCellElements
      rw [List.drop_eq_getElem_cons hlt]
      rfl
    obtain ⟨afterCell, hdecode, hvals, hs, hc, hkernel⟩ := decode_cell_eq h self cell (by omega)
    have hsize : (cellAccepted (cellVerdicts cell)).length ≤ 64 := by
      simpa [cellVerdicts] using cellAccepted_length (cellVerdicts cell)
    cases hsuccess : (cellVerdicts cell).all Option.isSome with
    | false =>
      refine ⟨afterCell, k, ?_, ?_, ?_, hs, hc, hkernel⟩
      · rw [verify.CellBatchVerifier.decode_cells_loop, loop.eq_1]
        simp only [verify.CellBatchVerifier.decode_cells_loop.body, htest, if_true,
          hindex, bind_tc_ok, hdecode, Function.uncurry_apply_pair, hsuccess, Bool.false_eq_true,
          if_false]
      · have hne : k ≠ Slice.len cells := by
          intro he
          have := congrArg UScalar.val he
          simp only [Slice.len_val, Slice.length] at this
          omega
        simp [hdrop, hsuccess, hne]
      · simpa [hdrop, cellAccepted_append, hsuccess] using hvals
    | true =>
      obtain ⟨next, stop, hloop, hresult, hval, hs', hc', hkernel'⟩ := ih afterCell k' (by omega)
        (by rw [hvals, List.length_append]; omega) (by omega)
      refine ⟨next, stop, ?_, ?_, ?_, hs'.trans hs, hc'.trans hc, hkernel'.trans hkernel⟩
      · rw [verify.CellBatchVerifier.decode_cells_loop, loop.eq_1]
        simp only [verify.CellBatchVerifier.decode_cells_loop.body, htest, if_true,
          hindex, bind_tc_ok, hdecode, Function.uncurry_apply_pair, hsuccess, hadd]
        exact hloop
      · simpa [hdrop, hsuccess] using hresult
      · simpa [hvals, hdrop, cellAccepted_append, hsuccess, List.append_assoc] using hval

theorem decode_cells_refinement [e : KzgExternals] (h : ExternalsCorrect e)
    (v : verify.CellBatchVerifier) (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (hb : cells.val.length * 2048 ≤ Isize.max.toNat) :
    ∃ next, verify.CellBatchVerifier.decode_cells v cells =
      ok ((decodedCellElements cells.val).all Option.isSome, next) ∧
      (v.kernel = none → next.evaluations.val =
        (((decodedCellElements cells.val).takeWhile Option.isSome).filterMap id).map frEncode) ∧
      next.setup = v.setup ∧ next.cosets = v.cosets ∧ next.kernel = v.kernel := by
  cases hkernelCase : v.kernel with
  | some kernel =>
    refine ⟨v, ?_, ?_, rfl, rfl, hkernelCase⟩
    · simp [verify.CellBatchVerifier.decode_cells, hkernelCase,
        InterpolationKernel.check_refinement]
    · simp
  | none =>
    have hmax : Isize.max.toNat ≤ Usize.max := by
      rcases System.Platform.numBits_eq with h | h <;>
        norm_num [Isize.max, Isize.numBits, Usize.max, Usize.numBits,
          UScalarTy.numBits, IScalarTy.numBits, h]
    have hcapacity : cells.val.length * 64 ≤ Usize.max := by omega
    let empty := alloc.vec.Vec.new blst.blst_fr
    have hclear (f : blst.blst_fr) :
        alloc.vec.Vec.resize blst.blst_fr.Insts.CoreCloneClone v.evaluations 0#usize f =
          ok empty := by
      simp [alloc.vec.Vec.resize, blst.blst_fr.Insts.CoreCloneClone.clone,
        List.resize, empty, alloc.vec.Vec.new]
    let initial := { v with evaluations := empty }
    obtain ⟨next, stop, hloop, hresult, hval, hs, hc, hkernel⟩ :=
      decode_cells_loop_eq h initial cells 0#usize (by simp)
        (by simpa [initial, empty, alloc.vec.Vec.new] using hcapacity)
    refine ⟨next, ?_, ?_, hs, hc, by simpa [initial, hkernelCase] using hkernel⟩
    · unfold verify.CellBatchVerifier.decode_cells
      simp only [hkernelCase, blst_ops.fr_from_u64, h.blst.fr_u64, bind_tc_ok, hclear]
      dsimp only [initial] at hloop
      simp only [hkernelCase] at hloop
      rw [hloop]
      simpa only [bind_tc_ok, Function.uncurry_apply_pair, UScalar.ofNatCore_val_eq,
        List.drop_zero] using congrArg (fun b => ok (b, next)) hresult
    · intro _
      simpa [initial, empty, alloc.vec.Vec.new, cellAccepted] using hval

end LeanBlsSimd.Kzg
