import LeanBlsSimd.Msm8.Chunk

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section
namespace LeanBlsSimd.Msm8
open EthLib.Cryptography Bls

theorem slice_range {α : Type} (xs : Slice α) (start finish : Usize)
    (hstart : start.val ≤ finish.val) (hfinish : finish.val ≤ xs.val.length) :
    ∃ ys, core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice α)
        xs {start, «end» := finish} = ok ys ∧
      ys.val = (xs.val.drop start.val).take (finish.val - start.val) := by
  simp only [core.slice.index.Slice.index,
    core.slice.index.SliceIndexRangeUsizeSlice.index, UScalar.le_equiv, Slice.length,
    hstart, hfinish, and_self, if_true]
  exact ⟨_, rfl, rfl⟩

theorem input_sum_split (ps : List blst.blst_p1_affine)
    (words : List ScalarWords) (start count : ℕ) :
    (((ps.drop start).zip (words.drop start)).map inputContribution).sum =
      ((((ps.drop start).take count).zip ((words.drop start).take count)).map
        inputContribution).sum +
      (((ps.drop (start + count)).zip (words.drop (start + count))).map
        inputContribution).sum := by
  have htake : ((ps.drop start).zip (words.drop start)).take count =
      ((ps.drop start).take count).zip ((words.drop start).take count) := List.take_zipWith
  have hdrop : ((ps.drop start).zip (words.drop start)).drop count =
      (ps.drop (start + count)).zip (words.drop (start + count)) := by
    simpa only [List.drop_drop, Nat.add_comm] using
      (List.drop_zipWith (f := Prod.mk) (l := ps.drop start) (l' := words.drop start)
        (i := count))
  have hsplit := List.take_append_drop count ((ps.drop start).zip (words.drop start))
  have hsum := congrArg (fun xs => (xs.map inputContribution).sum) hsplit
  simpa only [List.map_append, List.sum_append, htake, hdrop] using hsum.symm

theorem chunk_end (points : Slice blst.blst_p1_affine) (start : Usize)
    (hstart : start.val < points.val.length) :
    ∃ finish : Usize,
      (do
        let rest ← Slice.len points - start
        if rest < msm8.CHUNK then ok (Slice.len points) else start + msm8.CHUNK) = ok finish ∧
      finish.val = start.val + min 4096 (points.val.length - start.val) := by
  have hsub : start.val ≤ (Slice.len points).val := by simpa using Nat.le_of_lt hstart
  rw [sub_ok _ _ hsub]
  simp only [bind_tc_ok, msm8.CHUNK, UScalar.lt_equiv, UScalar.ofNatCore_val_eq]
  by_cases hsmall : points.val.length - start.val < 4096
  · simp only [Slice.len, Usize.ofNatCore_val_eq, hsmall, if_true]
    exact ⟨_, rfl, by change points.val.length = start.val + min 4096 (points.val.length - start.val); omega⟩
  · have hsize := (Slice.len points).hBounds
    have hadd : start.val + (4096#usize).val < 2 ^ UScalarTy.Usize.numBits := by
      change points.val.length < _ at hsize
      change start.val + 4096 < _
      omega
    simp only [Slice.len, Usize.ofNatCore_val_eq, hsmall, if_false]
    rw [add_ok _ _ hadd]
    exact ⟨_, rfl, by change start.val + 4096 = start.val + min 4096 (points.val.length - start.val); omega⟩

private theorem msm_loop_refinement
    (state : msm8.Msm8) (points : Slice blst.blst_p1_affine) (scalars : Slice ScalarWords)
    (total : G1x8) (start : Usize) (P : G1.curve.toAffine.Point)
    (halign : points.val.length = scalars.val.length)
    (hp : ∀ p ∈ points.val, Kzg.G1AffineValid p)
    (hs : ∀ s ∈ scalars.val, Kzg.limbs s.val < 2 ^ 255)
    (hstart : start.val ≤ points.val.length) (htotal : total.PointRep 0 P) :
    ∃ next out, state.msm_loop points scalars (toG1x8 total) start = ok (next, toG1x8 out) ∧
      out.PointRep 0 (P + (((points.val.drop start.val).zip
        (scalars.val.drop start.val)).map inputContribution).sum) := by
  induction hremaining : points.val.length - start.val using Nat.strong_induction_on
      generalizing state total start P with
  | h remaining ih =>
    by_cases hdone : points.val.length ≤ start.val
    · refine ⟨state, total, ?_, ?_⟩
      · rw [msm8.Msm8.msm_loop, loop.eq_1]
        simp only [msm8.Msm8.msm_loop.body, UScalar.lt_equiv, Slice.len,
          Usize.ofNatCore_val_eq, Nat.not_lt.mpr hdone, if_false]
      · simpa only [List.drop_eq_nil_of_le hdone, List.zip_nil_left, List.map_nil, List.sum_nil,
          add_zero] using htotal
    · have hlt : start.val < points.val.length := by omega
      obtain ⟨finish, hend, hfinish⟩ := chunk_end points start hlt
      have hprogress : start.val < finish.val := by omega
      have hfinishle : finish.val ≤ points.val.length := by omega
      have hcount : finish.val - start.val ≤ 4096 := by omega
      obtain ⟨ps, hps, hpsval⟩ := slice_range points start finish (by omega) hfinishle
      obtain ⟨ss, hss, hssval⟩ := slice_range scalars start finish (by omega) (by omega)
      have hchunklen : ps.val.length = ss.val.length := by
        simp only [hpsval, hssval, List.length_take, List.length_drop, halign]
      have hchunkp : ∀ p ∈ ps.val, Kzg.G1AffineValid p := by
        intro p hmem
        rw [hpsval] at hmem
        exact hp p (List.mem_of_mem_drop (List.mem_of_mem_take hmem))
      have hchunks : ∀ s ∈ ss.val, Kzg.limbs s.val < 2 ^ 255 := by
        intro s hmem
        rw [hssval] at hmem
        exact hs s (List.mem_of_mem_drop (List.mem_of_mem_take hmem))
      have hchunkbound : ps.val.length ≤ 2 ^ 24 := by
        rw [hpsval, List.length_take]
        omega
      obtain ⟨mid, part, hpart, hpartrep⟩ :=
        chunk_sum_refinement state ps ss hchunklen hchunkp hchunks hchunkbound
      have hbody : msm8.Msm8.msm_loop.body points scalars state (toG1x8 total) start =
          ok (cont (mid, toG1x8 (total.add_complete part), finish)) := by
        simp only [msm8.Msm8.msm_loop.body, UScalar.lt_equiv, Slice.len,
          Usize.ofNatCore_val_eq, hlt, if_true]
        rw [← bind_assoc_eq]
        change (do
          let finish ← (do
            let rest ← Slice.len points - start
            if rest < msm8.CHUNK then ok (Slice.len points) else start + msm8.CHUNK)
          let ps ← core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice _)
            points {start, «end» := finish}
          let ss ← core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice _)
            scalars {start, «end» := finish}
          let (part, mid) ← state.chunk_sum ps ss
          let total ← g1x8.G1x8.add_complete (toG1x8 total) part
          ok (cont (mid, total, finish))) = _
        rw [hend]
        simp only [bind_tc_ok, hps, hss, hpart, G1x8.add_complete_refines, ofG1x8_toG1x8]
      obtain ⟨next, out, hloop, hout⟩ := ih (points.val.length - finish.val) (by omega)
        mid (total.add_complete part) finish _ hfinishle (htotal.add_complete hpartrep) rfl
      refine ⟨next, out, ?_, ?_⟩
      · rw [msm8.Msm8.msm_loop, loop.eq_1]
        dsimp only
        rw [hbody]
        exact hloop
      · have heq : start.val + (finish.val - start.val) = finish.val := by omega
        rw [input_sum_split points.val scalars.val start.val (finish.val - start.val), heq,
          ← hpsval, ← hssval, ← add_assoc]
        exact hout

end LeanBlsSimd.Msm8

namespace LeanBlsSimd.Msm8
open EthLib.Cryptography Bls

theorem msm_refinement
    (state : msm8.Msm8) (points : Slice blst.blst_p1_affine) (scalars : Slice ScalarWords)
    (halign : points.val.length = scalars.val.length)
    (hp : ∀ p ∈ points.val, Kzg.G1AffineValid p)
    (hs : ∀ s ∈ scalars.val, Kzg.limbs s.val < Fr.modulus) :
    ∃ encoded next, state.msm points scalars = ok (encoded, next) ∧
      Kzg.G1Rep encoded (G1.msm (points.val.map Kzg.g1ReadAffine).toArray
        (scalars.val.map (fun w => Fr.ofNat (Kzg.limbs w.val))).toArray) := by
  have hs255 : ∀ s ∈ scalars.val, Kzg.limbs s.val < 2 ^ 255 := by
    intro s hmem
    exact (hs s hmem).trans (by norm_num [Fr.modulus])
  obtain ⟨next, out, hloop, hrep⟩ := msm_loop_refinement state points scalars
    G1x8.infinity 0#usize 0 halign hp hs255 (by simp) (WindowSums.infinity_pointRep 0)
  simp only [UScalar.ofNatCore_val_eq, List.drop_zero, zero_add] at hrep
  rw [inputContribution_sum_msm points.val scalars.val halign hp hs] at hrep
  obtain ⟨encoded, hencoded, hresult⟩ := lane_zero_pointRep (toG1x8 out) _
    (input_msm_valid points.val scalars.val hp) (by simpa only [ofG1x8_toG1x8] using hrep)
  have halign' : Slice.len points = Slice.len scalars := by
    apply UScalar.eq_of_val_eq
    simpa only [Slice.len, Usize.ofNatCore_val_eq] using halign
  refine ⟨encoded, next, ?_, hresult⟩
  simp only [msm8.Msm8.msm, halign', massert, if_true, bind_tc_ok,
    G1x8.infinity_refines, hloop]
  change (do let encoded ← msm8.lane_zero_in_blst (toG1x8 out); ok (encoded, next)) = _
  rw [hencoded]
  rfl

end LeanBlsSimd.Msm8
