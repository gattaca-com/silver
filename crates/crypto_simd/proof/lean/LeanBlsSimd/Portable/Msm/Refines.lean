import LeanBlsSimd.Portable.Msm.Chunk
import LeanBlsSimd.Msm8.Refines
import LeanBlsSimd.Kzg.PortableMsmContract

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm
open LeanBlsSimd.Msm8

theorem msm_loop_refinement [RuntimeFeatures]
    (state : portable.msm.Msm) (points : Slice blst.blst_p1_affine) (scalars : Slice ScalarWords)
    (total : portable.g1.G1) (start : Usize) (P : G1.curve.toAffine.Point)
    (halign : points.val.length = scalars.val.length)
    (hp : ∀ p ∈ points.val, Kzg.G1AffineValid p)
    (hs : ∀ s ∈ scalars.val, Kzg.limbs s.val < 2 ^ 255)
    (hstart : start.val ≤ points.val.length) (htotal : Group.PointRep total P) :
    ∃ next out, state.msm_loop points scalars total start = ok (next, out) ∧
      Group.PointRep out (P + (((points.val.drop start.val).zip
        (scalars.val.drop start.val)).map inputContribution).sum) := by
  induction hremaining : points.val.length - start.val using Nat.strong_induction_on
      generalizing state total start P with
  | h remaining ih =>
    by_cases hdone : points.val.length ≤ start.val
    · refine ⟨state, total, ?_, ?_⟩
      · rw [portable.msm.Msm.msm_loop, loop.eq_1]
        simp only [portable.msm.Msm.msm_loop.body, UScalar.lt_equiv, Slice.len,
          Usize.ofNatCore_val_eq, Nat.not_lt.mpr hdone, if_false]
      · simpa only [List.drop_eq_nil_of_le hdone, List.zip_nil_left, List.map_nil, List.sum_nil,
          add_zero] using htotal
    · have hlt : start.val < points.val.length := by omega
      obtain ⟨finish, hend, hfinish⟩ := Msm8.chunk_end points start hlt
      have hend : (do let rest ← Slice.len points-start
                      if rest < portable.msm.CHUNK then ok (Slice.len points) else start+portable.msm.CHUNK) = ok finish := by
        simpa only [bls.msm8.CHUNK,portable.msm.CHUNK] using hend
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
      have hchunkbound : ps.val.length ≤ portable.msm.CHUNK.val := by
        unfold portable.msm.CHUNK
        rw [hpsval,List.length_take]
        change min _ _ ≤ 4096
        omega
      obtain ⟨mid, part, hpart, hpartrep⟩ :=
        chunk_sum_refinement state ps ss hchunklen hchunkp hchunks hchunkbound
      obtain ⟨acc,hadd,haccrep⟩ := Group.add_complete total part _ _ htotal hpartrep
      have hbody : portable.msm.Msm.msm_loop.body points scalars state total start =
          ok (cont (mid, acc, finish)) := by
        simp only [portable.msm.Msm.msm_loop.body, UScalar.lt_equiv, Slice.len,
          Usize.ofNatCore_val_eq, hlt, if_true]
        rw [← bind_assoc_eq]
        change (do
          let finish ← (do
            let rest ← Slice.len points - start
            if rest < portable.msm.CHUNK then ok (Slice.len points) else start + portable.msm.CHUNK)
          let ps ← core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice _)
            points {start, «end» := finish}
          let ss ← core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice _)
            scalars {start, «end» := finish}
          let (part, mid) ← state.chunk_sum ps ss
          let total ← portable.g1.G1.add_complete total part
          ok (cont (mid, total, finish))) = _
        rw [hend]
        simp only [bind_tc_ok, hps, hss, hpart, hadd]
      obtain ⟨next, out, hloop, hout⟩ := ih (points.val.length - finish.val) (by omega)
        mid acc finish _ hfinishle haccrep rfl
      refine ⟨next, out, ?_, ?_⟩
      · rw [portable.msm.Msm.msm_loop, loop.eq_1]
        dsimp only
        rw [hbody]
        exact hloop
      · have heq : start.val + (finish.val - start.val) = finish.val := by omega
        rw [input_sum_split points.val scalars.val start.val (finish.val - start.val), heq,
          ← hpsval, ← hssval, ← add_assoc]
        exact hout


theorem to_blst_pointRep (p : portable.g1.G1) (Q : Bls.G1) (hq : Kzg.G1Valid Q)
    (h : Group.PointRep p (Bls.G1.toPoint Q)) :
    ∃ out, p.to_blst = ok out ∧ Kzg.G1Rep out Q := by
  obtain ⟨P,rfl,hvalid,heq⟩ := h
  have hp : Kzg.G1Valid P := Kzg.g1Valid_of_groupValid hvalid (by
    rw [heq]; exact Kzg.g1Valid_subgroup hq)
  have hmatch := (Kzg.g1_toPoint_eq_iff hp hq).mp heq
  have hrep := Kzg.g1Jacobian_rep P
  refine ⟨Kzg.g1Jacobian P,?_,hrep.1,hrep.2.1.trans hmatch.1,hrep.2.2.trans hmatch.2⟩
  rfl

/-- Arbitrary scratch and representable aligned slices; chunk bounds are internal. -/
theorem msm_refinement [RuntimeFeatures]
    (state : portable.msm.Msm) (points : Slice blst.blst_p1_affine) (scalars : Slice ScalarWords)
    (halign : points.val.length = scalars.val.length)
    (hp : ∀ p ∈ points.val, Kzg.G1AffineValid p)
    (hs : ∀ s ∈ scalars.val, Kzg.limbs s.val < Fr.modulus) :
    ∃ encoded next, state.msm points scalars = ok (encoded,next) ∧
      Kzg.G1Rep encoded (Bls.G1.msm (points.val.map Kzg.g1ReadAffine).toArray
        (scalars.val.map (fun w => Fr.ofNat (Kzg.limbs w.val))).toArray) := by
  have hs255 : ∀ s ∈ scalars.val, Kzg.limbs s.val < 2^255 := by
    intro s hmem
    exact (hs s hmem).trans (by norm_num [Fr.modulus])
  obtain ⟨next,out,hloop,hrep⟩ := msm_loop_refinement state points scalars
    portable.g1.G1.INFINITY 0#usize 0 halign hp hs255 (by simp) Group.infinity_rep
  simp only [UScalar.ofNatCore_val_eq,List.drop_zero,zero_add] at hrep
  rw [inputContribution_sum_msm points.val scalars.val halign hp hs] at hrep
  obtain ⟨encoded,hencoded,hresult⟩ := to_blst_pointRep out _
    (input_msm_valid points.val scalars.val hp) hrep
  have halign' : Slice.len points = Slice.len scalars := by
    apply UScalar.eq_of_val_eq
    exact halign
  refine ⟨encoded,next,?_,hresult⟩
  simp only [portable.msm.Msm.msm,halign',massert,if_true,bind_tc_ok,hloop]
  change (do let encoded ← out.to_blst; ok (encoded,next)) = _
  rw [hencoded]
  rfl

theorem portable_msm_correct [RuntimeFeatures] : Kzg.PortableMsmCorrect :=
  ⟨msm_refinement⟩

end LeanBlsSimd.Portable.Msm
