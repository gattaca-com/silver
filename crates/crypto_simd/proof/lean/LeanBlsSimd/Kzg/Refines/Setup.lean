import LeanBlsSimd.Portable.Decode.Correct
import LeanBlsSimd.Kzg.Decoder
import LeanBlsSimd.Kzg.Setup
import LeanBlsSimd.Kzg.Refines.Loop

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls
open core.iter.range core.ops.range

namespace LeanBlsSimd.Kzg

set_option maxRecDepth 16000
set_option maxHeartbeats 2000000

theorem setup_g2_zero_roundtrip :
    g2ReadAffine (g2Affine SetupPoints.g2Point0) = SetupPoints.g2Point0 := by
  simp only [g2ReadAffine, g2Affine, fp2Read, fpRead, G2.toAffine,
    Fp2.inverse, SetupArithmetic.inverse_eq]
  decide +kernel

theorem setup_g2_cell_roundtrip :
    g2ReadAffine (g2Affine SetupPoints.g2Point64) = SetupPoints.g2Point64 := by
  simp only [g2ReadAffine, g2Affine, fp2Read, fpRead, G2.toAffine,
    Fp2.inverse, SetupArithmetic.inverse_eq]
  decide +kernel

theorem setup_g2_zero_valid : G2AffineValid (g2Affine SetupPoints.g2Point0) := by
  rw [G2AffineValid, setup_g2_zero_roundtrip]
  exact ⟨rfl, arrayBytes SetupPoints.g2Bytes0,
    SetupPoints.g2_0_decoded, SetupPoints.g2_0_subgroup⟩

private theorem setup_loop (decoded : alloc.vec.Vec (Option g1_point.G1Point))
    (ps : List blst.blst_p1_affine) (hlen : ps.length = 64)
    (hd : decoded.val = ps.map some)
    (iter : Range Usize) (he : iter.end = 64#usize) (hs : iter.start.val ≤ 64)
    (acc : alloc.vec.Vec blst.blst_p1_affine) (ha : acc.val = ps.take iter.start.val) :
    ∃ out, setup.Setup.decode_loop iter decoded acc = ok out ∧ out.val = ps := by
  induction hk : 64 - iter.start.val generalizing iter acc with
  | zero =>
    have hi : iter.start.val = 64 := by omega
    have hn := Refinement.next_ge iter (by simp [he, hi])
    refine ⟨acc, ?_, ?_⟩
    · rw [setup.Setup.decode_loop, loop.eq_1]
      simp only [setup.Setup.decode_loop.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
    · simpa [hi, ← hlen] using ha
  | succ k ih =>
    have hi : iter.start.val < 64 := by omega
    have hp : iter.start.val < ps.length := by omega
    obtain ⟨iter', hi', he', hn⟩ := Refinement.next_lt iter (by simp [he, hi])
    let p := ps[iter.start.val]'hp
    have hb : acc.val.length + 1 ≤ Usize.max := by
      rw [ha, List.length_take, hlen]
      scalar_tac
    let acc' : alloc.vec.Vec blst.blst_p1_affine :=
      ⟨acc.val ++ [p], by simpa using hb⟩
    have hpush : alloc.vec.Vec.push acc p = ok acc' := by
      simp [alloc.vec.Vec.push, hb, acc']
    have ha' : acc'.val = ps.take iter'.start.val := by
      simp only [acc', ha, hi']
      rw [List.take_add_one, List.getElem?_eq_getElem hp]
      rfl
    obtain ⟨out, hout, hval⟩ := ih iter' (he'.trans he) (by omega) acc' ha' (by omega)
    refine ⟨out, ?_, hval⟩
    have hindex : alloc.vec.Vec.index
        (core.slice.index.SliceIndexUsizeSlice (Option g1_point.G1Point))
        decoded iter.start = ok (some p) := by
      simp [alloc.vec.Vec.index_usize, hd, hp, p]
    rw [setup.Setup.decode_loop, loop.eq_1]
    simp only [setup.Setup.decode_loop.body, hn, bind_tc_ok, Function.uncurry_apply_pair,
      hindex, g1_point.G1Point.into_blst, hpush]
    exact hout

theorem setup_decode_refinement [RuntimeFeatures] [KzgExternals] [UncompressG1.FallbackCorrect] :
    ∃ s, setup.Setup.decode = ok s ∧ SetupRep s := by
  let initial : alloc.vec.Vec (Option g1_point.G1Point) :=
    ⟨List.replicate 64 none, by simp; scalar_tac⟩
  have hresize : alloc.vec.Vec.resize
      (core.option.Option.Insts.CoreCloneClone g1_point.G1Point.Insts.CoreCloneClone)
      (alloc.vec.Vec.with_capacity _ FIELD_ELEMENTS_PER_CELL)
      FIELD_ELEMENTS_PER_CELL none = ok initial := by
    simp [alloc.vec.Vec.resize, alloc.vec.Vec.with_capacity, FIELD_ELEMENTS_PER_CELL,
      core.option.Option.Insts.CoreCloneClone.clone, List.resize, initial]
  let inputs := Array.to_slice trusted_setup.G1_MONOMIAL
  have hlen : (alloc.vec.Vec.deref_mut initial).1.val.length = inputs.val.length := by
    simp [initial, inputs, alloc.vec.Vec.deref_mut, Array.to_slice,
      trusted_setup.G1_MONOMIAL.property]
  obtain ⟨decoded, hdecoded, hdecodedVal, _⟩ := g1_decode_refinement inputs
    (alloc.vec.Vec.deref_mut initial).1 hlen
  let ps := rustG1Bytes.toList.map (fun b => g1Affine ((specPoint b).getD G1.zero))
  have hpslen : ps.length = 64 := by simp [ps, rustG1Bytes]
  have hps : inputs.val.map specVerdict = ps.map some := by
    simp only [inputs, Array.to_slice, ps, rustG1Bytes, List.toList_toArray, List.map_map]
    apply List.map_congr_left
    intro b hb
    have hvalid := embedded_setup_matches.2.2.2.2.2.2 (arrayBytes b)
      (by simpa [rustG1Bytes] using List.mem_map_of_mem (f := arrayBytes) hb)
    obtain ⟨p, hp⟩ := hvalid
    simp [specVerdict, hp, Function.comp_def]
  obtain ⟨g1s, hg1s, hg1val⟩ := setup_loop
    ((alloc.vec.Vec.deref_mut initial).2 decoded) ps hpslen
    (hdecodedVal.trans hps) { start := 0#usize, «end» := 64#usize } rfl (by decide)
    (alloc.vec.Vec.with_capacity _ FIELD_ELEMENTS_PER_CELL) (by simp [alloc.vec.Vec.with_capacity])
  refine ⟨⟨g1s⟩, ?_, hg1val⟩
  unfold setup.Setup.decode
  dsimp only
  rw [hresize]
  simp only [bind_tc_ok, lift, alloc.vec.Vec.deref_mut, Function.uncurry_apply_pair]
  dsimp [inputs, alloc.vec.Vec.deref_mut] at hdecoded hg1s
  rw [hdecoded]
  simp only [bind_tc_ok]
  have hg1s' := hg1s
  simp only [FIELD_ELEMENTS_PER_CELL] at hg1s'
  simp only [FIELD_ELEMENTS_PER_CELL, hg1s', bind_tc_ok]

end LeanBlsSimd.Kzg
