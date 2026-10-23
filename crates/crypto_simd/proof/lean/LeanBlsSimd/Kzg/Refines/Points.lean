import LeanBlsSimd.Kzg.Decoder

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

private theorem decode_points_loop_eq
    (encodings : Slice (Aeneas.Std.Array U8 48#usize))
    (decoded : alloc.vec.Vec (Option blst.blst_p1_affine))
    (remaining : List (Option blst.blst_p1_affine))
    (points : alloc.vec.Vec blst.blst_p1_affine) (i : Usize)
    (hlen : decoded.val.length = encodings.val.length)
    (hd : decoded.val = points.val.map some ++ remaining)
    (hi : i.val = points.val.length) :
    ∃ out j, verify.decode_points_loop encodings decoded points i = ok (out, j) ∧
      decide (j = Slice.len encodings) = remaining.all Option.isSome ∧
      out.val = points.val ++ (remaining.takeWhile Option.isSome).filterMap id := by
  induction remaining generalizing points i with
  | nil =>
    have hn : i.val = encodings.val.length := by simpa [hd, hi] using hlen
    have hstop : ¬ i < Slice.len encodings := by simp [hn]
    refine ⟨points, i, ?_, ?_, by simp⟩
    · rw [verify.decode_points_loop, loop.eq_1]
      simp only [verify.decode_points_loop.body, hstop, if_false]
    · simp [UScalar.eq_equiv, hn]
  | cons verdict remaining ih =>
    have hlt : i.val < encodings.val.length := by simp [hd, hi] at hlen ⊢; omega
    have htest : i < Slice.len encodings := by simpa using hlt
    have hindex : alloc.vec.Vec.index
        (core.slice.index.SliceIndexUsizeSlice (Option blst.blst_p1_affine)) decoded i =
          ok verdict := by
      simp [alloc.vec.Vec.index_usize, hd, hi, List.getElem_append_right]
    cases verdict with
    | none =>
      refine ⟨points, i, ?_, ?_, by simp⟩
      · rw [verify.decode_points_loop, loop.eq_1]
        simp only [verify.decode_points_loop.body, htest,
          if_true, hindex, bind_tc_ok]
      · have hne : i ≠ Slice.len encodings := by
          intro h
          have hval := congrArg UScalar.val h
          simp only [Slice.len_val, Slice.length] at hval
          omega
        simp [hne]
    | some p =>
      have hb : points.val.length + 1 ≤ Usize.max := by
        have hmax := encodings.property
        simp only [hd, List.length_append, List.length_map, List.length_cons] at hlen
        omega
      let points' : alloc.vec.Vec blst.blst_p1_affine :=
        ⟨points.val ++ [p], by simpa using hb⟩
      have hpush : alloc.vec.Vec.push points p = ok points' := by
        simp [alloc.vec.Vec.push, hb, points']
      have hib : i.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
        have hmax := (Slice.len encodings).hBounds
        have hn : (Slice.len encodings).val = encodings.val.length := by simp
        omega
      let i' : Usize := UScalar.ofNatCore (i.val + 1) hib
      have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
      have hadd : i + 1#usize = ok i' := by
        show UScalar.tryMk .Usize (i.val + (1#usize).val) = ok i'
        have hb' : i.val + 1 < 2 ^ System.Platform.numBits := hib
        simp [UScalar.tryMk, UScalar.tryMkOpt, hb', Result.ofOption, i']
      have hd' : decoded.val = points'.val.map some ++ remaining := by
        simp only [points', List.map_append, List.map_cons, List.map_nil,
          List.append_assoc, List.cons_append, List.nil_append]
        exact hd
      obtain ⟨out, j, hloop, hresult, hval⟩ := ih points' i' hd'
        (by simp [points', hi', hi])
      refine ⟨out, j, ?_, by simpa using hresult, ?_⟩
      · rw [verify.decode_points_loop, loop.eq_1]
        simp only [verify.decode_points_loop.body, htest,
          if_true, hindex, bind_tc_ok, hpush, hadd]
        exact hloop
      · simpa [points', List.append_assoc] using hval

theorem decode_points_refinement [RuntimeFeatures] (h : LeanBlsSimd.G1DecoderCorrect)
    (encodings : Slice (Aeneas.Std.Array U8 48#usize))
    (decoded : alloc.vec.Vec (Option blst.blst_p1_affine))
    (points : alloc.vec.Vec blst.blst_p1_affine) :
    ∃ resultDecoded resultPoints,
      verify.decode_points encodings decoded points =
        ok ((encodings.val.map specVerdict).all Option.isSome, resultDecoded, resultPoints) ∧
      resultDecoded.val = encodings.val.map specVerdict ∧
      resultPoints.val = ((encodings.val.map specVerdict).takeWhile Option.isSome).filterMap id := by
  let emptyDecoded := alloc.vec.Vec.new (Option blst.blst_p1_affine)
  let optionClone := core.option.Option.Insts.CoreCloneClone
    blst.blst_p1_affine.Insts.CoreCloneClone
  have hclear : alloc.vec.Vec.resize optionClone decoded 0#usize none = ok emptyDecoded := by
    simp [alloc.vec.Vec.resize, optionClone, core.option.Option.Insts.CoreCloneClone.clone,
      List.resize, emptyDecoded, alloc.vec.Vec.new]
  let initial : alloc.vec.Vec (Option blst.blst_p1_affine) :=
    ⟨List.replicate encodings.val.length none, by simpa using encodings.property⟩
  have hresize : alloc.vec.Vec.resize optionClone emptyDecoded (Slice.len encodings) none =
      ok initial := by
    simp [alloc.vec.Vec.resize, optionClone, core.option.Option.Insts.CoreCloneClone.clone,
      List.resize, emptyDecoded, initial]
  obtain ⟨output, houtput, houtputVal⟩ := g1_decode_refinement h encodings (alloc.vec.Vec.deref_mut initial).1
    (by simp [initial, alloc.vec.Vec.deref_mut])
  let resultDecoded := (alloc.vec.Vec.deref_mut initial).2 output
  have hdecoded : resultDecoded.val = encodings.val.map specVerdict := houtputVal
  let emptyPoints := alloc.vec.Vec.new blst.blst_p1_affine
  have hpoints (p : blst.blst_p1_affine) :
      alloc.vec.Vec.resize blst.blst_p1_affine.Insts.CoreCloneClone points 0#usize p =
        ok emptyPoints := by
    simp [alloc.vec.Vec.resize, blst.blst_p1_affine.Insts.CoreCloneClone.clone,
      List.resize, emptyPoints, alloc.vec.Vec.new]
  obtain ⟨resultPoints, j, hloop, hresult, hval⟩ := decode_points_loop_eq encodings
    resultDecoded (encodings.val.map specVerdict) emptyPoints 0#usize
    (by simp [hdecoded]) (by simpa [emptyPoints, alloc.vec.Vec.new] using hdecoded)
    (by simp [emptyPoints])
  refine ⟨resultDecoded, resultPoints, ?_, hdecoded, ?_⟩
  · unfold verify.decode_points
    dsimp only [optionClone] at hclear hresize
    simp only [hclear, hresize, bind_tc_ok, lift, alloc.vec.Vec.deref_mut,
      Function.uncurry_apply_pair]
    dsimp only [alloc.vec.Vec.deref_mut] at houtput
    rw [houtput]
    simp only [bind_tc_ok, blst.blst_p1_affine.Insts.CoreDefaultDefault.default, hpoints]
    dsimp only [resultDecoded, alloc.vec.Vec.deref_mut] at hloop ⊢
    rw [hloop]
    simp only [bind_tc_ok, Function.uncurry_apply_pair, hresult]
  · simpa [emptyPoints, alloc.vec.Vec.new] using hval

end LeanBlsSimd.Kzg
