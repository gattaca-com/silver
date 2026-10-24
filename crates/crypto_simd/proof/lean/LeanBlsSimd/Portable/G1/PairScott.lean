import LeanBlsSimd.Portable.G1.PairChains

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.G1.Pair
set_option maxRecDepth 4096

theorem scalar_comparison [RuntimeFeatures] (x y : Bls.Fp) (hp : Bls.G1.Valid ⟨x,y,Bls.Fp.one⟩) :
    portable.g1.G1.is_minus_sigma_squared (G1.encode (G1.timesZ (G1.timesZ ⟨x,y,Bls.Fp.one⟩)))
      (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (Bls.G1.inSubgroup ⟨x,y,Bls.Fp.one⟩) := by
  simpa only [portable.g1.G1.in_g1,G1.times_z_affine_encoded,G1.times_z_encoded,bind_tc_ok]
    using G1.in_g1_encoded x y hp

theorem finish_lane [RuntimeFeatures] (x y : Bls.Fp) (s : LaneState)
    (hp : Bls.G1.Valid ⟨x,y,Bls.Fp.one⟩)
    (hs : s.1 = false → s.2 = G1.timesZ (G1.timesZ ⟨x,y,Bls.Fp.one⟩)) :
    (if s.1 then portable.g1.G1.in_g1 (Kzg.fpEncode x).l (Kzg.fpEncode y).l else
      portable.g1.G1.is_minus_sigma_squared (G1.encode s.2) (Kzg.fpEncode x).l (Kzg.fpEncode y).l) =
      ok (Bls.G1.inSubgroup ⟨x,y,Bls.Fp.one⟩) := by
  cases hb : s.1
  · simp only [Bool.false_eq_true,if_false,hs hb]
    exact scalar_comparison x y hp
  · simp only [if_true]
    exact G1.in_g1_encoded x y hp

private theorem finish_body_zero [RuntimeFeatures] (x0 x1 y0 y1 : Bls.Fp) (s0 s1 : LaneState)
    (a b : Bool) (hp : Bls.G1.Valid ⟨x0,y0,Bls.Fp.one⟩)
    (hs : s0.1 = false → s0.2 = G1.timesZ (G1.timesZ ⟨x0,y0,Bls.Fp.one⟩)) :
    portable.g1_pair.G1Pair.in_g1_loop2.body (fields x0 x1) (fields y0 y1)
      (flags s0.1 s1.1) (encode s0.2 s1.2) (flags a b) 0#usize =
      ok (cont (flags (Bls.G1.inSubgroup ⟨x0,y0,Bls.Fp.one⟩) b,1#usize)) := by
  simp only [portable.g1_pair.G1Pair.in_g1_loop2.body,
    show 0#usize < 2#usize from by decide,if_true,flags_zero,Fp.pair_index_zero,lane_zero,bind_tc_ok]
  rw [finish_lane x0 y0 s0 hp hs]
  simp only [bind_tc_ok,flags_update_zero,
    show 0#usize+1#usize = ok 1#usize from by rw [usize_add_ok _ _ (by decide)]; rfl]

private theorem finish_body_one [RuntimeFeatures] (x0 x1 y0 y1 : Bls.Fp) (s0 s1 : LaneState)
    (a b : Bool) (hp : Bls.G1.Valid ⟨x1,y1,Bls.Fp.one⟩)
    (hs : s1.1 = false → s1.2 = G1.timesZ (G1.timesZ ⟨x1,y1,Bls.Fp.one⟩)) :
    portable.g1_pair.G1Pair.in_g1_loop2.body (fields x0 x1) (fields y0 y1)
      (flags s0.1 s1.1) (encode s0.2 s1.2) (flags a b) 1#usize =
      ok (cont (flags a (Bls.G1.inSubgroup ⟨x1,y1,Bls.Fp.one⟩),2#usize)) := by
  simp only [portable.g1_pair.G1Pair.in_g1_loop2.body,
    show 1#usize < 2#usize from by decide,if_true,flags_one,Fp.pair_index_one,lane_one,bind_tc_ok]
  rw [finish_lane x1 y1 s1 hp hs]
  simp only [bind_tc_ok,flags_update_one,
    show 1#usize+1#usize = ok 2#usize from by rw [usize_add_ok _ _ (by decide)]; rfl]

private theorem finish_step [RuntimeFeatures] (px py : Array portable.fp.Fp 2#usize)
    (e : Array Bool 2#usize) (r : portable.g1_pair.G1Pair) (m m' : Array Bool 2#usize)
    (k k' : Usize) (hb : portable.g1_pair.G1Pair.in_g1_loop2.body px py e r m k = ok (cont (m',k'))) :
    portable.g1_pair.G1Pair.in_g1_loop2 px py e r m k =
      portable.g1_pair.G1Pair.in_g1_loop2 px py e r m' k' := by
  rw [portable.g1_pair.G1Pair.in_g1_loop2,loop.eq_1]
  dsimp only
  rw [hb]
  rfl

private theorem finish_two [RuntimeFeatures] (px py : Array portable.fp.Fp 2#usize)
    (e : Array Bool 2#usize) (r : portable.g1_pair.G1Pair) (m : Array Bool 2#usize) :
    portable.g1_pair.G1Pair.in_g1_loop2 px py e r m 2#usize = ok m := by
  rw [portable.g1_pair.G1Pair.in_g1_loop2,loop.eq_1]
  simp only [portable.g1_pair.G1Pair.in_g1_loop2.body,lt_self_iff_false,if_false]

theorem finish_encoded [RuntimeFeatures] (x0 x1 y0 y1 : Bls.Fp) (s0 s1 : LaneState)
    (hp0 : Bls.G1.Valid ⟨x0,y0,Bls.Fp.one⟩) (hp1 : Bls.G1.Valid ⟨x1,y1,Bls.Fp.one⟩)
    (hs0 : s0.1 = false → s0.2 = G1.timesZ (G1.timesZ ⟨x0,y0,Bls.Fp.one⟩))
    (hs1 : s1.1 = false → s1.2 = G1.timesZ (G1.timesZ ⟨x1,y1,Bls.Fp.one⟩)) :
    portable.g1_pair.G1Pair.in_g1_loop2 (fields x0 x1) (fields y0 y1)
      (flags s0.1 s1.1) (encode s0.2 s1.2) (flags false false) 0#usize =
      ok (flags (Bls.G1.inSubgroup ⟨x0,y0,Bls.Fp.one⟩) (Bls.G1.inSubgroup ⟨x1,y1,Bls.Fp.one⟩)) := by
  rw [finish_step _ _ _ _ _ _ _ _ (finish_body_zero x0 x1 y0 y1 s0 s1 false false hp0 hs0)]
  rw [finish_step _ _ _ _ _ _ _ _ (finish_body_one x0 x1 y0 y1 s0 s1 _ false hp1 hs1)]
  exact finish_two _ _ _ _ _

theorem in_g1_encoded [RuntimeFeatures] (x0 x1 y0 y1 : Bls.Fp)
    (hp0 : Bls.G1.Valid ⟨x0,y0,Bls.Fp.one⟩) (hp1 : Bls.G1.Valid ⟨x1,y1,Bls.Fp.one⟩) :
    portable.g1_pair.G1Pair.in_g1 (fields x0 x1) (fields y0 y1) =
      ok (flags (Bls.G1.inSubgroup ⟨x0,y0,Bls.Fp.one⟩) (Bls.G1.inSubgroup ⟨x1,y1,Bls.Fp.one⟩)) := by
  have hflags : Array.repeat 2#usize false = flags false false := rfl
  simp only [portable.g1_pair.G1Pair.in_g1,from_affine_encoded,
    Z_BITS_index 0#usize (by decide),hflags,bind_tc_ok]
  change (do let (e,r) ← portable.g1_pair.G1Pair.in_g1_loop0 (fields x0 x1) (fields y0 y1)
                       (flags false false) (encode ⟨x0,y0,Bls.Fp.one⟩ ⟨x1,y1,Bls.Fp.one⟩) startBit
             let (e',r') ← portable.g1_pair.G1Pair.in_g1_loop1 e r startBit r.x r.y r.z
             portable.g1_pair.G1Pair.in_g1_loop2 (fields x0 x1) (fields y0 y1) e' r' (flags false false) 0#usize) = _
  rw [affine_chains_encoded]
  simp only [bind_tc_ok,encodeState]
  change (do let (e,r) ← portable.g1_pair.G1Pair.in_g1_loop1
               (flags (affineChain x0 y0).1 (affineChain x1 y1).1)
               (encode (affineChain x0 y0).2 (affineChain x1 y1).2) startBit
               (fields (affineChain x0 y0).2.x (affineChain x1 y1).2.x)
               (fields (affineChain x0 y0).2.y (affineChain x1 y1).2.y)
               (fields (affineChain x0 y0).2.z (affineChain x1 y1).2.z)
             portable.g1_pair.G1Pair.in_g1_loop2 (fields x0 x1) (fields y0 y1) e r (flags false false) 0#usize) = _
  rw [projective_chains_encoded (affineChain x0 y0) (affineChain x1 y1)]
  simp only [bind_tc_ok,encodeState]
  exact finish_encoded x0 x1 y0 y1 _ _ hp0 hp1 (bothChains_unflagged x0 y0) (bothChains_unflagged x1 y1)

end LeanBlsSimd.Portable.G1.Pair
