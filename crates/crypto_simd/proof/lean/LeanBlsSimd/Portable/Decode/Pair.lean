import LeanBlsSimd.Portable.Decode.PairBasis
import LeanBlsSimd.Portable.Decode.Scalar
open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
namespace LeanBlsSimd.Portable.Decode
open DecompressG1
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

private def pairSelection [RuntimeFeatures] (x ys : Array portable.fp.Fp 2#usize) (curve : Array Bool 2#usize) : Result (Array (Option blst.blst_p1_affine) 2#usize) := do
  let b5 ← Array.index_usize (curve) 0#usize
  let members ←
    if b5
    then
      do
      let b6 ← Array.index_usize (curve) 1#usize
      if b6
      then portable.g1_pair.G1Pair.in_g1 x (ys)
      else
        let b7 ←
          if b5
          then
            do
            let f8 ← Array.index_usize x 0#usize
            let f9 ←
              Array.index_usize (ys) 0#usize
            portable.g1.G1.in_g1 f8 f9
          else ok false
        if b6
        then
          let f8 ← Array.index_usize x 1#usize
          let f9 ←
            Array.index_usize (ys) 1#usize
          let b8 ← portable.g1.G1.in_g1 f8 f9
          ok (Array.make 2#usize [ b7, b8 ] (by rfl) : Array Bool 2#usize)
        else ok (Array.make 2#usize [ b7, false ] (by rfl) : Array Bool 2#usize)
    else
      do
      let b6 ←
        if b5
        then
          do
          let f8 ← Array.index_usize x 0#usize
          let f9 ←
            Array.index_usize (ys) 0#usize
          portable.g1.G1.in_g1 f8 f9
        else ok false
      let b7 ← Array.index_usize (curve) 1#usize
      if b7
      then
        let f8 ← Array.index_usize x 1#usize
        let f9 ←
          Array.index_usize (ys) 1#usize
        let b8 ← portable.g1.G1.in_g1 f8 f9
        ok (Array.make 2#usize [ b6, b8 ] (by rfl) : Array Bool 2#usize)
      else ok (Array.make 2#usize [ b6, false ] (by rfl) : Array Bool 2#usize)
  let b6 ← Array.index_usize members 0#usize
  let o2 ←
    if b6
    then
      do
      let f8 ← Array.index_usize x 0#usize
      let f9 ← Array.index_usize (ys) 0#usize
      let bpa ← portable.decompress.point f8 f9
      ok (some bpa)
    else ok none
  let b7 ← Array.index_usize members 1#usize
  if b7
  then
    let f8 ← Array.index_usize x 1#usize
    let f9 ← Array.index_usize (ys) 1#usize
    let bpa ← portable.decompress.point f8 f9
    ok (Array.make 2#usize [ o2, some bpa ] (by rfl))
  else ok (Array.make 2#usize [ o2, none ] (by rfl))

private def pairRoots [RuntimeFeatures] (x roots : Array portable.fp.Fp 2#usize) (has_roots : Array Bool 2#usize) (larger_a larger_b : Bool) : Result (Array (Option blst.blst_p1_affine) 2#usize) := do
  let f4 ← Array.index_usize roots 0#usize
  let f5 ← portable.decompress.signed f4 larger_a
  let f6 ← Array.index_usize roots 1#usize
  let f7 ← portable.decompress.signed f6 larger_b
  let b1 ← Array.index_usize has_roots 0#usize
  let b2 ←
    if b1
    then
      do
      let f8 ← Array.index_usize (Array.make 2#usize [ f5, f7 ] (by rfl)) 0#usize
      let b3 ← portable.fp.Fp.is_zero f8
      ok (¬ b3)
    else ok false
  let b3 ← Array.index_usize has_roots 1#usize
  let b4 ←
    if b3
    then
      do
      let f8 ← Array.index_usize (Array.make 2#usize [ f5, f7 ] (by rfl)) 1#usize
      let b5 ← portable.fp.Fp.is_zero f8
      ok (¬ b5)
    else ok false
  pairSelection x (Array.make 2#usize [f5,f7] (by rfl)) (Array.make 2#usize [b2,b4] (by rfl))

private def pairCore [RuntimeFeatures] (words_a words_b : Array U64 6#usize) (larger_a larger_b : Bool) : Result (Array (Option blst.blst_p1_affine) 2#usize) := do
  let x ←
    portable.fp.Fp.mul_pair (Array.make 2#usize [ words_a, words_b ] (by rfl))
      (Array.make 2#usize [ portable.constants.R2, portable.constants.R2 ] (by rfl))
  let a1 ← portable.fp.Fp.mul_pair x x
  let x_cubed ← portable.fp.Fp.mul_pair a1 x
  let f ← Array.index_usize x_cubed 0#usize
  let f1 ← portable.fp.Fp.add f portable.constants.FOUR
  let f2 ← Array.index_usize x_cubed 1#usize
  let f3 ← portable.fp.Fp.add f2 portable.constants.FOUR
  let (roots, has_roots) ←
    portable.fp.Fp.sqrt_pair (Array.make 2#usize [ f1, f3 ] (by rfl))
  pairRoots x roots has_roots larger_a larger_b

private theorem pair_some [RuntimeFeatures] (a b : Array U8 48#usize)
    (wa wb : Array U64 6#usize) (la lb : Bool)
    (ha : portable.decompress.ordinary a = ok (some (wa,la)))
    (hb : portable.decompress.ordinary b = ok (some (wb,lb))) :
    portable.decompress.uncompress_pair_in_g1 a b = pairCore wa wb la lb := by
  rw [portable.decompress.uncompress_pair_in_g1,ha,hb]
  rfl

private theorem pairSelection_refines [RuntimeFeatures] (a b : Encoding) :
    pairSelection (Fp.pairEncode (laneX a) (laneX b)) (Fp.pairEncode (laneY a) (laneY b))
      (Array.make 2#usize [curvePoint a,curvePoint b] (by rfl)) =
      ok (Array.make 2#usize [curveVerdict a,curveVerdict b] (by rfl)) := by
  have hscalar (v : Encoding) (h : curvePoint v = true) :
      portable.g1.G1.in_g1 (Kzg.fpEncode (laneX v)).l (Kzg.fpEncode (laneY v)).l =
        ok (Bls.G1.inSubgroup (lanePoint v)) := G1.in_g1_encoded _ _ (curvePoint_valid h)
  have hpair (ha : curvePoint a = true) (hb : curvePoint b = true) :
      portable.g1_pair.G1Pair.in_g1 (Fp.pairEncode (laneX a) (laneX b)) (Fp.pairEncode (laneY a) (laneY b)) =
        ok (G1.Pair.flags (Bls.G1.inSubgroup (lanePoint a)) (Bls.G1.inSubgroup (lanePoint b))) :=
    G1.Pair.in_g1_encoded _ _ _ _ (curvePoint_valid ha) (curvePoint_valid hb)
  simp only [pairSelection,pair_bool_zero,pair_bool_one,Fp.pair_index_zero,Fp.pair_index_one,bind_tc_ok]
  by_cases ha : curvePoint a = true <;> by_cases hb : curvePoint b = true
  all_goals simp only [ha,hb,if_true,if_false,Bool.false_eq_true]
  all_goals simp (disch := assumption) only [hpair,hscalar,bind_tc_ok,G1.Pair.flags_zero,G1.Pair.flags_one,
    pair_bool_zero,pair_bool_one,point_lane,curveVerdict,ha,hb,if_true,if_false,Bool.false_eq_true]
  all_goals split_ifs <;> simp only [bind_tc_ok]

private abbrev chosenRoot (x : ZMod Bls.Fp.modulus) (s : Bool) : ZMod Bls.Fp.modulus :=
  if Kernel.isLargerRootFp x ^^ s then -x else x

private theorem pair_field_zero (x y : portable.fp.Fp) :
    Array.index_usize (Array.make 2#usize [x,y] (by rfl)) 0#usize = ok x := by
  rw [index_usize_eq _ _ (by decide)]
  rfl

private theorem pair_field_one (x y : portable.fp.Fp) :
    Array.index_usize (Array.make 2#usize [x,y] (by rfl)) 1#usize = ok y := by
  rw [index_usize_eq _ _ (by decide)]
  rfl

private theorem pairRoots_fields [RuntimeFeatures] (x0 x1 r0 r1 : ZMod Bls.Fp.modulus)
    (h0 h1 s0 s1 : Bool) :
    pairRoots (Fp.pairEncode x0 x1) (Fp.pairEncode r0 r1) (G1.Pair.flags h0 h1) s0 s1 =
      pairSelection (Fp.pairEncode x0 x1) (Fp.pairEncode (chosenRoot r0 s0) (chosenRoot r1 s1))
        (G1.Pair.flags (h0 && !Bls.Fp.isZero (chosenRoot r0 s0))
          (h1 && !Bls.Fp.isZero (chosenRoot r1 s1))) := by
  simp only [pairRoots,Fp.pair_index_zero,Fp.pair_index_one,signed_encoded,bind_tc_ok,
    G1.Pair.flags_zero,G1.Pair.flags_one]
  simp only [pair_field_zero,pair_field_one,Fp.is_zero_encoded,bind_tc_ok,decide_not,Bool.decide_coe]
  cases h0 <;> cases h1 <;> rfl

private theorem pairCore_fields [RuntimeFeatures] (wa wb : Array U64 6#usize)
    (x0 x1 : ZMod Bls.Fp.modulus) (s0 s1 : Bool)
    (hw : portable.fp.Fp.mul_pair (Array.make 2#usize [wa,wb] (by rfl))
      (Array.make 2#usize [portable.constants.R2,portable.constants.R2] (by rfl)) = ok (Fp.pairEncode x0 x1)) :
    pairCore wa wb s0 s1 =
      pairRoots (Fp.pairEncode x0 x1)
        (Fp.pairEncode (Kernel.sqrtCandidate (x0^2*x0+4)) (Kernel.sqrtCandidate (x1^2*x1+4)))
        (G1.Pair.flags (decide (Kernel.sqrtCandidate (x0^2*x0+4)^2 = x0^2*x0+4))
          (decide (Kernel.sqrtCandidate (x1^2*x1+4)^2 = x1^2*x1+4))) s0 s1 := by
  simp only [pairCore,hw,Fp.mul_pair_encoded,Fp.pair_index_zero,Fp.pair_index_one,add_four_encoded,bind_tc_ok]
  change (do let (r,h) ← portable.fp.Fp.sqrt_pair
               (Fp.pairEncode ((x0*x0)*x0+(4 : ZMod Bls.Fp.modulus)) ((x1*x1)*x1+(4 : ZMod Bls.Fp.modulus)))
             pairRoots (Fp.pairEncode x0 x1) r h s0 s1) = _
  rw [Fp.sqrt_pair_refines]
  simp only [bind_tc_ok]
  simp only [sq]
  rfl

private theorem pair_ordinary [RuntimeFeatures] (a b : Encoding) (ha : Ordinary a) (hb : Ordinary b) :
    portable.decompress.uncompress_pair_in_g1 (toArray toU8 a) (toArray toU8 b) =
      ok (Array.make 2#usize [(G1Spec.verdict a).map toBlstP1Affine,(G1Spec.verdict b).map toBlstP1Affine] (by rfl)) := by
  rw [pair_some _ _ _ _ _ _ (by rw [ordinary_refines,ordinary_some ha]) (by rw [ordinary_refines,ordinary_some hb])]
  rw [pairCore_fields _ _ _ _ _ _ (mul_words_pair ha hb),pairRoots_fields]
  change pairSelection (Fp.pairEncode (laneX a) (laneX b)) (Fp.pairEncode (laneY a) (laneY b))
    (Array.make 2#usize [curvePoint a,curvePoint b] (by rfl)) = _
  rw [pairSelection_refines,curveVerdict_spec ha,curveVerdict_spec hb]

theorem pair_refines [RuntimeFeatures] (a b : Encoding) :
    portable.decompress.uncompress_pair_in_g1 (toArray toU8 a) (toArray toU8 b) =
      ok (Array.make 2#usize [(G1Spec.verdict a).map toBlstP1Affine,(G1Spec.verdict b).map toBlstP1Affine] (by rfl)) := by
  by_cases ha : Ordinary a
  · by_cases hb : Ordinary b
    · exact pair_ordinary a b ha hb
    · simp only [portable.decompress.uncompress_pair_in_g1,ordinary_refines,ordinary_eq,ha,hb,
        if_true,if_false,bind_tc_ok,scalar_refines]
      split <;> rfl
  · simp only [portable.decompress.uncompress_pair_in_g1,ordinary_refines,ordinary_eq,ha,
      if_false,bind_tc_ok,scalar_refines]

end LeanBlsSimd.Portable.Decode
