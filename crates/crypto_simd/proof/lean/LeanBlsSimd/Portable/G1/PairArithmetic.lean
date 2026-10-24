import LeanBlsSimd.Portable.G1.Scott
import LeanBlsSimd.Portable.Fp.PairArithmetic

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.G1.Pair
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

abbrev fields := Fp.pairEncode

def flags (a b : Bool) : Array Bool 2#usize := Array.make 2#usize [a,b] (by rfl)

def encode (P Q : Bls.G1) : portable.g1_pair.G1Pair :=
  ⟨fields P.x Q.x,fields P.y Q.y,fields P.z Q.z⟩

theorem add_fields (a b c d : Bls.Fp) :
    portable.g1_pair.add (fields a b) (fields c d) = ok (fields (a+c) (b+d)) := by
  simp only [portable.g1_pair.add,Fp.pair_index_zero,Fp.pair_index_one,Fp.add_encoded,bind_tc_ok]
  rfl

theorem sub_fields (a b c d : Bls.Fp) :
    portable.g1_pair.sub (fields a b) (fields c d) = ok (fields (a-c) (b-d)) := by
  simp only [portable.g1_pair.sub,Fp.pair_index_zero,Fp.pair_index_one,Fp.sub_encoded,bind_tc_ok]
  rfl

theorem double_fields (a b : Bls.Fp) :
    portable.g1_pair.double (fields a b) = ok (fields (a+a) (b+b)) := by
  simp only [portable.g1_pair.double,portable.fp.Fp.double,
    Fp.pair_index_zero,Fp.pair_index_one,Fp.add_encoded,bind_tc_ok]
  rfl

theorem mul_fields [RuntimeFeatures] (a b c d : Bls.Fp) :
    portable.g1_pair.mul (fields a b) (fields c d) = ok (fields (a*c) (b*d)) :=
  Fp.mul_pair_encoded a b c d

theorem square_fields [RuntimeFeatures] (a b : Bls.Fp) :
    portable.g1_pair.square (fields a b) = ok (fields (a*a) (b*b)) :=
  Fp.mul_pair_encoded a b a b

theorem double_encoded [RuntimeFeatures] (P Q : Bls.G1) :
    portable.g1_pair.G1Pair.double (encode P Q) =
      ok (encode (Kzg.PortableG1.doubleValues P) (Kzg.PortableG1.doubleValues Q)) := by
  simp only [portable.g1_pair.G1Pair.double,encode,square_fields,add_fields,sub_fields,
    double_fields,mul_fields,bind_tc_ok]
  rfl

theorem from_affine_encoded (x0 x1 y0 y1 : Bls.Fp) :
    portable.g1_pair.G1Pair.from_affine (fields x0 x1) (fields y0 y1) =
      ok (encode ⟨x0,y0,Bls.Fp.one⟩ ⟨x1,y1,Bls.Fp.one⟩) := by
  have hone := Fp.rep_eq_encode Kzg.portableFpRep_one
  simp only [portable.g1_pair.G1Pair.from_affine,hone]
  rfl

theorem lane_zero (P Q : Bls.G1) :
    portable.g1_pair.G1Pair.lane (encode P Q) 0#usize = ok (G1.encode P) := by
  simp only [portable.g1_pair.G1Pair.lane,encode,Fp.pair_index_zero,bind_tc_ok]
  rfl

theorem lane_one (P Q : Bls.G1) :
    portable.g1_pair.G1Pair.lane (encode P Q) 1#usize = ok (G1.encode Q) := by
  simp only [portable.g1_pair.G1Pair.lane,encode,Fp.pair_index_one,bind_tc_ok]
  rfl

theorem flags_zero (a b : Bool) : Array.index_usize (flags a b) 0#usize = ok a := by
  rw [index_usize_eq _ _ (by decide)]
  rfl

theorem flags_one (a b : Bool) : Array.index_usize (flags a b) 1#usize = ok b := by
  rw [index_usize_eq _ _ (by decide)]
  rfl

private theorem bool_or_result (a b : Bool) : (if a then ok true else ok b : Result Bool) =
    ok (a || b) := by cases a <;> rfl

theorem flags_update_zero (a b c : Bool) :
    Array.update (flags a b) 0#usize c = ok (flags c b) := by
  rw [update_eq _ _ _ (by decide)]
  rfl

theorem flags_update_one (a b c : Bool) :
    Array.update (flags a b) 1#usize c = ok (flags a c) := by
  rw [update_eq _ _ _ (by decide)]
  rfl

private theorem flags_body_zero [RuntimeFeatures] (z0 z1 w0 w1 h0 h1 : Bls.Fp) (a b : Bool) :
    portable.g1_pair.G1Pair.add_loop.body (fields z0 z1) (fields w0 w1) (fields h0 h1)
      (flags a b) 0#usize =
      ok (cont (flags (h0.isZero || (z0.isZero || w0.isZero)) b,1#usize)) := by
  simp only [portable.g1_pair.G1Pair.add_loop.body,show 0#usize < 2#usize from by decide,if_true,
    Fp.pair_index_zero,Fp.is_zero_encoded,bind_tc_ok,bool_or_result,flags_update_zero,
    show 0#usize+1#usize = ok 1#usize from by rw [usize_add_ok _ _ (by decide)]; rfl]

private theorem flags_body_one [RuntimeFeatures] (z0 z1 w0 w1 h0 h1 : Bls.Fp) (a b : Bool) :
    portable.g1_pair.G1Pair.add_loop.body (fields z0 z1) (fields w0 w1) (fields h0 h1)
      (flags a b) 1#usize =
      ok (cont (flags a (h1.isZero || (z1.isZero || w1.isZero)),2#usize)) := by
  simp only [portable.g1_pair.G1Pair.add_loop.body,show 1#usize < 2#usize from by decide,if_true,
    Fp.pair_index_one,Fp.is_zero_encoded,bind_tc_ok,bool_or_result,flags_update_one,
    show 1#usize+1#usize = ok 2#usize from by rw [usize_add_ok _ _ (by decide)]; rfl]

private theorem flags_loop_step (a b h : Array portable.fp.Fp 2#usize) (e e' : Array Bool 2#usize)
    (k k' : Usize) (hb : portable.g1_pair.G1Pair.add_loop.body a b h e k = ok (cont (e',k'))) :
    portable.g1_pair.G1Pair.add_loop a b h e k = portable.g1_pair.G1Pair.add_loop a b h e' k' := by
  rw [portable.g1_pair.G1Pair.add_loop,loop.eq_1]
  dsimp only
  rw [hb]
  rfl

private theorem flags_loop_two (a b h : Array portable.fp.Fp 2#usize) (e : Array Bool 2#usize) :
    portable.g1_pair.G1Pair.add_loop a b h e 2#usize = ok e := by
  rw [portable.g1_pair.G1Pair.add_loop,loop.eq_1]
  simp only [portable.g1_pair.G1Pair.add_loop.body,lt_self_iff_false,if_false]

private theorem flags_loop_one [RuntimeFeatures] (z0 z1 w0 w1 h0 h1 : Bls.Fp) (a b : Bool) :
    portable.g1_pair.G1Pair.add_loop (fields z0 z1) (fields w0 w1) (fields h0 h1)
      (flags a b) 1#usize = ok (flags a (h1.isZero || (z1.isZero || w1.isZero))) := by
  rw [flags_loop_step _ _ _ _ _ _ _ (flags_body_one z0 z1 w0 w1 h0 h1 a b)]
  exact flags_loop_two _ _ _ _


private theorem flags_loop [RuntimeFeatures] (z0 z1 w0 w1 h0 h1 : Bls.Fp) :
    portable.g1_pair.G1Pair.add_loop (fields z0 z1) (fields w0 w1) (fields h0 h1)
      (Array.repeat 2#usize false) 0#usize =
      ok (flags (h0.isZero || (z0.isZero || w0.isZero)) (h1.isZero || (z1.isZero || w1.isZero))) := by
  change portable.g1_pair.G1Pair.add_loop _ _ _ (flags false false) _ = _
  rw [flags_loop_step _ _ _ _ _ _ _ (flags_body_zero z0 z1 w0 w1 h0 h1 false false)]
  exact flags_loop_one _ _ _ _ _ _ _ _


def addExceptional (P Q : Bls.G1) : Bool :=
  (Kzg.PortableG1.termsValues P Q).h.isZero || (P.z.isZero || Q.z.isZero)

def affineExceptional (P : Bls.G1) (x y : Bls.Fp) : Bool :=
  (G1.mixedValues P x y).h.isZero || P.z.isZero

def sum (P Q : Bls.G1) : Bls.G1 := Kzg.PortableG1.sumValues (Kzg.PortableG1.termsValues P Q) P Q

def affineSum (P : Bls.G1) (x y : Bls.Fp) : Bls.G1 := G1.mixedSum (G1.mixedValues P x y) P

theorem add_encoded [RuntimeFeatures] (P0 P1 Q0 Q1 : Bls.G1) :
    portable.g1_pair.G1Pair.add (encode P0 P1) (encode Q0 Q1) =
      ok (encode (sum P0 Q0) (sum P1 Q1),flags (addExceptional P0 Q0) (addExceptional P1 Q1)) := by
  simp only [portable.g1_pair.G1Pair.add,encode,square_fields,add_fields,sub_fields,
    double_fields,mul_fields,bind_tc_ok,flags_loop]
  rfl

theorem add_affine_encoded [RuntimeFeatures] (P0 P1 : Bls.G1) (x0 x1 y0 y1 : Bls.Fp) :
    portable.g1_pair.G1Pair.add_affine (encode P0 P1) (fields x0 x1) (fields y0 y1) =
      ok (encode (affineSum P0 x0 y0) (affineSum P1 x1 y1),
        flags (affineExceptional P0 x0 y0) (affineExceptional P1 x1 y1)) := by
  simp only [portable.g1_pair.G1Pair.add_affine,encode,square_fields,add_fields,sub_fields,
    double_fields,mul_fields,bind_tc_ok,Fp.pair_index_zero,Fp.pair_index_one,Fp.is_zero_encoded,
    bool_or_result]
  split <;> rename_i h
  · simp only [affineSum,affineExceptional,G1.mixedValues,G1.mixedSum,flags,h,
      Bool.true_or]
  · simp only [affineSum,affineExceptional,G1.mixedValues,G1.mixedSum,flags,
      Bool.eq_false_iff.mpr h,Bool.false_or]

theorem sum_eq_add (P Q : Bls.G1) (h : addExceptional P Q = false) :
    sum P Q = Bls.G1.add P Q := by
  have hs : (Kzg.PortableG1.termsValues P Q).h.isZero = false ∧ P.z.isZero = false ∧ Q.z.isZero = false :=
    by simpa only [addExceptional,Bool.or_eq_false_iff] using h
  rw [←Kzg.PortableG1.addValues_eq_add]
  simp only [Kzg.PortableG1.addValues,hs.1,hs.2.1,hs.2.2,Bool.false_eq_true,if_false,sum]

theorem affineSum_eq_add (P : Bls.G1) (x y : Bls.Fp) (h : affineExceptional P x y = false) :
    affineSum P x y = Bls.G1.add P ⟨x,y,Bls.Fp.one⟩ := by
  have hs : (G1.mixedValues P x y).h.isZero = false ∧ P.z.isZero = false :=
    by simpa only [affineExceptional,Bool.or_eq_false_iff] using h
  rw [←G1.mixed_add_eq]
  simp only [G1.mixedAddValues,hs.1,hs.2,Bool.false_eq_true,if_false,affineSum]

end LeanBlsSimd.Portable.G1.Pair
