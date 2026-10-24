import LeanBlsSimd.Portable.Msm.PointRep
import LeanBlsSimd.Portable.G1.Scott
import LeanBlsSimd.Msm8.AffineInput

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Store
set_option maxRecDepth 4096
open BucketsRefines
local instance : Inhabited blst.blst_p1_affine := ⟨Kzg.g1Affine Bls.G1.zero⟩

def inputCoordinates (point : blst.blst_p1_affine) (endomorphism negative : Bool) :
    ZMod Bls.Fp.modulus × ZMod Bls.Fp.modulus :=
  let x : ZMod Bls.Fp.modulus := Kzg.fpRead point.x
  let y : ZMod Bls.Fp.modulus := Kzg.fpRead point.y
  (if endomorphism then x*(beta : ZMod Bls.Fp.modulus) else x,
    if negative then -y else y)

theorem inputCoordinates_point (point : blst.blst_p1_affine) (endomorphism negative : Bool)
    (hp : Kzg.G1AffineValid point) (hf : (Kzg.g1ReadAffine point).isInfinity ≠ true) :
    Bls.G1.Valid ⟨(inputCoordinates point endomorphism negative).1,
      (inputCoordinates point endomorphism negative).2,Bls.Fp.one⟩ ∧
    Bls.G1.toPoint ⟨(inputCoordinates point endomorphism negative).1,
      (inputCoordinates point endomorphism negative).2,Bls.Fp.one⟩ =
      Msm8.transformedPoint point endomorphism negative := by
  have hv := Kzg.g1_groupValid_of_noninfinity hp.2 hf
  rw [Msm8.affine_read_finite point hf] at hv
  refine ⟨Msm8.transformed_affine_valid _ _ _ _ hv,?_⟩
  unfold Msm8.transformedPoint
  rw [Msm8.affine_read_finite point hf]
  exact Msm8.transformed_affine_toPoint _ _ _ _ hv

theorem push_step [RuntimeFeatures] (s : portable.msm.store.PointStore)
    (points : Slice blst.blst_p1_affine) (negated : Slice Bool) (endomorphism : Bool) (k : Usize)
    (hk : k.val < points.val.length) (hn : negated.val.length = points.val.length)
    (hcap : s.len.val < s.points.val.length)
    (hp : Kzg.G1AffineValid points.val[k.val]!)
    (hf : (Kzg.g1ReadAffine points.val[k.val]!).isInfinity ≠ true) :
    ∃ next cursor, next.val = s.len.val+1 ∧ cursor.val = k.val+1 ∧
      portable.msm.store.PointStore.push_blst_loop.body points negated endomorphism
        s.points s.len k = ok (cont
          ((write s s.len.val (inputCoordinates points.val[k.val]! endomorphism negated.val[k.val]!).1
            (inputCoordinates points.val[k.val]! endomorphism negated.val[k.val]!).2).points,next,cursor)) := by
  have hkn : k.val < negated.val.length := by omega
  have his : s.len.val + 1 < 2^UScalarTy.Usize.numBits := by
    have := QueueRefines.vec_length_bound s.points
    omega
  have hks : k.val + 1 < 2^UScalarTy.Usize.numBits := by
    have h := points.property
    have := two_pow_32_le_usize
    simp only [Usize.max_def,Usize.numBits_def] at h
    omega
  let next : Usize := UScalar.ofNatCore _ his
  let cursor : Usize := UScalar.ofNatCore _ hks
  let point := points.val[k.val]!
  let negative := negated.val[k.val]!
  let x : ZMod Bls.Fp.modulus := Kzg.fpRead point.x
  let y : ZMod Bls.Fp.modulus := Kzg.fpRead point.y
  obtain ⟨hx,hy⟩ := Msm8.affine_finite_encoding point hp hf
  have he : portable.msm.store.PointStore.push_blst_loop.body points negated endomorphism
      s.points s.len k = (do
        let f ← if endomorphism then portable.fp.Fp.mul point.x.l portable.constants.BETA else ok point.x.l
        let y ← if negative then portable.fp.Fp.neg point.y.l else ok point.y.l
        let (_,back) ← alloc.vec.Vec.index_mut
          (core.slice.index.SliceIndexUsizeSlice (Array portable.fp.Fp 2#usize)) s.points s.len
        let i ← s.len+1#usize
        let j ← k+1#usize
        ok (cont (back (Array.make 2#usize [f,y] (by rfl)),i,j))) := by
    simp only [portable.msm.store.PointStore.push_blst_loop.body,UScalar.lt_equiv,Slice.len_val,hk,if_true]
    rw [show Slice.index_usize points k = ok point from by
      simp [Slice.index_usize,hk,point]]
    simp only [bind_tc_ok]
    rw [show Slice.index_usize negated k = ok negative from by
      simp [Slice.index_usize,hkn,negative]]
    rfl
  have hxc : (if endomorphism then portable.fp.Fp.mul point.x.l portable.constants.BETA
      else ok point.x.l) = ok (Kzg.fpEncode (show ZMod Bls.Fp.modulus from if endomorphism then x*(beta : ZMod Bls.Fp.modulus) else x)).l := by
    rw [show point.x.l = (Kzg.fpEncode x).l from congrArg blst.blst_fp.l hx,G1.beta_encoded]
    cases endomorphism
    · rfl
    · exact Fp.mul_encoded x (beta : ZMod Bls.Fp.modulus)
  have hyc : (if negative then portable.fp.Fp.neg point.y.l else ok point.y.l) =
      ok (Kzg.fpEncode (show ZMod Bls.Fp.modulus from if negative then -y else y)).l := by
    rw [show point.y.l = (Kzg.fpEncode y).l from congrArg blst.blst_fp.l hy]
    cases negative
    · rfl
    · exact Fp.neg_encoded y
  refine ⟨next,cursor,rfl,rfl,?_⟩
  rw [he,hxc]
  simp only [bind_tc_ok,hyc]
  rw [vec_index_mut _ _ hcap]
  simp only [bind_tc_ok]
  rw [add_ok _ _ his]
  simp only [bind_tc_ok]
  rw [add_ok _ _ hks]
  rfl

end LeanBlsSimd.Portable.Msm.Store
