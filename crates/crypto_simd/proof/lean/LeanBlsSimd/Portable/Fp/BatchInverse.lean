import LeanBlsSimd.Portable.Fp.Inverse

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Fp
open Word64
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

def encodeFour (a b c d : ZMod Bls.Fp.modulus) : Array portable.fp.Fp 4#usize :=
  Array.make 4#usize [(Kzg.fpEncode a).l,(Kzg.fpEncode b).l,
    (Kzg.fpEncode c).l,(Kzg.fpEncode d).l] (by rfl)

private theorem mul_field_encoded [RuntimeFeatures] (a b : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.mul (Kzg.fpEncode a).l (Kzg.fpEncode b).l =
      ok (Kzg.fpEncode (a*b)).l := mul_encoded a b

private theorem sub_four_one : 4#usize - 1#usize = ok 3#usize := by
  rw [sub_ok _ _ (by decide)]
  congr 1

private theorem prefix_run [RuntimeFeatures] (a b c d : ZMod Bls.Fp.modulus) :
    portable.msm.pairs.batch_inverse_loop0 (encodeFour a b c d) (encodeFour a b c d) 1#usize =
      ok (encodeFour a (a*b) (a*b*c) (a*b*c*d)) := by
  simp (disch := decide) only [portable.msm.pairs.batch_inverse_loop0,loop.eq_1,
    portable.msm.pairs.batch_inverse_loop0.body,portable.msm.pairs.CHAINS,if_pos,if_neg,encodeFour,Array.make,
    Aeneas.Std.Array.set,List.getElem_cons_zero,List.getElem_cons_succ,List.set_cons_zero,
    List.set_cons_succ,index_usize_eq,UScalar.ofNatCore_val_eq,Nat.reduceAdd,Nat.reduceSub,sub_ok,usize_add_ok,update_eq,mul_field_encoded,bind_tc_ok]


private theorem zero_encoded : portable.fp.Fp.ZERO = (Kzg.fpEncode (0 : ZMod Bls.Fp.modulus)).l :=
  rep_eq_encode Kzg.portableFpRep_zero

private theorem suffix_run [RuntimeFeatures] (a b c d i : ZMod Bls.Fp.modulus) :
    portable.msm.pairs.batch_inverse_loop1 (encodeFour a b c d)
      (encodeFour a (a*b) (a*b*c) (a*b*c*d)) 3#usize (Kzg.fpEncode i).l
      (Array.repeat 4#usize portable.fp.Fp.ZERO) =
      ok ((Kzg.fpEncode (i*d*c*b)).l,encodeFour 0 (i*d*c*a) (i*d*(a*b)) (i*(a*b*c))) := by
  simp (disch := decide) only [portable.msm.pairs.batch_inverse_loop1,
    portable.msm.pairs.batch_inverse_loop1.body,zero_encoded,Array.repeat,List.replicate,loop.eq_1,if_pos,if_neg,encodeFour,Array.make,
    Aeneas.Std.Array.set,List.getElem_cons_zero,List.getElem_cons_succ,List.set_cons_zero,
    List.set_cons_succ,index_usize_eq,UScalar.ofNatCore_val_eq,Nat.reduceSub,sub_ok,update_eq,mul_field_encoded,bind_tc_ok]

theorem batch_inverse_schedule [RuntimeFeatures] (a b c d : ZMod Bls.Fp.modulus) :
    portable.msm.pairs.batch_inverse (encodeFour a b c d) =
      ok (encodeFour (((a*b*c*d)⁻¹*d)*c*b) (((a*b*c*d)⁻¹*d)*c*a)
        (((a*b*c*d)⁻¹*d)*(a*b)) ((a*b*c*d)⁻¹*(a*b*c))) := by
  simp (disch := decide) only [portable.msm.pairs.batch_inverse,prefix_run,
    portable.msm.pairs.CHAINS,sub_four_one,index_usize_eq,bind_tc_ok]
  change (do let i ← portable.fp.Fp.inverse (Kzg.fpEncode (a*b*c*d)).l
             let (i',out) ← portable.msm.pairs.batch_inverse_loop1 (encodeFour a b c d)
               (encodeFour a (a*b) (a*b*c) (a*b*c*d)) 3#usize i
               (Array.repeat 4#usize portable.fp.Fp.ZERO)
             Array.update out 0#usize i') = _
  rw [inverse_encoded]
  simp only [bind_tc_ok,suffix_run]
  simp (disch := decide) only [update_eq]
  rfl

private theorem inverse_product_nonzero {K : Type} [Field K] (a b c d : K)
    (ha : a ≠ 0) (hb : b ≠ 0) (hc : c ≠ 0) (hd : d ≠ 0) :
    (((a*b*c*d)⁻¹*d)*c*b) = a⁻¹ ∧ (((a*b*c*d)⁻¹*d)*c*a) = b⁻¹ ∧
    (((a*b*c*d)⁻¹*d)*(a*b)) = c⁻¹ ∧ ((a*b*c*d)⁻¹*(a*b*c)) = d⁻¹ := by
  refine ⟨?_,?_,?_,?_⟩ <;> field_simp [ha,hb,hc,hd]

theorem batch_inverse_nonzero [RuntimeFeatures] (a b c d : ZMod Bls.Fp.modulus)
    (ha : a ≠ 0) (hb : b ≠ 0) (hc : c ≠ 0) (hd : d ≠ 0) :
    portable.msm.pairs.batch_inverse (encodeFour a b c d) =
      ok (encodeFour a⁻¹ b⁻¹ c⁻¹ d⁻¹) := by
  rw [batch_inverse_schedule]
  obtain ⟨h0,h1,h2,h3⟩ := inverse_product_nonzero a b c d ha hb hc hd
  rw [h0,h1,h2,h3]

theorem batch_inverse_zero_product [RuntimeFeatures] (a b c d : ZMod Bls.Fp.modulus)
    (hzero : a*b*c*d = 0) :
    portable.msm.pairs.batch_inverse (encodeFour a b c d) =
      ok (encodeFour 0 0 0 0) := by
  rw [batch_inverse_schedule,hzero]
  simp only [inv_zero,zero_mul]

end LeanBlsSimd.Portable.Fp
