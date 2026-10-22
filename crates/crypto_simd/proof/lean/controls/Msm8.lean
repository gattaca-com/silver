import LeanBlsSimd.Msm8.Inversion
import LeanBlsSimd.Msm8.Lanes
import LeanBlsSimd.Msm8.Glv
import LeanBlsSimd.Msm8.Buckets
import LeanBlsSimd.Msm8.Fill
import LeanBlsSimd.Msm8.Queue
import LeanBlsSimd.Msm8.Batch
import LeanBlsSimd.Msm8.PlainWords

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Controls.MsmInverse
open EthCryptographySpecs.Bls

private def inverseWith (finish : Bool) (x : Fp8) : Fp8 :=
  let squared := x.pow_p_minus_3_over_4.square.square
  if finish then squared.mul x else squared

example : inverseWith true = Fp8.inverse := rfl

private theorem missing_multiplication :
    (inverseWith false Fp8.one.neg).Holds 0 (1 : ZMod Fp.modulus) := by
  have hpow (n : ℕ) : ((-(1 : ZMod Fp.modulus)) ^ n) ^ 2 = 1 := by
    rw [← pow_mul, Nat.mul_comm n 2, pow_mul]
    simp
  apply (Fp8.holds_one 0).neg.pow_p_minus_3_over_4.square.square.of_eq
  simp only [Kernel.powPMinus3Over4, hpow, one_pow]

example : ¬ (inverseWith false Fp8.one.neg).Holds 0 ((-(1 : ZMod Fp.modulus))⁻¹) := by
  intro h
  have heq := missing_multiplication.eq.symm.trans h.eq
  have hne : (1 : ZMod Fp.modulus) ≠ -1 := by decide +kernel
  exact hne (by simpa only [inv_neg, inv_one] using heq)

example : ((Fp.modulus - 3) / 4) * 2 * 2 ≠ Fp.modulus - 2 := by decide +kernel

example : True := by
  fail_if_success
    have : ((Fp.modulus - 3) / 4) * 2 * 2 = Fp.modulus - 2 := by decide +kernel
  trivial

end LeanBlsSimd.Controls.MsmInverse

namespace LeanBlsSimd.Controls.MsmBuckets
open BucketsRefines

private def buckets4 : msm8.buckets.Buckets :=
  ⟨4#usize,2#usize,alloc.vec.Vec.new U32,alloc.vec.Vec.new U32,alloc.vec.Vec.new U32⟩

private theorem second_window_first_bucket : buckets4.list 1#usize 1#usize = ok 8#usize := by
  obtain ⟨i,hi,hv⟩ := list_refines buckets4 1#usize 1#usize (by decide) (by decide)
    (by decide) (by decide) (by decide)
  have he : i = 8#usize := UScalar.eq_of_val_eq hv
  simpa only [he] using hi

example : buckets4.list 1#usize 1#usize ≠ ok 9#usize := by
  rw [second_window_first_bucket]
  intro h
  have he := congrArg UScalar.val (Result.ok.inj h)
  contradiction

example : True := by
  fail_if_success
    have : buckets4.list 1#usize 1#usize = ok 9#usize := second_window_first_bucket
  trivial

example (state : msm8.buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ) (contents : BucketLists)
    (h : Packed state n base capacity contents) (i : ℕ) (hi : i < n) (reference : U32) :
    bucketSlice state i ≠ contents i ++ [reference] := by
  rw [packed_recovers state n base capacity contents h i hi]
  intro he
  have := congrArg List.length he
  simp only [List.length_append,List.length_singleton] at this
  omega

example (i : Usize) (hi : i.val < 2 ^ 31) :
    (signedReference i true).val / 2 ^ 31 = 1 := signedReference_sign i true hi

example (i : Usize) (hi : i.val < 2 ^ 31) :
    (signedReference i true).val / 2 ^ 31 ≠ 0 := by
  rw [signedReference_sign i true hi]
  decide

end LeanBlsSimd.Controls.MsmBuckets

namespace LeanBlsSimd.Controls.MsmDigits
open SignedDigits

private theorem tie_positive (self : msm8.buckets.SignedDigits)
    (hb : self.bit.val < 256) (hwl : 1 ≤ self.window_bits.val) (hwh : self.window_bits.val ≤ 8)
    (hc : self.carry.val ≤ 1)
    (htie : value self.words / 2 ^ self.bit.val % 2 ^ self.window_bits.val + self.carry.val =
      2 ^ (self.window_bits.val - 1)) :
    ∃ mag next, self.next_digit = ok ((mag,false),next) ∧ next.carry.val = 0 := by
  obtain ⟨mag,neg,next,hs,_,_,_,hcarry,hneg,_,_⟩ := next_digit_refines self hb hwl hwh hc
  have hn : neg = false := by simpa only [htie,Nat.lt_irrefl,decide_false] using hneg
  rw [hn] at hs hcarry
  exact ⟨mag,next,hs,hcarry⟩

private def tieWords : Array U64 4#usize := Array.make 4#usize [8#u64,0#u64,0#u64,0#u64] (by rfl)

example : ∃ mag next, (initial tieWords 4#usize).next_digit = ok ((mag,false),next) ∧ next.carry.val = 0 :=
  tie_positive _ (by decide) (by decide) (by decide) (by decide) (by decide +kernel)

example : ¬ ∃ mag next, (initial tieWords 4#usize).next_digit = ok ((mag,true),next) := by
  obtain ⟨mag,next,hgood,_⟩ := tie_positive (initial tieWords 4#usize)
    (by decide) (by decide) (by decide) (by decide) (by decide +kernel)
  rintro ⟨mag',next',hbad⟩
  have he := congrArg (fun x => x.1.2) (Result.ok.inj (hgood.symm.trans hbad))
  contradiction

end LeanBlsSimd.Controls.MsmDigits

namespace LeanBlsSimd.Controls.MsmEqualX
open BatchedRefines

private def prepareWithReject (reject : Bool) (self : msm8.pairs.BatchedAdds)
    (store : msm8.store.PointStore) (group : ℕ) (products : Vector Fp8 4) :
    Bool × msm8.pairs.BatchedAdds × Vector Fp8 4 :=
  if reject then prepareStep self store group products else
    let updated := preparedUpdate self group products (difference self store group)
    (true,updated.1,updated.2)

example : prepareWithReject true = prepareStep := rfl

example : (Fp8.one.sub Fp8.one).is_zero_mask ≠ 0 :=
  equal_x_zero_mask _ _ 0 (Fp8.holds_one 0).inv (Fp8.holds_one 0).inv rfl

example (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (group : ℕ) (products : Vector Fp8 4)
    (hzero : (difference self store group).is_zero_mask ≠ 0) :
    prepareWithReject false self store group products ≠ prepareStep self store group products := by
  intro h
  have he := congrArg Prod.fst h
  simp only [prepareWithReject,prepareStep,hzero,if_false,Bool.false_eq_true] at he
  contradiction

example (self : msm8.pairs.BatchedAdds) (store : msm8.store.PointStore)
    (g : Usize) (products : Array fp8.Fp8 4#usize)
    (ia ib : Array U32 8#usize) (na nb : U8) (xa xb : Fp8)
    (hra : msm8.pairs.references self.a.deref g = ok (ia,na))
    (hrb : msm8.pairs.references self.b.deref g = ok (ib,nb))
    (hla : store.load_x ia = ok (toFp8 xa)) (hlb : store.load_x ib = ok (toFp8 xb))
    (hzero : (xb.sub xa).is_zero_mask ≠ 0) :
    ¬ ∃ next updated, self.extend_chain store g products = ok (true,next,updated) := by
  rw [extend_chain_zero self store g products ia ib na nb xa xb hra hrb hla hlb hzero]
  rintro ⟨next,updated,h⟩
  have he := congrArg Prod.fst (Result.ok.inj h)
  contradiction

end LeanBlsSimd.Controls.MsmEqualX

namespace LeanBlsSimd.Controls.MsmGlv

example : GlvRefines.value msm8.glv.LAMBDA = Glv.lambda := GlvRefines.lambda_value

example : GlvRefines.value msm8.glv.LAMBDA ≠ Glv.lambda + 1 := by
  rw [GlvRefines.lambda_value]
  omega

example : (Glv.first Glv.lambda + Glv.lambda * Glv.second Glv.lambda) % Glv.modulus =
    Glv.lambda % Glv.modulus := Glv.congruent _

example : (Glv.first Glv.lambda + (Glv.lambda + 1) * Glv.second Glv.lambda) % Glv.modulus ≠
    Glv.lambda % Glv.modulus := by decide +kernel

example : True := by
  fail_if_success
    have : GlvRefines.value msm8.glv.LAMBDA = Glv.lambda + 1 := GlvRefines.lambda_value
  trivial

end LeanBlsSimd.Controls.MsmGlv

namespace LeanBlsSimd.Controls.MsmWeights
open EthCryptographySpecs.Bls

private def joinWith (extra : ℕ) (self : G1x8) (bits distance : ℕ) : G1x8 :=
  self.add_complete ((self.times_two_pow (distance * bits + extra)).permute (G1x8.lanesAbove distance))

example : joinWith 0 = G1x8.joinLanes := rfl

example (self : G1x8) (bits distance : ℕ) (P : Fin 8 → G1.curve.toAffine.Point)
    (hP : ∀ l, self.PointRep l (P l)) (l : Fin 8) :
    (joinWith 0 self bits distance).PointRep l
      (P l + 2 ^ (distance * bits) • P ⟨(l.val+distance)%8,Nat.mod_lt _ (by decide)⟩) :=
  G1x8.joinLanes_correct self bits distance P hP l

example : (2 ^ (1 * 4 + 1) : ℕ) • G1.toPoint G1.generator ≠
    (2 ^ (1 * 4) : ℕ) • G1.toPoint G1.generator := by
  rw [ne_eq,nsmul_inj_mod,G1.addOrderOf_toPoint_generator]
  decide +kernel

example : True := by
  fail_if_success
    have : ∀ (self : G1x8) (bits distance : ℕ) (P : Fin 8 → G1.curve.toAffine.Point),
        (∀ l, self.PointRep l (P l)) → ∀ l,
        (joinWith 1 self bits distance).PointRep l
          (P l + 2 ^ (distance * bits) • P ⟨(l.val+distance)%8,Nat.mod_lt _ (by decide)⟩) := by
      intro self bits distance P hP l
      exact (hP l).add_complete ((hP _).times_two_pow (distance * bits)).lanesAbove
  trivial

end LeanBlsSimd.Controls.MsmWeights

namespace LeanBlsSimd.Controls.MsmQueue
open QueueRefines BatchedRefines

example : RefIndependent 2 0#u32 0#u32 := by unfold RefIndependent; decide
example : ¬ RefIndependent 2 2#u32 2#u32 := by unfold RefIndependent; decide
example : ¬ JobIndependent ⟨0#u32,1#u32,2#u32⟩ ⟨2#u32,1#u32,3#u32⟩ := by
  unfold JobIndependent
  decide
example : (reduce 2 4 [2#u32,0#u32,3#u32,1#u32]).2.2 = 4 := by decide
example : (reduce 2 4 [0#u32,1#u32,0#u32,1#u32]).2.2 = 6 := by decide

example : ¬ PairValues (fun r : U32 => (r.val : ℤ)) (fun _ => (0 : ℤ))
    [⟨0#u32,1#u32,2#u32⟩] := by
  intro h
  have hh := h ⟨0#u32,1#u32,2#u32⟩ (by simp)
  norm_num at hh

private theorem padded_last (self : msm8.pairs.BatchedAdds)
    (ha : self.a.val = [3#u32]) (ho : self.out.val = [7#u32]) :
    (paddedAdds self 2#usize 16#usize).out.val = List.replicate 16 7#u32 := by
  simp only [paddedAdds,resizeVec,ha,ho]
  rfl

example (self : msm8.pairs.BatchedAdds)
    (ha : self.a.val = [3#u32]) (ho : self.out.val = [7#u32]) :
    (paddedAdds self 2#usize 16#usize).out.val[15]! = 7#u32 := by
  rw [padded_last self ha ho]
  rfl

example (self : msm8.pairs.BatchedAdds)
    (ha : self.a.val = [3#u32]) (ho : self.out.val = [7#u32]) :
    (paddedAdds self 2#usize 16#usize).out.val[15]! ≠ 0#u32 := by
  rw [padded_last self ha ho]
  decide

end LeanBlsSimd.Controls.MsmQueue

namespace LeanBlsSimd.Controls.MsmPlainWords
open EthCryptographySpecs.Bls PlainWords Kzg silver_crypto_simd.kzg

example (input : Slice blst.blst_fr) (words : alloc.vec.Vec Word)
    (values : List Fr) (hinput : input.val = values.map frEncode) :
    ∃ out, fr8.Fr8.plain_words input words = ok out ∧ out.val.length = values.length ∧
      out.val.map (fun word => limbs word.val) = values.map (fun x => x.val) :=
  plain_words_encoded input words values hinput

example (input : Slice blst.blst_fr) (words : alloc.vec.Vec Word)
    (values : List Fr) (hinput : input.val = values.map frEncode) :
    ¬ ∃ out, fr8.Fr8.plain_words input words = ok out ∧ out.val.length = values.length + 1 := by
  obtain ⟨out,hout,hlen,_⟩ := plain_words_encoded input words values hinput
  rintro ⟨wrong,hwrong,hbad⟩
  have he := Result.ok.inj (hout.symm.trans hwrong)
  subst wrong
  omega

end LeanBlsSimd.Controls.MsmPlainWords
