import LeanBlsSimd.Portable.Fp.Words

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls

set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

namespace LeanBlsSimd.Portable.Fp
open Word64

private theorem select_zero_word (a b : U64) :
    (a &&& 0#u64) ||| (b &&& ~~~0#u64) = b := by
  apply (UScalar.eq_equiv_bv_eq _ _).2
  change (a.bv &&& 0) ||| (b.bv &&& ~~~0) = b.bv
  simp

private theorem select_ones_word (a b : U64) :
    (a &&& 18446744073709551615#u64) ||| (b &&& ~~~18446744073709551615#u64) = a := by
  apply (UScalar.eq_equiv_bv_eq _ _).2
  change (a.bv &&& ~~~0) ||| (b.bv &&& ~~~~~~0) = a.bv
  simp

private theorem select_loop_eq (mask : U64) (a b out target : Array U64 6#usize) (j : Usize)
    (hj : j.val ≤ 6)
    (hw : ∀ i (hi : i < 6),
      (a.val[i]'(by rw [a.property]; exact hi) &&& mask) |||
        (b.val[i]'(by rw [b.property]; exact hi) &&& ~~~mask) =
          target.val[i]'(by rw [target.property]; exact hi))
    (hp : ∀ i (hi : i < 6), i < j.val →
      out.val[i]'(by rw [out.property]; exact hi) = target.val[i]'(by rw [target.property]; exact hi)) :
    portable.fp.select_loop mask a b out j = ok target := by
  induction hn : 6-j.val generalizing out j with
  | zero =>
    have hje : j.val = 6 := by omega
    have hstop : ¬j < 6#usize := by change ¬j.val < 6; omega
    have heq : out = target := by
      apply Subtype.ext
      apply List.ext_getElem
      · rw [out.property,target.property]
      · intro i hi ht
        have hi6 : i < 6 := by simpa only [out.property] using hi
        exact hp i hi6 (by omega)
    rw [portable.fp.select_loop,loop.eq_1]
    simp [portable.fp.select_loop.body,hstop,heq]
  | succ n ih =>
    have hjlt : j.val < 6 := by omega
    let next : Usize := UScalar.ofNatCore (j.val+1)
      (lt_of_lt_of_le (by omega : j.val+1 < 2^32) two_pow_32_le_usize)
    let word := target.val[j.val]'(by rw [target.property]; exact hjlt)
    have hnxt : next.val = j.val+1 := rfl
    have hbody : portable.fp.select_loop.body mask a b out j = ok (cont (out.set j word,next)) := by
      have hj' : j < 6#usize := hjlt
      simp only [portable.fp.select_loop.body,hj',if_true]
      rw [index_usize_eq a j hjlt,index_usize_eq b j hjlt]
      simp only [lift,bind_tc_ok,hw j.val hjlt]
      rw [update_eq out j word hjlt,usize_add_ok j 1#usize (by change j.val+1 < 2^32; omega)]
      rfl
    have hp' : ∀ i (hi : i < 6), i < next.val →
      (out.set j word).val[i]'(by rw [(out.set j word).property]; exact hi) =
        target.val[i]'(by rw [target.property]; exact hi) := by
      intro i hi hij
      change (out.val.set j.val word)[i]'_ = _
      by_cases h : j.val = i
      · subst i
        rw [List.getElem_set_self]
      · rw [List.getElem_set_ne h]
        exact hp i hi (by omega)
    rw [portable.fp.select_loop,loop.eq_1]
    simpa only [hbody] using ih (out.set j word) next (by omega) hp' (by omega)

theorem select_zero (a b : Array U64 6#usize) : portable.fp.select 0#u64 a b = ok b :=
  select_loop_eq _ a b _ b 0#usize (by decide) (by intro i hi; exact select_zero_word _ _)
    (by intro i hi h; change i < 0 at h; omega)

theorem select_ones (a b : Array U64 6#usize) :
    portable.fp.select 18446744073709551615#u64 a b = ok a :=
  select_loop_eq _ a b _ a 0#usize (by decide) (by intro i hi; exact select_ones_word _ _)
    (by intro i hi h; change i < 0 at h; omega)

theorem wordsValue_take_drop (xs : List U64) (i : Nat) :
    wordsValue xs = wordsValue (xs.take i)+(radix : ℤ)^i*wordsValue (xs.drop i) := by
  induction i generalizing xs with
  | zero => simp [wordsValue]
  | succ i ih =>
    cases xs with
    | nil => simp [wordsValue]
    | cons x xs =>
      simp only [List.take_succ_cons,List.drop_succ_cons,wordsValue,pow_succ]
      rw [ih xs]
      ring

theorem negative_mask_refines (d : Array U64 6#usize) :
    portable.fp.negative_mask d =
      ok (if value d < 2^383 then 0#u64 else 18446744073709551615#u64) := by
  let high := d.val[5]'(by rw [d.property]; decide)
  have hsix : tail d 6 = 0 := tail_end d
  have hsplit := wordsValue_take_drop d.val 5
  change value d = wordsValue (d.val.take 5)+(radix : ℤ)^5*tail d 5 at hsplit
  rw [tail_step d 5 (by decide),hsix,mul_zero,add_zero] at hsplit
  have hlow := wordsValue_bounds (d.val.take 5)
  have hlen : (d.val.take 5).length = 5 := by simp [d.property]
  rw [hlen] at hlow
  have hh := high.hBounds
  have hbit : high.val / 2^63 = if value d < 2^383 then 0 else 1 := by
    change value d = wordsValue (d.val.take 5)+(radix : ℤ)^5*high.val at hsplit
    norm_num [radix,UScalarTy.numBits] at hsplit hlow hh ⊢
    split <;> omega
  have hshift : high >>> 63#i32 = ok ⟨high.bv.ushiftRight 63⟩ := rfl
  have hbval : (⟨high.bv.ushiftRight 63⟩ : U64).val = high.val/2^63 := by
    change (high.bv >>> (63 : Nat)).toNat = _
    rw [BitVec.toNat_ushiftRight,Nat.shiftRight_eq_div_pow]
    rfl
  simp only [portable.fp.negative_mask]
  rw [index_usize_eq d 5#usize (by decide)]
  simp only [bind_tc_ok]
  change (do let bit ← high >>> 63#i32; ok (core.num.U64.wrapping_sub 0#u64 bit)) = _
  rw [hshift]
  simp only [bind_tc_ok]
  by_cases h : value d < 2^383
  · have he : (⟨high.bv.ushiftRight 63⟩ : U64) = 0#u64 := by
      apply UScalar.eq_of_val_eq
      rw [hbval,hbit,if_pos h]
      rfl
    rw [he,if_pos h]
    rfl
  · have he : (⟨high.bv.ushiftRight 63⟩ : U64) = 1#u64 := by
      apply UScalar.eq_of_val_eq
      rw [hbval,hbit,if_neg h]
      rfl
    rw [he,if_neg h]
    rfl

theorem below_p_refines (t : Array U64 6#usize) (ht : value t < 2*Bls.Fp.modulus) :
    ∃ out, portable.fp.below_p t = ok out ∧ value out = value t % (Bls.Fp.modulus : ℤ) := by
  obtain ⟨d,he,hd⟩ := sub_words_refines t bls.constants.P_U64
  rw [modulus_words] at he hd
  have ht0 := (value_bounds t).1
  have hneg := negative_mask_refines d
  by_cases hsmall : value t < Bls.Fp.modulus
  · have hhigh : ¬value d < 2^383 := by
      norm_num [radix,Bls.Fp.modulus] at ht hd hsmall ⊢
      omega
    refine ⟨t,?_,(Int.emod_eq_of_lt ht0 hsmall).symm⟩
    simp only [portable.fp.below_p,he,bind_tc_ok]
    change (do let mask ← portable.fp.negative_mask d; portable.fp.select mask t d) = _
    rw [hneg]
    simp only [if_neg hhigh,bind_tc_ok,select_ones]
  · have hlow : value d < 2^383 := by
      norm_num [radix,Bls.Fp.modulus] at ht hd hsmall ⊢
      omega
    refine ⟨d,?_,?_⟩
    · simp only [portable.fp.below_p,he,bind_tc_ok]
      change (do let mask ← portable.fp.negative_mask d; portable.fp.select mask t d) = _
      rw [hneg]
      simp only [if_pos hlow,bind_tc_ok,select_zero]
    · norm_num [radix,Bls.Fp.modulus] at ht hd hsmall ⊢
      omega

private theorem zero_and (x : U64) : 0#u64 &&& x = 0#u64 := by
  apply (UScalar.eq_equiv_bv_eq _ _).2
  change (0 : BitVec 64) &&& x.bv = 0
  simp

private theorem or_zero (x : U64) : x ||| 0#u64 = x := by
  apply (UScalar.eq_equiv_bv_eq _ _).2
  change x.bv ||| 0 = x.bv
  simp

private theorem p_if_loop_eq_select (mask : U64) (out : Array U64 6#usize) (j : Usize) :
    portable.fp.p_if_loop mask out j =
      portable.fp.select_loop mask bls.constants.P_U64 (Array.repeat 6#usize 0#u64) out j := by
  unfold portable.fp.p_if_loop portable.fp.select_loop
  congr 1
  funext state
  rcases state with ⟨out,j⟩
  by_cases hj : j < 6#usize
  · simp only [portable.fp.p_if_loop.body,portable.fp.select_loop.body,hj,if_true]
    rw [index_usize_eq bls.constants.P_U64 j hj,
      index_usize_eq (Array.repeat 6#usize 0#u64) j hj]
    simp only [lift,bind_tc_ok,Array.repeat,List.getElem_replicate,zero_and,or_zero]
  · simp [portable.fp.p_if_loop.body,portable.fp.select_loop.body,hj]

theorem p_if_refines (borrowed : Bool) :
    portable.fp.p_if borrowed = ok (if borrowed then bls.constants.P_U64 else Array.repeat 6#usize 0#u64) := by
  cases borrowed with
  | false =>
    change portable.fp.p_if_loop 0#u64 (Array.repeat 6#usize 0#u64) 0#usize = _
    rw [p_if_loop_eq_select]
    exact select_zero _ _
  | true =>
    change portable.fp.p_if_loop 18446744073709551615#u64 (Array.repeat 6#usize 0#u64) 0#usize = _
    rw [p_if_loop_eq_select]
    exact select_ones _ _

end LeanBlsSimd.Portable.Fp
