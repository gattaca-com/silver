import LeanBlsSimd.Kzg.Fr.Divide

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg
open EthLib.Cryptography Bls

namespace LeanBlsSimd.FrScalar
open Word64

theorem modulus_words : value fr.R = (Fr.modulus : ℤ) := by
  unfold fr.R
  rfl

theorem montgomery_row (a t : Array U64 4#usize) (w : U64)
    (ha : value a < Fr.modulus) (ht : value t < value a+Fr.modulus) :
    ∃ (low : Array U64 4#usize) (top : U64) (out : Array U64 4#usize) (m : U64),
      fr.multiply_add t a w = ok (low,top) ∧
      fr.divide_out_word low top = ok out ∧
      value out < value a+Fr.modulus ∧
      value out*(radix : ℤ) = value t+value a*w.val+(m.val : ℤ)*Fr.modulus := by
  obtain ⟨low,top,hmul,hmulval⟩ := multiply_add_refines t a w
  obtain ⟨out,m,hdiv,hdivval,hcancel⟩ := divide_out_word_refines low top
  rw [modulus_words] at hdivval hcancel
  rw [hmulval] at hdivval hcancel
  have ha0 := (value_bounds a).1
  have ht0 := (value_bounds t).1
  have hw : (w.val : ℤ) ≤ (radix : ℤ)-1 := by
    have h := w.hBounds
    norm_num [radix,UScalarTy.numBits] at h ⊢
    omega
  have hm : (m.val : ℤ) ≤ (radix : ℤ)-1 := by
    have h := m.hBounds
    norm_num [radix,UScalarTy.numBits] at h ⊢
    omega
  have hwmul := mul_le_mul_of_nonneg_left hw ha0
  have hmmul := mul_le_mul_of_nonneg_left hm (show (0 : ℤ) ≤ Fr.modulus by decide)
  have hbound : value t+value a*w.val+(Fr.modulus : ℤ)*m.val <
      (value a+Fr.modulus)*(radix : ℤ) := by
    nlinarith
  have hnonneg : 0 ≤ value t+value a*w.val+(Fr.modulus : ℤ)*m.val := by positivity
  have hq : 0 ≤ (value t+value a*w.val+(Fr.modulus : ℤ)*m.val)/(radix : ℤ) ∧
      (value t+value a*w.val+(Fr.modulus : ℤ)*m.val)/(radix : ℤ) < value a+Fr.modulus := by
    norm_num [radix] at hbound ⊢
    omega
  have hfit : (value t+value a*w.val+(Fr.modulus : ℤ)*m.val)/(radix : ℤ) < (radix : ℤ)^4 := by
    norm_num [radix,Fr.modulus] at ha hq ⊢
    omega
  rw [Int.emod_eq_of_lt hq.1 hfit] at hdivval
  refine ⟨low,top,out,m,hmul,hdiv,?_,?_⟩
  · rw [hdivval]
    exact hq.2
  · have h := Int.emod_add_mul_ediv (value t+value a*w.val+(Fr.modulus : ℤ)*m.val) (radix : ℤ)
    rw [hcancel,zero_add] at h
    rw [hdivval]
    nlinarith

def prefixValue (b : Array U64 4#usize) (i : Nat) : ℤ :=
  value b-tail b i*(radix : ℤ)^i

theorem prefixValue_zero (b : Array U64 4#usize) : prefixValue b 0 = 0 := by
  change value b-value b*(radix : ℤ)^0 = 0
  ring

theorem prefixValue_four (b : Array U64 4#usize) : prefixValue b 4 = value b := by
  simp [prefixValue,tail_four]

theorem prefixValue_step (b : Array U64 4#usize) (i : Nat) (hi : i < 4) :
    prefixValue b (i+1) = prefixValue b i+
      (b.val[i]'(by rw [b.property]; exact hi)).val*(radix : ℤ)^i := by
  simp only [prefixValue,tail_step b i hi,pow_succ]
  ring

theorem montgomery_loop_exact (a b t : Array U64 4#usize) (i : Usize)
    (hi : i.val ≤ 4) (ha : value a < Fr.modulus)
    (ht : value t < value a+Fr.modulus)
    (hcong : ∃ k : ℤ, value t*(radix : ℤ)^i.val = value a*prefixValue b i.val+k*Fr.modulus) :
    ∃ out, fr.montgomery_product_loop a b t i = ok out ∧
      value out < value a+Fr.modulus ∧
      ∃ k : ℤ, value out*(radix : ℤ)^4 = value a*value b+k*Fr.modulus := by
  induction hn : 4-i.val generalizing t i with
  | zero =>
    have hi4 : i.val = 4 := by omega
    have hstop : ¬ i < 4#usize := by change ¬i.val < 4; omega
    refine ⟨t,?_,ht,?_⟩
    · rw [fr.montgomery_product_loop,loop.eq_1]
      simp [fr.montgomery_product_loop.body,hstop]
    · simpa only [hi4,prefixValue_four] using hcong
  | succ n ih =>
    have hilt : i.val < 4 := by omega
    let w := b.val[i.val]'(by rw [b.property]; exact hilt)
    obtain ⟨low,top,out,m,hmul,hdiv,hbound,hvalue⟩ := montgomery_row a t w ha ht
    let next : Usize := UScalar.ofNatCore (i.val+1)
      (lt_of_lt_of_le (by omega : i.val+1 < 2^32) two_pow_32_le_usize)
    have hnext : next.val = i.val+1 := rfl
    have hcong' : ∃ k : ℤ, value out*(radix : ℤ)^next.val =
        value a*prefixValue b next.val+k*Fr.modulus := by
      obtain ⟨k,hk⟩ := hcong
      refine ⟨k+(m.val : ℤ)*(radix : ℤ)^i.val,?_⟩
      rw [hnext,prefixValue_step b i.val hilt,pow_succ]
      linear_combination hk+hvalue*(radix : ℤ)^i.val
    obtain ⟨result,hr,hrbound,hrcong⟩ := ih out next (by omega) hbound hcong' (by omega)
    have hbody : fr.montgomery_product_loop.body a b t i = ok (cont (out,next)) := by
      have hilt' : i < 4#usize := hilt
      simp only [fr.montgomery_product_loop.body,hilt',if_true]
      rw [index_usize_eq b i hilt]
      simp only [bind_tc_ok]
      change (do
        let (lo,hi) ← fr.multiply_add t a w
        let result ← fr.divide_out_word lo hi
        let next' ← i+1#usize
        ok (cont (result,next'))) = _
      rw [hmul]
      simp only [bind_tc_ok]
      rw [hdiv]
      simp only [bind_tc_ok]
      rw [usize_add_ok i 1#usize (by change i.val+1 < 2^32; omega)]
      rfl
    refine ⟨result,?_,hrbound,hrcong⟩
    rw [fr.montgomery_product_loop,loop.eq_1]
    simpa only [hbody] using hr

theorem below_r_refines (t : Array U64 4#usize) (ht : value t < 2*Fr.modulus) :
    ∃ out, fr.below_r t = ok out ∧ value out = value t % (Fr.modulus : ℤ) := by
  obtain ⟨difference,hsub,hdiff⟩ := sub_words_refines t fr.R
  rw [modulus_words] at hsub hdiff
  have ht0 := (value_bounds t).1
  by_cases hsmall : value t < Fr.modulus
  · refine ⟨t,?_,?_⟩
    · simp [fr.below_r,hsub,hsmall]
    · exact (Int.emod_eq_of_lt ht0 hsmall).symm
  · refine ⟨difference,?_,?_⟩
    · simp [fr.below_r,hsub,hsmall]
    · norm_num [radix,Fr.modulus] at ht hsmall hdiff ⊢
      omega

theorem montgomery_product_refines (a b : Array U64 4#usize)
    (ha : value a < Fr.modulus) :
    ∃ out, fr.montgomery_product a b = ok out ∧
      value out < Fr.modulus ∧
      ∃ k : ℤ, value out*(radix : ℤ)^4 = value a*value b+k*Fr.modulus := by
  have ha0 := (value_bounds a).1
  obtain ⟨t,hloop,ht,k,hk⟩ := montgomery_loop_exact a b (Array.repeat 4#usize 0#u64)
    0#usize (by decide) ha (by
      change (0 : ℤ) < value a+Fr.modulus
      have hpos : (0 : ℤ) < Fr.modulus := by decide
      omega) (by
      refine ⟨0,?_⟩
      change (0 : ℤ)*(radix : ℤ)^0 = value a*prefixValue b 0+0*Fr.modulus
      rw [prefixValue_zero]
      ring)
  obtain ⟨out,hbelow,hvalue⟩ := below_r_refines t (by omega)
  refine ⟨out,?_,?_,k-(value t/(Fr.modulus : ℤ))*(radix : ℤ)^4,?_⟩
  · simp only [fr.montgomery_product,hloop,bind_tc_ok]
    exact hbelow
  · rw [hvalue]
    exact Int.emod_lt_of_pos _ (by decide)
  · have hdiv := Int.emod_add_mul_ediv (value t) (Fr.modulus : ℤ)
    rw [← hvalue] at hdiv
    linear_combination hk+(radix : ℤ)^4*hdiv

end LeanBlsSimd.FrScalar
