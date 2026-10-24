import LeanBlsSimd.Portable.Fp.Wide

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Fp.Wide
open Word64
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096
set_option maxHeartbeats 2000000

theorem reduce_row_run (t : Array U64 6#usize) (reduced : Array U64 7#usize)
    (hr : portable.fp.mul_add (extend t) bls.constants.P_U64
      (core.num.U64.wrapping_mul (t.val[0]'(by rw [t.property]; decide)) portable.constants.P_INV) = ok reduced) :
    portable.fp.reduce_row t = ok (shift reduced) := by
  simp (disch := decide) only [portable.fp.reduce_row,index_usize_eq,bind_tc_ok,lift]
  simp only [show (0#usize).val = 0 from rfl,show (1#usize).val = 1 from rfl,
    show (2#usize).val = 2 from rfl,show (3#usize).val = 3 from rfl,
    show (4#usize).val = 4 from rfl,show (5#usize).val = 5 from rfl]
  change (do
    let reduced ← portable.fp.mul_add (extend t) bls.constants.P_U64
      (core.num.U64.wrapping_mul (t.val[0]'(by rw [t.property]; decide)) portable.constants.P_INV)
    ok (shift reduced)) = _
  rw [hr,bind_tc_ok]

theorem reduce_row_refines (t : Array U64 6#usize) :
    ∃ out, ∃ m : U64, portable.fp.reduce_row t = ok out ∧
      value out*(radix : ℤ) = value t+(m.val : ℤ)*Bls.Fp.modulus := by
  let m := core.num.U64.wrapping_mul (t.val[0]'(by rw [t.property]; decide)) portable.constants.P_INV
  obtain ⟨reduced,hr,hv⟩ := mul_add_refines (extend t) bls.constants.P_U64 m
  have ht := value_bounds t
  have hm := m.hBounds
  have hfit : value t+(Bls.Fp.modulus : ℤ)*m.val < (radix : ℤ)^7 := by
    norm_num [radix,Bls.Fp.modulus,UScalarTy.numBits] at ht hm ⊢
    omega
  rw [value_extend,modulus_words,Int.emod_eq_of_lt (add_nonneg ht.1 (mul_nonneg (by decide) (Int.natCast_nonneg _))) hfit] at hv
  have hc := cancellation (extend t)
  change (value (extend t)+(m.val : ℤ)*Bls.Fp.modulus) % (radix : ℤ) = 0 at hc
  rw [value_extend] at hc
  have hdiv := Int.emod_add_mul_ediv (value t+(m.val : ℤ)*Bls.Fp.modulus) (radix : ℤ)
  rw [hc,zero_add] at hdiv
  refine ⟨shift reduced,m,reduce_row_run t reduced hr,?_⟩
  rw [value_shift,hv,mul_comm (Bls.Fp.modulus : ℤ) (m.val : ℤ)]
  nlinarith

theorem reduce_row_bound (t out : Array U64 6#usize) (m : U64) (k : Nat)
    (hv : value out*(radix : ℤ) = value t+(m.val : ℤ)*Bls.Fp.modulus)
    (ht : value t < Bls.Fp.modulus+(radix : ℤ)^(k+1)) :
    value out < Bls.Fp.modulus+(radix : ℤ)^k := by
  have hm := m.hBounds
  rw [pow_succ] at ht
  norm_num [radix,Bls.Fp.modulus,UScalarTy.numBits] at hv ht hm ⊢
  omega

theorem reduce_low_refines (t : Array U64 6#usize) :
    ∃ t0 t1 t2 t3 t4 t5,
      portable.fp.reduce_row t = ok t0 ∧ portable.fp.reduce_row t0 = ok t1 ∧
      portable.fp.reduce_row t1 = ok t2 ∧ portable.fp.reduce_row t2 = ok t3 ∧
      portable.fp.reduce_row t3 = ok t4 ∧ portable.fp.reduce_row t4 = ok t5 ∧
      value t5 ≤ Bls.Fp.modulus ∧
      ∃ k : ℤ, value t5*(radix : ℤ)^6 = value t+k*Bls.Fp.modulus := by
  obtain ⟨t0,m0,h0,v0⟩ := reduce_row_refines t
  obtain ⟨t1,m1,h1,v1⟩ := reduce_row_refines t0
  obtain ⟨t2,m2,h2,v2⟩ := reduce_row_refines t1
  obtain ⟨t3,m3,h3,v3⟩ := reduce_row_refines t2
  obtain ⟨t4,m4,h4,v4⟩ := reduce_row_refines t3
  obtain ⟨t5,m5,h5,v5⟩ := reduce_row_refines t4
  have ht : value t < Bls.Fp.modulus+(radix : ℤ)^(5+1) := by
    have := (value_bounds t).2
    norm_num [Bls.Fp.modulus] at *
    omega
  have b0 := reduce_row_bound t t0 m0 5 v0 ht
  have b1 := reduce_row_bound t0 t1 m1 4 v1 b0
  have b2 := reduce_row_bound t1 t2 m2 3 v2 b1
  have b3 := reduce_row_bound t2 t3 m3 2 v3 b2
  have b4 := reduce_row_bound t3 t4 m4 1 v4 b3
  have b5 := reduce_row_bound t4 t5 m5 0 v5 b4
  let q : ℤ := (m0.val : ℤ)+(m1.val : ℤ)*(radix : ℤ)+(m2.val : ℤ)*(radix : ℤ)^2+
    (m3.val : ℤ)*(radix : ℤ)^3+(m4.val : ℤ)*(radix : ℤ)^4+(m5.val : ℤ)*(radix : ℤ)^5
  refine ⟨t0,t1,t2,t3,t4,t5,h0,h1,h2,h3,h4,h5,?_,q,?_⟩
  · simp only [pow_zero] at b5
    omega
  · dsimp only [q]
    linear_combination v0+(radix : ℤ)*v1+(radix : ℤ)^2*v2+(radix : ℤ)^3*v3+
      (radix : ℤ)^4*v4+(radix : ℤ)^5*v5

theorem reduce_refines (a : portable.fp.Wide)
    (ha : value a < (Bls.Fp.modulus : ℤ)*(radix : ℤ)^6) :
    ∃ out, portable.fp.Wide.reduce a = ok out ∧ value out < Bls.Fp.modulus ∧
      ∃ k : ℤ, value out*(radix : ℤ)^6 = value a+k*Bls.Fp.modulus := by
  have hs := split_value a
  have hl := value_bounds (low a)
  have hh := value_bounds (high a)
  have hhigh : value (high a) < Bls.Fp.modulus := by
    norm_num [radix] at ha hs hl ⊢
    omega
  obtain ⟨difference,hsub,hdiff⟩ := sub_words_refines (high a) bls.constants.P_U64
  rw [modulus_words] at hsub
  obtain ⟨t0,t1,t2,t3,t4,t5,h0,h1,h2,h3,h4,h5,hbound,k,hvalue⟩ := reduce_low_refines (low a)
  obtain ⟨sum,hadd,hsum⟩ := add_words_refines t5 (high a)
  have ht0 := (value_bounds t5).1
  have hsumrange : 0 ≤ value t5+value (high a) ∧ value t5+value (high a) < 2*Bls.Fp.modulus := by omega
  have hfit : value t5+value (high a) < (radix : ℤ)^6 := by
    norm_num [Bls.Fp.modulus,radix] at hsumrange ⊢
    omega
  rw [Int.emod_eq_of_lt hsumrange.1 hfit] at hsum
  obtain ⟨out,hbelow,hout⟩ := below_p_refines sum (by omega)
  refine ⟨out,?_,?_,k-(value sum/(Bls.Fp.modulus : ℤ))*(radix : ℤ)^6,?_⟩
  · simp (disch := decide) only [portable.fp.Wide.reduce,index_usize_eq,bind_tc_ok]
    simp only [show (0#usize).val = 0 from rfl, show (1#usize).val = 1 from rfl, show (2#usize).val = 2 from rfl, show (3#usize).val = 3 from rfl, show (4#usize).val = 4 from rfl, show (5#usize).val = 5 from rfl, show (6#usize).val = 6 from rfl, show (7#usize).val = 7 from rfl, show (8#usize).val = 8 from rfl, show (9#usize).val = 9 from rfl, show (10#usize).val = 10 from rfl, show (11#usize).val = 11 from rfl]
    change (do
      let (_,borrow) ← portable.fp.sub_words (high a) bls.constants.P_U64
      massert borrow
      let t0 ← portable.fp.reduce_row (low a)
      let t1 ← portable.fp.reduce_row t0
      let t2 ← portable.fp.reduce_row t1
      let t3 ← portable.fp.reduce_row t2
      let t4 ← portable.fp.reduce_row t3
      let t5 ← portable.fp.reduce_row t4
      let (sum,_) ← portable.fp.add_words t5 (high a)
      let out ← portable.fp.below_p sum
      ok out) = _
    simp only [hsub,hhigh,decide_true,bind_tc_ok]
    simp only [bind_tc_ok,h0,h1,h2,h3,h4,h5,hadd]
    change (do let out ← portable.fp.below_p sum; ok out) = _
    rw [hbelow,bind_tc_ok]
  · rw [hout]
    exact Int.emod_lt_of_pos _ (by decide)
  · have hdiv := Int.emod_add_mul_ediv (value sum) (Bls.Fp.modulus : ℤ)
    rw [←hout] at hdiv
    rw [hsum] at hdiv ⊢
    linear_combination hvalue+(radix : ℤ)^6*hdiv-hs

end LeanBlsSimd.Portable.Fp.Wide
