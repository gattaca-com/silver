import LeanBlsSimd.Portable.Fp.Conversion

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Fp.Wide
open Word64
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

theorem list_12 (a : Array U64 12#usize) :
    a.val = [a.val[0]'(by rw [a.property]; decide), a.val[1]'(by rw [a.property]; decide), a.val[2]'(by rw [a.property]; decide), a.val[3]'(by rw [a.property]; decide), a.val[4]'(by rw [a.property]; decide), a.val[5]'(by rw [a.property]; decide), a.val[6]'(by rw [a.property]; decide), a.val[7]'(by rw [a.property]; decide), a.val[8]'(by rw [a.property]; decide), a.val[9]'(by rw [a.property]; decide), a.val[10]'(by rw [a.property]; decide), a.val[11]'(by rw [a.property]; decide)] := by
  apply List.ext_getElem
  · exact a.property
  · intro i hi _
    have h : i < 12 := by simpa only [a.property] using hi
    interval_cases i <;> rfl

def low (a : portable.fp.Wide) : Array U64 6#usize :=
  Array.make 6#usize [a.val[0]'(by rw [a.property]; decide), a.val[1]'(by rw [a.property]; decide), a.val[2]'(by rw [a.property]; decide), a.val[3]'(by rw [a.property]; decide), a.val[4]'(by rw [a.property]; decide), a.val[5]'(by rw [a.property]; decide)] (by rfl)

def high (a : portable.fp.Wide) : Array U64 6#usize :=
  Array.make 6#usize [a.val[6]'(by rw [a.property]; decide), a.val[7]'(by rw [a.property]; decide), a.val[8]'(by rw [a.property]; decide), a.val[9]'(by rw [a.property]; decide), a.val[10]'(by rw [a.property]; decide), a.val[11]'(by rw [a.property]; decide)] (by rfl)

def pack (lo hi : Array U64 6#usize) : portable.fp.Wide :=
  Array.make 12#usize [lo.val[0]'(by rw [lo.property]; decide), lo.val[1]'(by rw [lo.property]; decide), lo.val[2]'(by rw [lo.property]; decide), lo.val[3]'(by rw [lo.property]; decide), lo.val[4]'(by rw [lo.property]; decide), lo.val[5]'(by rw [lo.property]; decide), hi.val[0]'(by rw [hi.property]; decide), hi.val[1]'(by rw [hi.property]; decide), hi.val[2]'(by rw [hi.property]; decide), hi.val[3]'(by rw [hi.property]; decide), hi.val[4]'(by rw [hi.property]; decide), hi.val[5]'(by rw [hi.property]; decide)] (by rfl)

theorem split_value (a : portable.fp.Wide) :
    value a = value (low a)+(radix : ℤ)^6*value (high a) := by
  conv_lhs => unfold value; rw [list_12 a]
  simp only [value,low,high,Array.make,wordsValue]
  ring

theorem pack_value (a b : Array U64 6#usize) :
    value (pack a b) = value a+(radix : ℤ)^6*value b := by
  conv_rhs => arg 1; unfold value; rw [list_6 a]
  conv_rhs => arg 2; arg 2; unfold value; rw [list_6 b]
  simp only [value,pack,Array.make,wordsValue]
  ring

theorem minus_refines (a b : portable.fp.Wide) (horder : value b ≤ value a) :
    ∃ out, portable.fp.Wide.minus a b = ok out ∧ value out = value a-value b := by
  obtain ⟨out,he,hv⟩ := sub_words_refines a b
  have ha := value_bounds a
  have hb := value_bounds b
  have hneg : ¬value a < value b := by omega
  refine ⟨out,?_,?_⟩
  · simp only [portable.fp.Wide.minus,he,bind_tc_ok]
    change (do massert (¬decide (value a < value b) = true); ok out) = _
    simp [hneg]
  · rw [hv]
    apply Int.emod_eq_of_lt <;> omega

theorem unreduced_add_refines (a b : portable.fp.Fp)
    (ha : value a < Bls.Fp.modulus) (hb : value b < Bls.Fp.modulus) :
    ∃ out, portable.fp.Fp.unreduced_add a b = ok out ∧ value out = value a+value b := by
  obtain ⟨out,he,hv⟩ := add_words_refines a b
  have ha0 := (value_bounds a).1
  have hb0 := (value_bounds b).1
  have hfit : value a+value b < (radix : ℤ)^6 := by
    norm_num [radix,Bls.Fp.modulus] at ha hb ⊢
    omega
  refine ⟨out,?_,?_⟩
  · simp only [portable.fp.Fp.unreduced_add,he,bind_tc_ok]
    rfl
  · rw [hv,Int.emod_eq_of_lt (by omega) hfit]

theorem cross_term_bounds (a0 a1 b0 b1 : ℤ)
    (ha0 : 0 ≤ a0 ∧ a0 < Bls.Fp.modulus) (ha1 : 0 ≤ a1 ∧ a1 < Bls.Fp.modulus)
    (hb0 : 0 ≤ b0 ∧ b0 < Bls.Fp.modulus) (hb1 : 0 ≤ b1 ∧ b1 < Bls.Fp.modulus) :
    0 ≤ (a0+a1)*(b0+b1)-a0*b0-a1*b1 ∧
      (a0+a1)*(b0+b1)-a0*b0-a1*b1 < 2*(Bls.Fp.modulus : ℤ)^2 ∧
      (a0+a1)*(b0+b1)-a0*b0-a1*b1 < (Bls.Fp.modulus : ℤ)*(radix : ℤ)^6 := by
  have hp : (0 : ℤ) < Bls.Fp.modulus := by decide
  have h01 : a0*b1 < (Bls.Fp.modulus : ℤ)*Bls.Fp.modulus :=
    lt_of_le_of_lt (mul_le_mul_of_nonneg_right ha0.2.le hb1.1) (mul_lt_mul_of_pos_left hb1.2 hp)
  have h10 : a1*b0 < (Bls.Fp.modulus : ℤ)*Bls.Fp.modulus :=
    lt_of_le_of_lt (mul_le_mul_of_nonneg_right ha1.2.le hb0.1) (mul_lt_mul_of_pos_left hb0.2 hp)
  have hcross : (a0+a1)*(b0+b1)-a0*b0-a1*b1 = a0*b1+a1*b0 := by ring
  rw [hcross]
  refine ⟨add_nonneg (mul_nonneg ha0.1 hb1.1) (mul_nonneg ha1.1 hb0.1),by nlinarith,?_⟩
  have hcapacity : 2*(Bls.Fp.modulus : ℤ)^2 < (Bls.Fp.modulus : ℤ)*(radix : ℤ)^6 := by norm_num [Bls.Fp.modulus,radix]
  nlinarith

theorem minus_mod_run (a b d : portable.fp.Wide) (borrow : Bool) (correction out : Array U64 6#usize)
    (he : portable.fp.sub_words a b = ok (d,borrow))
    (hp : portable.fp.p_if borrow = ok correction)
    (ha : portable.fp.add_words (high d) correction =
      ok (out,decide ((radix : ℤ)^6 ≤ value (high d)+value correction))) :
    portable.fp.Wide.minus_mod a b = ok (pack (low d) out) := by
  simp only [portable.fp.Wide.minus_mod,he,bind_tc_ok]
  simp (disch := decide) only [index_usize_eq,bind_tc_ok]
  simp only [show (0#usize).val = 0 from rfl, show (1#usize).val = 1 from rfl, show (2#usize).val = 2 from rfl, show (3#usize).val = 3 from rfl, show (4#usize).val = 4 from rfl, show (5#usize).val = 5 from rfl, show (6#usize).val = 6 from rfl, show (7#usize).val = 7 from rfl, show (8#usize).val = 8 from rfl, show (9#usize).val = 9 from rfl, show (10#usize).val = 10 from rfl, show (11#usize).val = 11 from rfl]
  change (do
    let a ← portable.fp.p_if borrow
    let (h,_) ← portable.fp.add_words (high d) a
    ok (pack (low d) h)) = _
  simp only [hp,ha,bind_tc_ok]

theorem minus_mod_refines (a b : portable.fp.Wide)
    (ha : value a < (Bls.Fp.modulus : ℤ)*(radix : ℤ)^6)
    (hb : value b < (Bls.Fp.modulus : ℤ)*(radix : ℤ)^6) :
    ∃ out, portable.fp.Wide.minus_mod a b = ok out ∧
      value out = (value a-value b) % ((Bls.Fp.modulus : ℤ)*(radix : ℤ)^6) := by
  obtain ⟨d,he,hd⟩ := sub_words_refines a b
  have ha0 := (value_bounds a).1
  have hb0 := (value_bounds b).1
  have hsplit := split_value d
  have hlo := value_bounds (low d)
  by_cases hborrow : value a < value b
  · obtain ⟨hi,hadd,hhi⟩ := add_words_refines (high d) bls.constants.P_U64
    refine ⟨pack (low d) hi,minus_mod_run a b d true _ hi (by simpa only [hborrow,decide_true] using he)
      (by simpa using p_if_refines true) hadd,?_⟩
    rw [modulus_words] at hhi
    rw [pack_value,hhi]
    norm_num [radix,Bls.Fp.modulus] at ha hb hd hsplit hlo ⊢
    omega
  · obtain ⟨hi,hadd,hhi⟩ := add_words_refines (high d) (Array.repeat 6#usize 0#u64)
    refine ⟨pack (low d) hi,minus_mod_run a b d false _ hi (by simpa only [hborrow,decide_false] using he)
      (by simpa using p_if_refines false) hadd,?_⟩
    have hz : value (Array.repeat 6#usize 0#u64) = 0 := rfl
    rw [hz,add_zero] at hhi
    rw [pack_value,hhi]
    norm_num [radix,Bls.Fp.modulus] at ha hb hd hsplit hlo ⊢
    omega

end LeanBlsSimd.Portable.Fp.Wide
