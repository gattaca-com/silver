import LeanBlsSimd.Kzg.Fr.Divide

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg
open LeanBlsSimd Word64 FrScalar

namespace LeanBlsSimd.Controls.FrScalar

def lowMaximum : Array U64 4#usize :=
  Array.make 4#usize [18446744073709551615#u64,0#u64,0#u64,0#u64] (by rfl)

def one : Array U64 4#usize :=
  Array.make 4#usize [1#u64,0#u64,0#u64,0#u64] (by rfl)

theorem carry_reaches_next_word :
    ∃ out, fr.add_words lowMaximum one = ok out ∧ value out = radix := by
  obtain ⟨out,hr,hvalue⟩ := add_words_refines lowMaximum one
  refine ⟨out,hr,?_⟩
  simpa only [value, wordsValue, lowMaximum, one, Array.make] using hvalue

theorem dropped_carry_rejected :
    fr.add_words lowMaximum one ≠ ok (Array.repeat 4#usize 0#u64) := by
  intro h
  obtain ⟨out,hr,hvalue⟩ := carry_reaches_next_word
  have heq : out = Array.repeat 4#usize 0#u64 := Result.ok.inj (hr.symm.trans h)
  subst out
  change (0 : ℤ) = radix at hvalue
  norm_num [radix] at hvalue

def secondWord : Array U64 4#usize :=
  Array.make 4#usize [0#u64,1#u64,0#u64,0#u64] (by rfl)

theorem borrow_reaches_next_word :
    ∃ out, fr.sub_words secondWord one = ok (out,false) ∧ value out = radix-1 := by
  obtain ⟨out,hr,hvalue⟩ := sub_words_refines secondWord one
  refine ⟨out,hr,?_⟩
  simpa only [value,wordsValue,secondWord,one,Array.make] using hvalue

theorem missing_borrow_rejected (out : Array U64 4#usize) :
    fr.sub_words (Array.repeat 4#usize 0#u64) one ≠ ok (out,false) := by
  intro h
  obtain ⟨actual,hr,_⟩ := sub_words_refines (Array.repeat 4#usize 0#u64) one
  change fr.sub_words (Array.repeat 4#usize 0#u64) one = ok (actual,true) at hr
  have impossible := hr.symm.trans h
  cases impossible

def allMaximum : Array U64 4#usize := Array.repeat 4#usize 18446744073709551615#u64

theorem dropped_multiply_add_top_rejected (out : Array U64 4#usize) :
    fr.multiply_add (Array.repeat 4#usize 0#u64) allMaximum 18446744073709551615#u64 ≠
      ok (out,0#u64) := by
  intro h
  obtain ⟨actual,top,hr,hvalue⟩ := multiply_add_refines
    (Array.repeat 4#usize 0#u64) allMaximum 18446744073709551615#u64
  have heq := Prod.mk.inj (Result.ok.inj (hr.symm.trans h))
  rcases heq with ⟨rfl,rfl⟩
  have hout := value_bounds actual
  have hfull : value allMaximum = (radix : ℤ)^4-1 := by rfl
  have hzero : value (Array.repeat 4#usize 0#u64) = 0 := by rfl
  rw [hfull,hzero] at hvalue
  norm_num [radix] at hvalue hout
  omega

theorem zeroed_reduction_rejected :
    fr.divide_out_word one 0#u64 ≠ ok (Array.repeat 4#usize 0#u64) := by
  intro h
  obtain ⟨out,m,hr,hvalue,hcancel⟩ := divide_out_word_refines one 0#u64
  have heq := Result.ok.inj (hr.symm.trans h)
  subst out
  have hm := m.hBounds
  have hrval : value fr.R = (EthLib.Cryptography.Bls.Fr.modulus : ℤ) := by
    unfold fr.R
    rfl
  rw [hrval] at hvalue hcancel
  norm_num [value,wordsValue,Array.repeat,one,Array.make,radix,
    EthLib.Cryptography.Bls.Fr.modulus,UScalarTy.numBits] at hvalue hcancel hm
  change (0 : ℤ) = _ at hvalue
  obtain ⟨k,hk⟩ := hcancel
  omega

end LeanBlsSimd.Controls.FrScalar
