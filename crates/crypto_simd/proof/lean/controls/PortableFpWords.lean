import LeanBlsSimd.Portable.Fp.Words

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Fp.Controls

theorem carry_is_not_discarded :
    portable.fp.add_carry 18446744073709551615#u64 0#u64 1#u64 ≠ ok (0#u64,0#u64) := by
  intro h
  obtain ⟨s,c,he,_,hv⟩ := add_carry_refines 18446744073709551615#u64 0#u64 1#u64 (by decide)
  obtain ⟨rfl,rfl⟩ := Prod.mk.inj (Result.ok.inj (he.symm.trans h))
  norm_num at hv

theorem subtraction_borrow_is_not_reversed :
    portable.fp.sub_words (Array.make 1#usize [0#u64] (by rfl))
      (Array.make 1#usize [1#u64] (by rfl)) ≠
      ok (Array.make 1#usize [18446744073709551615#u64] (by rfl),false) := by
  intro h
  obtain ⟨out,he,_⟩ := sub_words_refines (Array.make 1#usize [0#u64] (by rfl))
    (Array.make 1#usize [1#u64] (by rfl))
  have bad := congrArg Prod.snd (Result.ok.inj (he.symm.trans h))
  norm_num [Word64.value,Word64.wordsValue,Array.make] at bad

theorem wide_high_word_is_not_discarded :
    portable.fp.wide_mul 9223372036854775808#u64 2#u64 ≠ ok (0#u64,0#u64) := by
  intro h
  obtain ⟨lo,hi,he,hv⟩ := wide_mul_refines 9223372036854775808#u64 2#u64
  obtain ⟨rfl,rfl⟩ := Prod.mk.inj (Result.ok.inj (he.symm.trans h))
  norm_num at hv

#print axioms add_carry_refines
#print axioms sub_words_refines
#print axioms add_words_refines
#print axioms wide_mul_refines

end LeanBlsSimd.Portable.Fp.Controls
