import LeanBlsSimd.Kzg.G1Arithmetic
import LeanBlsSimd.Refines.Fp8

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8

def zeroWord (p : blst.blst_p1_affine) (j : Fin 6) : Prop :=
  p.x.l.val[j.val]'(by rw [p.x.l.property]; exact j.isLt) = 0#u64 ∧
  p.y.l.val[j.val]'(by rw [p.y.l.property]; exact j.isLt) = 0#u64

instance (p : blst.blst_p1_affine) (j : Fin 6) : Decidable (zeroWord p j) := by
  unfold zeroWord
  infer_instance

private theorem infinity_loop_refines (p : blst.blst_p1_affine) (k : Usize)
    (hk : k.val ≤ 6) :
    ∃ out, msm8.is_infinity_loop p k = ok out ∧
      (out = 6#usize ↔ ∀ j : Fin 6, k.val ≤ j.val → zeroWord p j) := by
  unfold msm8.is_infinity_loop
  induction hn : 6 - k.val generalizing k with
  | zero =>
    have hk6 : k.val = 6 := by omega
    have heq : k = 6#usize := UScalar.eq_of_val_eq (by simpa using hk6)
    refine ⟨k, ?_, ?_⟩
    · rw [loop.eq_1]
      simp [msm8.is_infinity_loop.body, UScalar.lt_equiv, hk6]
    · simp [heq]
  | succ n ih =>
    have hlt : k.val < 6 := by omega
    have hxlen : k.val < p.x.l.val.length := by rw [p.x.l.property]; exact hlt
    have hylen : k.val < p.y.l.val.length := by rw [p.y.l.property]; exact hlt
    have hk6 : k ≠ 6#usize := by
      intro h
      have heq := congrArg UScalar.val h
      simp only [UScalar.ofNatCore_val_eq] at heq
      omega
    by_cases hx : p.x.l.val[k.val] = 0#u64
    · by_cases hy : p.y.l.val[k.val] = 0#u64
      · let next : Usize := UScalar.ofNatCore (k.val + 1)
          (by have := two_pow_32_le_usize; omega)
        have hnext : next.val = k.val + 1 := UScalar.ofNatCore_val_eq _
        obtain ⟨out, hout, hz⟩ := ih next (by omega) (by omega)
        refine ⟨out, ?_, ?_⟩
        · rw [loop.eq_1]
          simp only [msm8.is_infinity_loop.body, UScalar.lt_equiv,
            UScalar.ofNatCore_val_eq, hlt, ↓reduceIte,
            index_usize_eq p.x.l k hlt, index_usize_eq p.y.l k hlt,
            bind_tc_ok, hx, hy]
          rw [add_ok _ _ (by
            have := two_pow_32_le_usize
            simp only [UScalar.ofNatCore_val_eq]
            omega)]
          exact hout
        · rw [hz]
          constructor
          · intro h j hj
            by_cases hjk : j.val = k.val
            · exact ⟨by simpa [hjk] using hx, by simpa [hjk] using hy⟩
            · exact h j (by omega)
          · intro h j hj
            exact h j (by omega)
      · refine ⟨k, ?_, ?_⟩
        · rw [loop.eq_1]
          simp [msm8.is_infinity_loop.body, UScalar.lt_equiv, hlt,
            index_usize_eq p.x.l k hlt, index_usize_eq p.y.l k hlt, hx, hy]
        · constructor
          · exact fun h => False.elim (hk6 h)
          · intro h
            exact False.elim (hy (h ⟨k.val, hlt⟩ (Nat.le_refl _)).2)
    · refine ⟨k, ?_, ?_⟩
      · rw [loop.eq_1]
        simp [msm8.is_infinity_loop.body, UScalar.lt_equiv, hlt,
          index_usize_eq p.x.l k hlt, hx]
      · constructor
        · exact fun h => False.elim (hk6 h)
        · intro h
          exact False.elim (hx (h ⟨k.val, hlt⟩ (Nat.le_refl _)).1)

theorem is_infinity_refines (p : blst.blst_p1_affine) :
    msm8.is_infinity p = ok (decide (∀ j : Fin 6, zeroWord p j)) := by
  obtain ⟨out, hout, hz⟩ := infinity_loop_refines p 0#usize (by decide)
  simp only [UScalar.ofNatCore_val_eq, Nat.zero_le, forall_true_left] at hz
  simp only [msm8.is_infinity, hout, bind_tc_ok]
  apply congrArg ok
  exact decide_eq_decide.mpr hz

end LeanBlsSimd.Msm8

namespace LeanBlsSimd.Msm8

open EthLib.Cryptography Bls

private theorem encoded_zero_word (j : Fin 6) :
    (Kzg.fpEncode Fp.zero).l.val[j.val]'(by
      rw [(Kzg.fpEncode Fp.zero).l.property]
      exact j.isLt) = 0#u64 := by
  unfold Kzg.fpEncode
  simp only [show Fp.zero.val = 0 from rfl, Nat.zero_mul, Nat.zero_mod]
  simp only [Kzg.words, List.getElem_map, Nat.zero_div]
  rfl

private theorem blst_fp_ext (x y : blst.blst_fp) (h : x.l = y.l) : x = y := by
  cases x
  cases y
  exact congrArg blst.blst_fp.mk h

theorem all_zero_words_iff (p : blst.blst_p1_affine) :
    (∀ j : Fin 6, zeroWord p j) ↔
      p = ⟨Kzg.fpEncode Fp.zero, Kzg.fpEncode Fp.zero⟩ := by
  constructor
  · intro h
    have hx : p.x = Kzg.fpEncode Fp.zero := by
      apply blst_fp_ext
      apply Subtype.ext
      apply List.ext_getElem
      · rw [p.x.l.property, (Kzg.fpEncode Fp.zero).l.property]
      · intro i hi hi'
        have hi6 : i < 6 := by simpa only [p.x.l.property] using hi
        exact (h ⟨i, hi6⟩).1.trans (encoded_zero_word ⟨i, hi6⟩).symm
    have hy : p.y = Kzg.fpEncode Fp.zero := by
      apply blst_fp_ext
      apply Subtype.ext
      apply List.ext_getElem
      · rw [p.y.l.property, (Kzg.fpEncode Fp.zero).l.property]
      · intro i hi hi'
        have hi6 : i < 6 := by simpa only [p.y.l.property] using hi
        exact (h ⟨i, hi6⟩).2.trans (encoded_zero_word ⟨i, hi6⟩).symm
    cases p
    simp_all
  · intro h j
    subst p
    exact ⟨encoded_zero_word j, encoded_zero_word j⟩

theorem all_zero_words_read_infinity (p : blst.blst_p1_affine)
    (hp : p = Kzg.g1Affine (Kzg.g1ReadAffine p)) :
    (∀ j : Fin 6, zeroWord p j) ↔ (Kzg.g1ReadAffine p).isInfinity = true := by
  rw [all_zero_words_iff]
  constructor
  · intro h
    rw [h]
    simp only [Kzg.g1ReadAffine, Kzg.fpRead_fpEncode,
      show Fp.zero.isZero = true from rfl, Bool.and_self, if_true]
    rfl
  · intro h
    calc
      p = Kzg.g1Affine (Kzg.g1ReadAffine p) := hp
      _ = _ := by
        unfold Kzg.g1Affine G1.toAffine
        rw [show (Kzg.g1ReadAffine p).z.isZero = true from h]
        rfl

theorem is_infinity_correct (p : blst.blst_p1_affine)
    (hp : Kzg.G1AffineValid p) :
    msm8.is_infinity p = ok (Kzg.g1ReadAffine p).isInfinity := by
  rw [is_infinity_refines]
  apply congrArg ok
  apply Bool.eq_iff_iff.mpr
  simp only [decide_eq_true_eq]
  exact all_zero_words_read_infinity p hp.1

theorem is_infinity_group_zero (p : blst.blst_p1_affine)
    (hp : Kzg.G1AffineValid p) :
    msm8.is_infinity p = ok true ↔ G1.toPoint (Kzg.g1ReadAffine p) = 0 := by
  rw [is_infinity_correct p hp, Kzg.g1Valid_toPoint_zero_iff hp.2]
  simp only [Result.ok.injEq]

end LeanBlsSimd.Msm8
