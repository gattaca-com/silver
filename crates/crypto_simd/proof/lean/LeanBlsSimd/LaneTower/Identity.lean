import LeanBlsSimd.LaneTower.InverseCoordinates

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

def oneIndices : Array I64 8#usize := Array.make 8#usize
  [8#i64, 0#i64, 0#i64, 0#i64, 0#i64, 0#i64, 0#i64, 0#i64] (by rfl)

def oneReal : Fp8 := Fp8.zero.permute2 Fp8.one (ofArray (fun i => Int64.ofBitVec i.bv) oneIndices)

def oneValues : P F := (fun l => if l = 0 then 1 else 0, fun _ => 0)

theorem one_exact : fp12.Fp12.one = ok ⟨toFp8 oneReal, toFp8 Fp8.zero⟩ := by
  simp only [fp12.Fp12.one, Fp8.zero_refines, Fp8.one_refines, Fp8.permute2_refines,
    ofFp8_toFp8, bind_tc_ok]
  rfl

theorem one_real_holds (l : Fin 8) : oneReal.Holds l (oneValues.1 l) := by
  have h : oneReal.lane l = if l = 0 then Fp8.one.lane 0 else Fp8.zero.lane 0 := by
    rw [oneReal, Fp8.lane_permute2]
    fin_cases l <;> rfl
  constructor
  · rw [h]
    split_ifs
    · exact Fp8.inv_one 0
    · exact Fp8.inv_zero 0
  · rw [h]
    dsimp [oneValues]
    split_ifs
    · exact Fp8.decode_lane_one 0
    · exact Fp8.decode_lane_zero 0

theorem mask63_bit (l : ℕ) : (63 : Mmask8).toNat.testBit l = decide (l < 6) := by
  by_cases hl : l < 6
  · interval_cases l <;> decide
  · exact (Nat.testBit_lt_two_pow (lt_of_lt_of_le (by decide : 63 < 2 ^ 6)
      (Nat.pow_le_pow_right (by decide) (by omega)))).trans (by simp [hl])

theorem mask63_eq (m : Mmask8) : (m &&& 63) = 63 ↔ ∀ l : Fin 6, m.toNat.testBit l = true := by
  constructor
  · intro h l
    have hb := congrArg (fun k : Mmask8 => k.toNat.testBit l.val) h
    simpa only [Mmask8.testBit_and, mask63_bit, l.isLt, decide_true, Bool.and_true] using hb
  · intro h
    apply UInt8.toNat_inj.mp
    apply Nat.eq_of_testBit_eq
    intro i
    rw [Mmask8.testBit_and, mask63_bit]
    by_cases hi : i < 6
    · simp only [hi, decide_true, Bool.and_true]
      exact h ⟨i, hi⟩
    · simp [hi]

def oneMask (x : fp2x8.Fp2x8) : Mmask8 :=
  ((ofFp8 x.c0).mul Fp8.one).eq_mask oneReal &&&
    ((ofFp8 x.c1).mul Fp8.one).eq_mask Fp8.zero

theorem is_one_run (x : fp2x8.Fp2x8) :
    fp12.Fp12.is_one x = ok (decide ((oneMask x &&& 63) = 63)) := by
  have ho : fp8.Fp8.splat_limbs constants.R_MOD_P = ok (toFp8 Fp8.one) := Fp8.one_refines
  simp only [fp12.Fp12.is_one, ho, one_exact, Fp8.mul_refines, Fp8.eq_mask_refines,
    ofFp8_toFp8, lift, bind_tc_ok, show 63#u8 = toU8 63 from rfl, toU8_and, toU8_inj]
  rfl

theorem one_mask_bits {x : fp2x8.Fp2x8} {a : P F} (hx : Strict2 256 x a) (l : Fin 8) :
    (oneMask x).toNat.testBit l = decide (a.1 l = oneValues.1 l ∧ a.2 l = 0) := by
  have h0 := ((hx.1 l).mul (Fp8.holds_one l).boundRep (by decide)).of_eq (mul_one (a.1 l))
  have h1 := ((hx.2 l).mul (Fp8.holds_one l).boundRep (by decide)).of_eq (mul_one (a.2 l))
  rw [oneMask, Mmask8.testBit_and, h0.testBit_eq_mask (one_real_holds l),
    h1.testBit_eq_mask (Fp8.holds_zero l), Bool.decide_and]

theorem value_eq_one (a : P F) :
    (∀ l : Fin 6, a.1 ⟨l.val, by omega⟩ = oneValues.1 ⟨l.val, by omega⟩ ∧
      a.2 ⟨l.val, by omega⟩ = 0) ↔ value a = Bls.Fp12.one := by
  constructor
  · intro h
    have h0 := h ⟨0, by decide⟩
    have h1 := h ⟨1, by decide⟩
    have h2 := h ⟨2, by decide⟩
    have h3 := h ⟨3, by decide⟩
    have h4 := h ⟨4, by decide⟩
    have h5 := h ⟨5, by decide⟩
    simp only [oneValues, Fin.mk_zero, ↓reduceIte] at h0 h1 h2 h3 h4 h5
    apply fp12_ext <;> apply fp6_ext <;> apply fp2_ext <;>
      simp_all [value, Bls.Fp12.one, Bls.Fp6.one, Bls.Fp6.zero, Bls.Fp2.one, Bls.Fp2.zero]
  · intro h l
    have hv : value a = value oneValues := by
      rw [h]
      apply fp12_ext <;> apply fp6_ext <;> apply fp2_ext <;> rfl
    have hcoords := hv
    simp only [value, Bls.Fp12.mk.injEq, Bls.Fp6.mk.injEq, Bls.Fp2.mk.injEq] at hcoords
    rcases hcoords with ⟨⟨h0, h1, h2⟩, h3, h4, h5⟩
    fin_cases l
    · exact h0
    · exact h1
    · exact h2
    · exact h3
    · exact h4
    · exact h5

theorem is_one_refines {x : fp2x8.Fp2x8} {a : Bls.Fp12} (hx : Rep x a) :
    fp12.Fp12.is_one x = ok a.isOne := by
  obtain ⟨v, h0, h1, rfl⟩ := hx
  rw [is_one_run]
  congr 1
  apply Bool.eq_iff_iff.mpr
  rw [decide_eq_true_eq, mask63_eq, Fp12.isOne_iff]
  have hm : (∀ l : Fin 6, (oneMask x).toNat.testBit l = true) ↔
      (∀ l : Fin 6, v.1 ⟨l.val, by omega⟩ = oneValues.1 ⟨l.val, by omega⟩ ∧
        v.2 ⟨l.val, by omega⟩ = 0) := by
    apply forall_congr'
    intro l
    rw [one_mask_bits ⟨h0, h1⟩ ⟨l.val, by omega⟩, decide_eq_true_eq]
  rw [hm, value_eq_one]
  exact ⟨fun h => by rw [h, Fp12.toField_one],
    fun h => Fp12.toField.injective (by simpa using h)⟩

end LeanBlsSimd.LaneTower
