import LeanBlsSimd.Refines.Basic
import Mathlib.Tactic

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.SignedDigits
open silver_crypto_simd.bls.msm8.buckets

abbrev radix : ℕ := 2 ^ 64

def wordsValue : List U64 → ℕ
  | [] => 0
  | x :: xs => x.val + radix * wordsValue xs

def value (a : Array U64 4#usize) : ℕ := wordsValue a.val

def wordAt (xs : List U64) (j : ℕ) : U64 := xs[j]?.getD 0#u64

theorem wordsValue_drop (xs : List U64) (q : ℕ) :
    wordsValue (xs.drop q) = wordsValue xs / radix ^ q := by
  induction q generalizing xs with
  | zero => simp
  | succ q ih =>
    cases xs with
    | nil => simp [wordsValue]
    | cons x xs =>
      rw [List.drop_succ_cons, ih, pow_succ, Nat.mul_comm (radix ^ q),
        ← Nat.div_div_eq_div_mul]
      congr 1
      have hx : x.val < radix := x.hBounds
      simp [wordsValue, Nat.add_mul_div_left, Nat.div_eq_of_lt hx]

theorem wordsValue_pair (xs : List U64) :
    wordsValue xs % 2 ^ 128 = (wordAt xs 0).val + radix * (wordAt xs 1).val := by
  cases xs with
  | nil => simp [wordsValue, wordAt]
  | cons x xs =>
    cases xs with
    | nil =>
      have hx := x.hBounds
      simp [wordsValue, wordAt]
      norm_num [UScalarTy.numBits] at hx ⊢
      omega
    | cons y ys =>
      have hx := x.hBounds
      have hy := y.hBounds
      simp only [wordsValue, wordAt, List.getElem?_cons_zero, List.getElem?_cons_succ,
        Option.getD_some]
      norm_num [radix, UScalarTy.numBits] at *
      omega

theorem window_mod (x r w : ℕ) (hrw : r + w ≤ 128) :
    x % 2 ^ 128 / 2 ^ r % 2 ^ w = x / 2 ^ r % 2 ^ w := by
  have hp : 2 ^ 128 = 2 ^ r * 2 ^ (128 - r) := by
    rw [← pow_add, Nat.add_sub_of_le (by omega)]
  rw [hp, Nat.mod_mul_right_div_self]
  apply Nat.mod_mod_of_dvd
  exact pow_dvd_pow 2 (by omega)

theorem window_value (xs : List U64) (bit w : ℕ) (hw : w ≤ 64) :
    ((wordAt xs (bit / 64)).val + radix * (wordAt xs (bit / 64 + 1)).val) /
        2 ^ (bit % 64) % 2 ^ w = wordsValue xs / 2 ^ bit % 2 ^ w := by
  have hp := wordsValue_pair (xs.drop (bit / 64))
  simp only [wordAt, List.getElem?_drop, Nat.add_zero] at hp
  unfold wordAt
  rw [← hp, wordsValue_drop, window_mod _ _ _ (by have := Nat.mod_lt bit (by decide : 0 < 64); omega),
    Nat.div_div_eq_div_mul]
  congr 2
  rw [radix, ← pow_mul, ← pow_add]
  congr 1
  exact Nat.div_add_mod bit 64

end LeanBlsSimd.SignedDigits
namespace LeanBlsSimd.SignedDigits
open silver_crypto_simd.bls.msm8

theorem cast128_val (x : U64) : (UScalar.cast .U128 x).val = x.val := by
  rw [UScalar.cast_val_eq]
  exact Nat.mod_eq_of_lt (lt_trans x.hBounds (by norm_num [UScalarTy.numBits]))

def pair (lo hi : U64) : U128 :=
  UScalar.cast .U128 lo ||| ⟨(UScalar.cast .U128 hi).bv.shiftLeft 64⟩

theorem pair_val (lo hi : U64) : (pair lo hi).val = lo.val + radix * hi.val := by
  change ((UScalar.cast .U128 lo).bv ||| (UScalar.cast .U128 hi).bv.shiftLeft 64).toNat = _
  rw [BitVec.toNat_or]
  rw [show ((UScalar.cast .U128 hi).bv.shiftLeft 64).toNat =
    (UScalar.cast .U128 hi).bv.toNat <<< 64 % 2 ^ 128 from BitVec.toNat_shiftLeft]
  change (UScalar.cast .U128 lo).val ||| ((UScalar.cast .U128 hi).val <<< 64) % 2 ^ 128 = _
  rw [cast128_val, cast128_val, Nat.shiftLeft_eq]
  have hbound : hi.val * 2 ^ 64 < 2 ^ 128 := by
    have := hi.hBounds
    norm_num [UScalarTy.numBits] at *
    omega
  rw [Nat.mod_eq_of_lt hbound, Nat.or_comm, Nat.mul_comm hi.val,
    ← Nat.two_pow_add_eq_or_of_lt (show lo.val < 2 ^ 64 from lo.hBounds)]
  simp only [radix, Nat.add_comm]

def rawWindow (lo hi : U64) (r w : ℕ) : U64 :=
  let shifted : U128 := ⟨(pair lo hi).bv.ushiftRight r⟩
  UScalar.cast .U64 shifted &&& ⟨BitVec.ofNat 64 (2 ^ w - 1)⟩

theorem rawWindow_val (lo hi : U64) (r w : ℕ) (hw : w < 64) :
    (rawWindow lo hi r w).val = (lo.val + radix * hi.val) / 2 ^ r % 2 ^ w := by
  have hpow : 2 ^ w < 2 ^ 64 := Nat.pow_lt_pow_right (by decide) hw
  change ((UScalar.cast .U64 (⟨(pair lo hi).bv.ushiftRight r⟩ : U128)).bv &&&
    BitVec.ofNat UScalarTy.U64.numBits (2 ^ w - 1)).toNat = _
  rw [BitVec.toNat_and, BitVec.toNat_ofNat]
  change (UScalar.cast .U64 (⟨(pair lo hi).bv.ushiftRight r⟩ : U128)).val &&&
    (2 ^ w - 1) % 2 ^ 64 = _
  rw [Nat.mod_eq_of_lt (by omega), UScalar.cast_val_eq]
  change ((pair lo hi).bv.ushiftRight r).toNat % 2 ^ 64 &&& (2 ^ w - 1) = _
  rw [show ((pair lo hi).bv.ushiftRight r).toNat = (pair lo hi).bv.toNat >>> r from BitVec.toNat_ushiftRight _ _, Nat.shiftRight_eq_div_pow,
    Nat.and_two_pow_sub_one_eq_mod, Nat.mod_mod_of_dvd _ (pow_dvd_pow 2 (by omega))]
  exact congrArg (fun x => x / 2 ^ r % 2 ^ w) (pair_val lo hi)

theorem wordAt_eq (words : Array U64 4#usize) (i : Usize) (hi : i.val < 4) :
    wordAt words.val i.val = words.val[i.val]'(by rw [words.property]; exact hi) := by
  simp [wordAt, words.property, hi]

theorem high_refines (words : Array U64 4#usize) (i : Usize) :
    (if i < 4#usize then Array.index_usize words i else ok 0#u64) =
      ok (wordAt words.val i.val) := by
  simp only [UScalar.lt_equiv, show (4#usize).val = 4 from rfl]
  by_cases hi : i.val < 4
  · rw [if_pos hi, index_usize_eq words i hi, wordAt_eq words i hi]
  · rw [if_neg hi]
    have hn : words.val[i.val]? = none := List.getElem?_eq_none (by simpa only [words.property] using Nat.le_of_not_lt hi)
    simp only [wordAt, hn, Option.getD_none]

theorem unsigned_window_raw (self : buckets.SignedDigits)
    (hb : self.bit.val < 256) (hw : self.window_bits.val < 64) :
    self.unsigned_window = ok (rawWindow (wordAt self.words.val (self.bit.val / 64))
      (wordAt self.words.val (self.bit.val / 64 + 1)) (self.bit.val % 64) self.window_bits.val) := by
  let q : Usize := UScalar.ofNatCore (self.bit.val / 64)
    (lt_of_le_of_lt (Nat.div_le_self _ _) self.bit.hBounds)
  have hq : q.val < 4 := by change self.bit.val / 64 < 4; omega
  let next : Usize := UScalar.ofNatCore (q.val + 1)
    (lt_of_lt_of_le (by omega : q.val + 1 < 2 ^ 32) two_pow_32_le_usize)
  let r : Usize := UScalar.ofNatCore (self.bit.val % 64)
    (lt_of_le_of_lt (Nat.mod_le _ _) self.bit.hBounds)
  have hr : r.val < 128 := by change self.bit.val % 64 < 128; omega
  have hp : 2 ^ self.window_bits.val < 2 ^ 64 := Nat.pow_lt_pow_right (by decide) hw
  have hshift : ((⟨(1#u64).bv.shiftLeft self.window_bits.val⟩ : U64)).val =
      2 ^ self.window_bits.val := by
    change ((1#u64).bv.shiftLeft self.window_bits.val).toNat = _
    rw [show ((1#u64).bv.shiftLeft self.window_bits.val).toNat =
      (1#u64).bv.toNat <<< self.window_bits.val % 2 ^ 64 from BitVec.toNat_shiftLeft]
    simp only [show (1#u64).bv.toNat = 1 from rfl, Nat.one_shiftLeft]
    exact Nat.mod_eq_of_lt hp
  rw [buckets.SignedDigits.unsigned_window, div_ok _ _ (by decide)]
  simp only [bind_tc_ok]
  rw [show (UScalar.ofNatCore (self.bit.val / (64#usize).val)
    (lt_of_le_of_lt (Nat.div_le_self _ _) self.bit.hBounds) : Usize) = q from rfl]
  rw [usize_add_ok q 1#usize (by change q.val + 1 < 2 ^ 32; omega)]
  simp only [bind_tc_ok]
  rw [show (UScalar.ofNatCore (q.val + (1#usize).val)
    (by change q.val + 1 < 2 ^ UScalarTy.Usize.numBits; exact lt_of_lt_of_le (by omega : q.val + 1 < 2 ^ 32) two_pow_32_le_usize) : Usize) = next from rfl]
  rw [high_refines, index_usize_eq self.words q hq]
  simp only [bind_tc_ok, lift]
  rw [show (UScalar.cast .U128 (wordAt self.words.val next.val)) <<< 64#i32 =
    ok (⟨(UScalar.cast .U128 (wordAt self.words.val next.val)).bv.shiftLeft 64⟩ : U128) from rfl,
    rem_ok _ _ (by decide)]
  simp only [bind_tc_ok]
  rw [show (UScalar.ofNatCore (self.bit.val % (64#usize).val)
    (lt_of_le_of_lt (Nat.mod_le _ _) self.bit.hBounds) : Usize) = r from rfl]
  rw [shiftRight_ok (ty := .U128) _ r hr]
  simp only [bind_tc_ok]
  rw [shiftLeft_ok _ _ hw]
  simp only [bind_tc_ok]
  rw [sub_ok _ _ (by rw [hshift]; exact Nat.one_le_pow _ _ (by decide))]
  simp only [bind_tc_ok]
  simp only [hshift]
  rw [← wordAt_eq self.words q hq]
  have hmask : (UScalar.ofNatCore (2 ^ self.window_bits.val - 1) (by change _ < 2 ^ 64; omega) : U64) =
      ⟨BitVec.ofNat 64 (2 ^ self.window_bits.val - 1)⟩ := by
    apply UScalar.eq_of_val_eq
    exact (Nat.mod_eq_of_lt (by omega : 2 ^ self.window_bits.val - 1 < 2 ^ 64)).symm
  simp only [show (1#u64).val = 1 from rfl, hmask]
  rfl

theorem unsigned_window_refines (self : buckets.SignedDigits)
    (hb : self.bit.val < 256) (hw : self.window_bits.val < 64) :
    ∃ out : U64, self.unsigned_window = ok out ∧
      out.val = value self.words / 2 ^ self.bit.val % 2 ^ self.window_bits.val := by
  refine ⟨_, unsigned_window_raw self hb hw, ?_⟩
  rw [rawWindow_val _ _ _ _ hw, window_value _ _ _ (by omega)]
  rfl

end LeanBlsSimd.SignedDigits
namespace LeanBlsSimd.SignedDigits
open silver_crypto_simd.bls.msm8

def digitValue (magnitude : ℕ) (negative : Bool) : ℤ :=
  if negative then -(magnitude : ℤ) else magnitude

theorem one_shiftLeft (w : Usize) (hw : w.val < 64) :
    1#u64 <<< w = ok ((UScalar.ofNatCore (2 ^ w.val)
      (Nat.pow_lt_pow_right (by decide) hw) : U64)) := by
  rw [shiftLeft_ok _ _ hw]
  congr 1
  apply UScalar.eq_of_val_eq
  change ((1#u64).bv.shiftLeft w.val).toNat = 2 ^ w.val
  rw [show ((1#u64).bv.shiftLeft w.val).toNat = (1#u64).bv.toNat <<< w.val % 2 ^ 64
    from BitVec.toNat_shiftLeft]
  simp only [show (1#u64).bv.toNat = 1 from rfl, Nat.one_shiftLeft]
  exact Nat.mod_eq_of_lt (Nat.pow_lt_pow_right (by decide) hw)

theorem cast_usize_val (x : U64) (hx : x.val < 2 ^ 32) :
    (UScalar.cast .Usize x).val = x.val := by
  rw [UScalar.cast_val_eq]
  exact Nat.mod_eq_of_lt (lt_of_lt_of_le hx two_pow_32_le_usize)

theorem next_digit_refines (self : buckets.SignedDigits)
    (hb : self.bit.val < 256) (hwl : 1 ≤ self.window_bits.val) (hwh : self.window_bits.val ≤ 8)
    (hc : self.carry.val ≤ 1) :
    ∃ (magnitude : Usize) (negative : Bool) (next : buckets.SignedDigits),
      self.next_digit = ok ((magnitude, negative), next) ∧
      next.words = self.words ∧ next.window_bits = self.window_bits ∧
      next.bit.val = self.bit.val + self.window_bits.val ∧
      next.carry.val = (if negative then 1 else 0) ∧
      negative = decide (2 ^ (self.window_bits.val - 1) <
        value self.words / 2 ^ self.bit.val % 2 ^ self.window_bits.val + self.carry.val) ∧
      magnitude.val ≤ 2 ^ (self.window_bits.val - 1) ∧
      digitValue magnitude.val negative + (2 ^ self.window_bits.val : ℤ) * next.carry.val =
        (value self.words / 2 ^ self.bit.val % 2 ^ self.window_bits.val : ℕ) + self.carry.val := by
  obtain ⟨u, hu, huv⟩ := unsigned_window_refines self hb (by omega)
  have hul : u.val < 2 ^ self.window_bits.val := by rw [huv]; exact Nat.mod_lt _ (by positivity)
  have hp : 2 ^ self.window_bits.val ≤ 256 := by
    exact le_trans (Nat.pow_le_pow_right (by decide) hwh) (by decide)
  have hv : u.val + self.carry.val ≤ 2 ^ self.window_bits.val := by omega
  have hv64 : u.val + self.carry.val < 2 ^ 64 := by omega
  let v : U64 := UScalar.ofNatCore (u.val + self.carry.val) hv64
  have hvv : v.val = u.val + self.carry.val := rfl
  have half : 2 ^ self.window_bits.val = 2 * 2 ^ (self.window_bits.val - 1) := by
    rw [Nat.mul_comm 2, ← pow_succ, Nat.sub_add_cancel hwl]
  let bit' : Usize := UScalar.ofNatCore (self.bit.val + self.window_bits.val)
    (lt_of_lt_of_le (by omega : self.bit.val + self.window_bits.val < 2 ^ 32) two_pow_32_le_usize)
  by_cases hn : 2 ^ (self.window_bits.val - 1) < v.val
  · change 2 ^ (self.window_bits.val - 1) < u.val + self.carry.val at hn
    let mag : U64 := UScalar.ofNatCore (2 ^ self.window_bits.val - v.val) (by change _ < 2 ^ 64; omega)
    refine ⟨UScalar.cast .Usize mag, true, { self with bit := bit', carry := 1#u64 }, ?_, rfl, rfl, rfl, rfl, ?_, ?_, ?_⟩
    · simp only [buckets.SignedDigits.next_digit, hu, bind_tc_ok]
      rw [add_ok _ _ hv64]
      simp only [bind_tc_ok]
      rw [sub_ok self.window_bits 1#usize hwl]
      simp only [bind_tc_ok]
      rw [one_shiftLeft _ (by change self.window_bits.val - 1 < 64; omega)]
      simp only [bind_tc_ok]
      simp only [UScalar.lt_equiv, UScalar.ofNatCore_val_eq, show (1#usize).val = 1 from rfl]
      rw [if_pos hn, one_shiftLeft self.window_bits (by omega)]
      simp only [bind_tc_ok]
      rw [sub_ok (UScalar.ofNatCore (2 ^ self.window_bits.val)
        (show 2 ^ self.window_bits.val < 2 ^ 64 from by omega) : U64) v hv]
      simp only [bind_tc_ok, lift]
      rw [usize_add_ok self.bit self.window_bits (by omega)]
      rfl
    · simp [← huv, hn]
    · rw [cast_usize_val mag (by change 2 ^ self.window_bits.val - v.val < 2 ^ 32; omega)]
      change 2 ^ self.window_bits.val - v.val ≤ _
      omega
    · rw [cast_usize_val mag (by change 2 ^ self.window_bits.val - v.val < 2 ^ 32; omega)]
      simp only [digitValue, if_true, show (1#u64).val = 1 from rfl, Nat.cast_one, mul_one]
      change -((2 ^ self.window_bits.val - (u.val + self.carry.val) : ℕ) : ℤ) +
        (2 ^ self.window_bits.val : ℤ) = _
      rw [Nat.cast_sub hv, Nat.cast_add, Nat.cast_pow, Nat.cast_ofNat, huv]
      ring
  · change ¬2 ^ (self.window_bits.val - 1) < u.val + self.carry.val at hn
    refine ⟨UScalar.cast .Usize v, false, { self with bit := bit', carry := 0#u64 }, ?_, rfl, rfl, rfl, rfl, ?_, ?_, ?_⟩
    · simp only [buckets.SignedDigits.next_digit, hu, bind_tc_ok]
      rw [add_ok _ _ hv64]
      simp only [bind_tc_ok]
      rw [sub_ok self.window_bits 1#usize hwl]
      simp only [bind_tc_ok]
      rw [one_shiftLeft _ (by change self.window_bits.val - 1 < 64; omega)]
      simp only [bind_tc_ok]
      simp only [UScalar.lt_equiv, UScalar.ofNatCore_val_eq, show (1#usize).val = 1 from rfl]
      rw [if_neg hn]
      simp only [bind_tc_ok, lift]
      rw [usize_add_ok self.bit self.window_bits (by omega)]
      rfl
    · simp [← huv, hn]
    · rw [cast_usize_val v (by change u.val + self.carry.val < 2 ^ 32; omega)]
      omega
    · rw [cast_usize_val v (by change u.val + self.carry.val < 2 ^ 32; omega)]
      simp only [digitValue, Bool.false_eq_true, if_false, show (0#u64).val = 0 from rfl,
        Nat.cast_zero, mul_zero, add_zero]
      change ((u.val + self.carry.val : ℕ) : ℤ) = _
      rw [Nat.cast_add, huv]

end LeanBlsSimd.SignedDigits
namespace LeanBlsSimd.SignedDigits
open silver_crypto_simd.bls.msm8

def digitSum (w : ℕ) : List (Usize × Bool) → ℤ
  | [] => 0
  | (m, neg) :: ds => digitValue m.val neg + (2 ^ w : ℤ) * digitSum w ds

def run : ℕ → buckets.SignedDigits → Result (List (Usize × Bool) × buckets.SignedDigits)
  | 0, self => ok ([], self)
  | n + 1, self => do
    let (digits, state) ← run n self
    let (digit, state') ← state.next_digit
    ok (digits ++ [digit], state')

theorem digitSum_append (w : ℕ) (ds : List (Usize × Bool)) (d : Usize × Bool) :
    digitSum w (ds ++ [d]) = digitSum w ds + (2 ^ w : ℤ) ^ ds.length * digitValue d.1.val d.2 := by
  induction ds with
  | nil => simp [digitSum]
  | cons a ds ih =>
    rcases a with ⟨m, neg⟩
    simp only [List.cons_append, digitSum, ih, List.length_cons, pow_succ]
    ring

theorem run_refines (self : buckets.SignedDigits) (n : ℕ)
    (hb : self.bit.val + self.window_bits.val * n ≤ 256)
    (hwl : 1 ≤ self.window_bits.val) (hwh : self.window_bits.val ≤ 8)
    (hc : self.carry.val ≤ 1) :
    ∃ (digits : List (Usize × Bool)) (last : buckets.SignedDigits),
      run n self = ok (digits, last) ∧ digits.length = n ∧
      last.words = self.words ∧ last.window_bits = self.window_bits ∧
      last.bit.val = self.bit.val + self.window_bits.val * n ∧ last.carry.val ≤ 1 ∧
      (∀ d ∈ digits, d.1.val ≤ 2 ^ (self.window_bits.val - 1)) ∧
      digitSum self.window_bits.val digits + (2 ^ self.window_bits.val : ℤ) ^ n * last.carry.val =
        (value self.words / 2 ^ self.bit.val % (2 ^ self.window_bits.val) ^ n : ℕ) + self.carry.val := by
  induction n with
  | zero => refine ⟨[], self, rfl, rfl, rfl, rfl, by simp, hc, by simp, ?_⟩; simp [digitSum]
  | succ n ih =>
    obtain ⟨ds, state, hr, hlen, hwords, hwidth, hbit, hcarry, hbounds, heq⟩ :=
      ih (by nlinarith)
    obtain ⟨mag, neg, last, hs, hlwords, hlwidth, hlbit, hlcarry, _, hmag, hdigit⟩ :=
      next_digit_refines state (by rw [hbit]; nlinarith)
        (hwidth.symm ▸ hwl) (hwidth.symm ▸ hwh) hcarry
    have hlastcarry : last.carry.val ≤ 1 := by rw [hlcarry]; cases neg <;> decide
    refine ⟨ds ++ [(mag, neg)], last, ?_, by simp [hlen], hlwords.trans hwords,
      hlwidth.trans hwidth, ?_, hlastcarry, ?_, ?_⟩
    · simp only [run, hr, bind_tc_ok, Function.uncurry_def, hs]
    · rw [hlbit, hbit, hwidth]
      ring
    · intro d hd
      rcases List.mem_append.mp hd with hd | hd
      · exact hbounds d hd
      · have hd' := List.mem_singleton.mp hd
        subst d
        exact hwidth ▸ hmag
    · have hquot : value state.words / 2 ^ state.bit.val =
          (value self.words / 2 ^ self.bit.val) / (2 ^ self.window_bits.val) ^ n := by
        rw [hwords, hbit, Nat.div_div_eq_div_mul, pow_add, pow_mul]
      rw [hquot, hwidth] at hdigit
      rw [digitSum_append, hlen, pow_succ]
      have hmod := Nat.mod_mul (x := value self.words / 2 ^ self.bit.val)
        (a := (2 ^ self.window_bits.val) ^ n) (b := 2 ^ self.window_bits.val)
      rw [pow_succ, hmod, Nat.cast_add, Nat.cast_mul, Nat.cast_pow, Nat.cast_pow, Nat.cast_ofNat]
      linear_combination heq + (2 ^ self.window_bits.val : ℤ) ^ n * hdigit

end LeanBlsSimd.SignedDigits
namespace LeanBlsSimd.SignedDigits
open silver_crypto_simd.bls.msm8

def initial (words : Array U64 4#usize) (width : Usize) : buckets.SignedDigits :=
  ⟨words, width, 0#usize, 0#u64⟩

theorem new_refines (words : Array U64 4#usize) (width : Usize) :
    buckets.SignedDigits.new words width = ok (initial words width) := rfl

theorem run_complete (words : Array U64 4#usize) (width : Usize)
    (hwl : 1 ≤ width.val) (hwh : width.val ≤ 8) (hn : value words < 2 ^ 127) :
    ∃ (digits : List (Usize × Bool)) (last : buckets.SignedDigits),
      run (127 / width.val + 1) (initial words width) = ok (digits, last) ∧
      digits.length = 127 / width.val + 1 ∧
      last.carry.val = 0 ∧
      (∀ d ∈ digits, d.1.val ≤ 2 ^ (width.val - 1)) ∧
      digitSum width.val digits = value words := by
  let k := 127 / width.val
  have hdiv := Nat.mod_add_div 127 width.val
  have hrem := Nat.mod_lt 127 (by omega : 0 < width.val)
  have hk : width.val * k ≤ 127 := by dsimp [k]; omega
  have hk' : 127 < width.val * (k + 1) := by dsimp [k]; nlinarith
  obtain ⟨ds, state, hr, hlen, hwords, hwidth, hbit, hcarry, _, _⟩ :=
    run_refines (initial words width) k (by change 0 + width.val * k ≤ 256; omega)
      hwl hwh (by change 0 ≤ 1; decide)
  change state.words = words at hwords
  change state.window_bits = width at hwidth
  change state.bit.val = 0 + width.val * k at hbit
  simp only [zero_add] at hbit
  obtain ⟨mag, neg, last, hs, _, _, _, hlcarry, hneg, _, _⟩ :=
    next_digit_refines state (by rw [hbit]; omega)
      (hwidth.symm ▸ hwl) (hwidth.symm ▸ hwh) hcarry
  have htop : value words / 2 ^ (width.val * k) < 2 ^ (width.val - 1) := by
    apply (Nat.div_lt_iff_lt_mul (by positivity)).mpr
    rw [← pow_add]
    apply lt_of_lt_of_le hn
    apply Nat.pow_le_pow_right (by decide)
    nlinarith [Nat.sub_add_cancel hwl]
  have hsmall : ¬2 ^ (state.window_bits.val - 1) <
      value state.words / 2 ^ state.bit.val % 2 ^ state.window_bits.val + state.carry.val := by
    rw [hwords, hwidth, hbit]
    have hm := Nat.mod_le (value words / 2 ^ (width.val * k)) (2 ^ width.val)
    omega
  have hnfalse : neg = false := by rw [hneg]; exact decide_eq_false hsmall
  have hc0 : last.carry.val = 0 := by rw [hlcarry, hnfalse]; rfl
  have hrun : run (k + 1) (initial words width) = ok (ds ++ [(mag, neg)], last) := by
    simp only [run, hr, bind_tc_ok, Function.uncurry_def, hs]
  obtain ⟨out, final, hfull, hlength, _, _, _, _, hbounds, hsum⟩ :=
    run_refines (initial words width) (k + 1)
      (by change 0 + width.val * (k + 1) ≤ 256; nlinarith) hwl hwh (by change 0 ≤ 1; decide)
  have heq : (out, final) = (ds ++ [(mag, neg)], last) := Result.ok.inj (hfull.symm.trans hrun)
  have hout : out = ds ++ [(mag, neg)] := congrArg Prod.fst heq
  have hfinal : final = last := congrArg Prod.snd heq
  rw [hout, hfinal] at hsum
  rw [hout] at hlength hbounds
  refine ⟨ds ++ [(mag, neg)], last, hrun, hlength, hc0, hbounds, ?_⟩
  change digitSum width.val (ds ++ [(mag, neg)]) + (2 ^ width.val : ℤ) ^ (k + 1) * last.carry.val =
    (value words / 2 ^ 0 % (2 ^ width.val) ^ (k + 1) : ℕ) + (0 : ℕ) at hsum
  have hbound : value words < (2 ^ width.val) ^ (k + 1) := by
    rw [← pow_mul]
    exact lt_of_lt_of_le hn (Nat.pow_le_pow_right (by decide) (by omega))
  simpa only [hc0, Nat.cast_zero, mul_zero, add_zero, pow_zero, Nat.div_one,
    Nat.mod_eq_of_lt hbound] using hsum

end LeanBlsSimd.SignedDigits
