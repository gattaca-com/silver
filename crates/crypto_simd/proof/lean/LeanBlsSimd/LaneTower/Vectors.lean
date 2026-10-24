import LeanBlsSimd.LaneTower.Upper

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

set_option maxRecDepth 4096

abbrev V (α : Type) := Fin 8 → α
abbrev F := ZMod Fp.modulus

def Raw (k : V ℕ) (m : ℕ) (x : fp8.Fp8) (a : V F) : Prop :=
  ∀ l, Fp8.UpperRep (k l) m (ofFp8 x) l (a l)

def Normal (k : V ℕ) (x : fp8.Fp8) (a : V F) : Prop :=
  ∀ l, Fp8.CappedRep (k l) (ofFp8 x) l (a l)

def offset (c : ℕ) (x : fp8.Fp8) : Prop := ∀ l, Fp8.Offset c (ofFp8 x) l

def select {α : Type} (mask : U8) (a b : V α) : V α :=
  fun l => if (ofU8 mask).toNat.testBit l then b l else a l

def index (is : Array I64 8#usize) (l : Fin 8) : ℕ :=
  (ofArray (fun i => Int64.ofBitVec i.bv) is)[l].toUInt64.toNat

def shuffle {α : Type} (is : Array I64 8#usize) (a b : V α) : V α :=
  fun l => if (index is l).testBit 3 then b ⟨index is l % 8, Nat.mod_lt _ (by decide)⟩
    else a ⟨index is l % 8, Nat.mod_lt _ (by decide)⟩

theorem Normal.raw {k : V ℕ} {x : fp8.Fp8} {a : V F} (h : Normal k x a) : Raw k 1 x a :=
  fun l => (h l).upper

theorem raw_zero : ∃ out, fp8.Fp8.zero = ok out ∧ Normal (fun _ => 0) out (fun _ => 0) := by
  refine ⟨toFp8 Fp8.zero, Fp8.zero_refines, ?_⟩
  simpa only [Normal, ofFp8_toFp8] using Fp8.capped_zero

theorem raw_one : ∃ out, fp8.Fp8.one = ok out ∧ Normal (fun _ => 2) out (fun _ => 1) := by
  refine ⟨toFp8 Fp8.one, Fp8.one_refines, ?_⟩
  intro l
  simpa only [ofFp8_toFp8] using (Fp8.holds_one l).capped

theorem raw_offset (c : U64) (hc : c.val < 4096) :
    ∃ out, fp8.Fp8.multiple_of_p c = ok out ∧ offset c.val out := by
  refine ⟨toFp8 (Fp8.multiple_of_p (ofU64 c)), Fp8.multiple_of_p_refines c hc, ?_⟩
  intro l
  obtain ⟨hn, hv⟩ := Fp8.multiple_of_p_spec (ofU64 c) hc l
  exact ⟨by simpa only [ofFp8_toFp8] using hn, by simpa only [ofFp8_toFp8] using hv⟩

variable {k k' : V ℕ} {m m' : ℕ} {x y : fp8.Fp8} {a b : V F}

theorem raw_add (hx : Raw k m x a) (hy : Raw k' m' y b) (hm : m + m' ≤ 1024) :
    ∃ out, fp8.Fp8.add_raw x y = ok out ∧
      Raw (fun l => k l + k' l) (m + m') out (fun l => a l + b l) := by
  refine ⟨toFp8 ((ofFp8 x).add_raw (ofFp8 y)), Fp8.add_raw_refines x y, ?_⟩
  intro l
  simpa only [ofFp8_toFp8] using (hx l).add_raw (hy l) hm

theorem raw_sub {c : ℕ} {o : fp8.Fp8} (hx : Raw k m x a) (hy : Raw k' m' y b)
    (ho : offset c o) (hc : ∀ l, k' l ≤ c) (hm : m + m' + 1 ≤ 1024) :
    ∃ out, fp8.Fp8.sub_raw x y o = ok out ∧
      Raw (fun l => k l + c) (m + m' + 1) out (fun l => a l - b l) := by
  refine ⟨toFp8 ((ofFp8 x).sub_raw (ofFp8 y) (ofFp8 o)), Fp8.sub_raw_refines x y o, ?_⟩
  intro l
  simpa only [ofFp8_toFp8] using (hx l).sub_raw (hy l) (ho l) (hc l) hm

theorem raw_normalise (hx : Raw k m x a) (hk : ∀ l, k l ≤ 5120) (hm : m ≤ 1024) :
    ∃ out, fp8.Fp8.normalise x = ok out ∧ Normal k out a := by
  refine ⟨toFp8 (ofFp8 x).normalise, Fp8.normalise_refines x, ?_⟩
  intro l
  have hc : k l * Fp.modulus < R :=
    (Nat.mul_le_mul_right _ (hk l)).trans_lt (by decide +kernel)
  simpa only [ofFp8_toFp8] using (hx l).normalise hc hm

theorem raw_mul (hx : Normal k x a) (hy : Normal k' y b)
    (hk : ∀ l, k l * k' l ≤ 80 * 256 ^ 2) :
    ∃ out, fp8.Fp8.mul x y = ok out ∧ Normal (fun _ => 2) out (fun l => a l * b l) := by
  refine ⟨toFp8 ((ofFp8 x).mul (ofFp8 y)), Fp8.mul_refines x y, ?_⟩
  intro l
  have hc := (Nat.mul_le_mul_right Fp.modulus (hk l)).trans_lt product_capacity
  simpa only [ofFp8_toFp8] using ((hx l).mul (hy l) hc).capped

theorem raw_select (mask : U8) (hx : Raw k m x a) (hy : Raw k' m' y b) :
    ∃ out, fp8.Fp8.select mask x y = ok out ∧
      Raw (select mask k k') (max m m') out (select mask a b) := by
  refine ⟨toFp8 (Fp8.select (ofU8 mask) (ofFp8 x) (ofFp8 y)), Fp8.select_refines mask x y, ?_⟩
  intro l
  simp only [ofFp8_toFp8, select]
  split_ifs with h
  · exact ((hy l).mono le_rfl (le_max_right _ _)).of_lane_eq (by
      simpa only [Fp8.lane_select, ofU8] using if_pos (by simpa only [ofU8] using h))
  · exact ((hx l).mono le_rfl (le_max_left _ _)).of_lane_eq (by
      simpa only [Fp8.lane_select, ofU8] using if_neg (by simpa only [ofU8] using h))

theorem raw_permute2 (is : Array I64 8#usize) (hx : Raw k m x a) (hy : Raw k' m' y b) :
    ∃ out, fp8.Fp8.permute2 x y is = ok out ∧
      Raw (shuffle is k k') (max m m') out (shuffle is a b) := by
  refine ⟨_, Fp8.permute2_refines x y is, ?_⟩
  intro l
  simp only [ofFp8_toFp8, shuffle]
  split_ifs with h
  · exact ((hy _).mono le_rfl (le_max_right _ _)).of_lane_eq
      (by simp_all [Fp8.lane_permute2, index])
  · exact ((hx _).mono le_rfl (le_max_left _ _)).of_lane_eq
      (by simp_all [Fp8.lane_permute2, index])

theorem normal_permute2 (is : Array I64 8#usize) (hx : Normal k x a) (hy : Normal k' y b) :
    ∃ out, fp8.Fp8.permute2 x y is = ok out ∧
      Normal (shuffle is k k') out (shuffle is a b) := by
  refine ⟨_, Fp8.permute2_refines x y is, ?_⟩
  intro l
  simp only [ofFp8_toFp8, shuffle]
  split_ifs with h
  · exact (hy _).of_lane_eq (by simp_all [Fp8.lane_permute2, index])
  · exact (hx _).of_lane_eq (by simp_all [Fp8.lane_permute2, index])

end LeanBlsSimd.LaneTower
