import LeanBlsSimd.Kzg.Extender.Kernel.Basic
import LeanBlsSimd.Proofs.SignedLimbs

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthCryptographySpecs.Bls.Fr

namespace LeanBlsSimd.Kzg.Extender.Kernel

theorem laneInt_eq_laneNat {x : fr8.Fr8} (hx : Normalized x) (lane : Fin 8) :
    laneInt x lane = (laneNat x lane : ℤ) := by
  unfold laneInt laneNat
  rw [Fin.sum_univ_def]
  push_cast
  simp only [List.map_map]
  apply congrArg List.sum
  apply List.map_congr_left
  intro j _
  rw [SignedLimbs.limb_eq_nat (by have := hx j lane; omega)]
  simp

theorem lazyLaneValue_eq_laneValue {x : fr8.Fr8} (hx : Normalized x) (lane : Fin 8) :
    lazyLaneValue x lane = laneValue x lane := by
  simp [lazyLaneValue, laneValue, laneInt_eq_laneNat hx, Fr.ofNat_eq_natCast]

theorem Lazy.mono {k m k' m' : Nat} {x : fr8.Fr8} (h : Lazy k m x)
    (hk : k ≤ k') (hm : m ≤ m') : Lazy k' m' x := by
  intro lane
  obtain ⟨hn, hv, hl⟩ := h lane
  refine ⟨hn, lt_of_lt_of_le hv ?_, fun j => lt_of_lt_of_le (hl j) ?_⟩
  · exact mul_le_mul_of_nonneg_right (by exact_mod_cast hk) (by positivity)
  · exact mul_le_mul_of_nonneg_right (by exact_mod_cast hm) (by positivity)

theorem LazyRep.mono {k m k' m' : Nat} {x : fr8.Fr8} {values : Fin 8 → Fr}
    (h : LazyRep k m x values) (hk : k ≤ k') (hm : m ≤ m') :
    LazyRep k' m' x values := ⟨h.1.mono hk hm, h.2⟩

theorem Represents.lazy {x : fr8.Fr8} {values : Fin 8 → Fr}
    (h : Represents x values) : LazyRep 2 1 x values := by
  refine ⟨fun lane => ⟨?_, ?_, fun j => ?_⟩, fun lane => ?_⟩
  · rw [laneInt_eq_laneNat h.1.1]; positivity
  · rw [laneInt_eq_laneNat h.1.1]
    exact_mod_cast h.1.2 lane
  · rw [SignedLimbs.limb_eq_nat (by have := h.1.1 j lane; omega),
      abs_of_nonneg (by positivity)]
    simpa using (show ((x.val[j.val]!)[lane].toNat : ℤ) < 2 ^ 52 by
      exact_mod_cast h.1.1 j lane)
  · rw [lazyLaneValue_eq_laneValue h.1.1]
    exact h.2 lane

theorem DataRep.lazy {data : Slice fr8.Fr8} {values : _root_.Array Fr}
    (h : DataRep data values) : LazyDataRep 2 1 data values :=
  ⟨h.1, fun v => (h.2 v).lazy⟩

theorem LazyDataRep.mono {k m k' m' : Nat}
    {data : Slice fr8.Fr8} {values : _root_.Array Fr}
    (h : LazyDataRep k m data values) (hk : k ≤ k') (hm : m ≤ m') :
    LazyDataRep k' m' data values :=
  ⟨h.1, fun v => (h.2 v).mono hk hm⟩

theorem lazy_value_below_radix {k m : Nat} {x : fr8.Fr8}
    (h : Lazy k m x) (hk : k ≤ 35) (lane : Fin 8) :
    laneInt x lane < (2 : ℤ) ^ 260 := by
  have hr : (35 : ℤ) * Fr.modulus < (2 : ℤ) ^ 260 := by decide +kernel
  have hk' : (k : ℤ) ≤ 35 := by exact_mod_cast hk
  have hprod : (k : ℤ) * Fr.modulus ≤ (35 : ℤ) * Fr.modulus :=
    mul_le_mul_of_nonneg_right hk' (by positivity)
  exact lt_trans (lt_of_lt_of_le (h lane).2.1 hprod) hr

end LeanBlsSimd.Kzg.Extender.Kernel
