import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Model
import LeanBlsSimd.Kzg.Extender.Kernel.Lazy
import LeanBlsSimd.Refines.Fr8Lazy

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthCryptographySpecs.Bls.Fr

namespace LeanBlsSimd.Kzg.Extender.Kernel

theorem laneInt_eq_val (x : fr8.Fr8) (lane : Fin 8) :
    laneInt x lane = SignedLimbs.val ((FrModel.ofFr8 x).lane lane) := by
  unfold laneInt SignedLimbs.val
  apply Finset.sum_congr rfl
  intro j _
  change SignedLimbs.limb (x.val[j.val]!)[lane] * (2 : ℤ) ^ (52 * j.val) =
    SignedLimbs.limb ((FrModel.ofFr8 x).lane lane)[j.val] * (2 : ℤ) ^ (52 * j.val)
  rw [getElem_lane_ofFr8]

theorem lazy_iff_model (x : fr8.Fr8) (k m : Nat) :
    Lazy k m x ↔ ∀ lane, 0 ≤ SignedLimbs.val ((FrModel.ofFr8 x).lane lane) ∧
      SignedLimbs.val ((FrModel.ofFr8 x).lane lane) < (k : ℤ) * Fr.modulus ∧
      SignedLimbs.Bounded ((FrModel.ofFr8 x).lane lane) m := by
  simp only [Lazy, laneInt_eq_val, SignedLimbs.Bounded, Fin.getElem_fin, getElem_lane_ofFr8]
  rfl

theorem normalise_lazy_refinement {k m : Nat} (a : fr8.Fr8) (values : Fin 8 → Fr)
    (ha : LazyRep k m a values) (hk : k ≤ 35) (hm : m ≤ 1024) :
    ∃ out, fr8.Fr8.normalise a = ok out ∧ Normalized out ∧
      ∀ lane, (laneNat out lane : ℤ) = laneInt a lane ∧
        laneValue out lane = values lane := by
  let out := FrModel.toFr8 (FrModel.ofFr8 a).normalise
  have ha' := (lazy_iff_model a k m).mp ha.1
  have hl lane : ∀ j : Fin 5,
      |SignedLimbs.limb ((FrModel.ofFr8 a).lane lane)[j]| < (2 : ℤ) ^ 62 := by
    intro j
    have h := (ha' lane).2.2 j
    have hm' : (m : ℤ) ≤ 1024 := by exact_mod_cast hm
    have : (m : ℤ) * 2 ^ 52 ≤ (2 : ℤ) ^ 62 := by linarith
    exact lt_of_lt_of_le h this
  have hs (lane : Fin 8) :
      SignedLimbs.val (SignedLimbs.normalise ((FrModel.ofFr8 a).lane lane)) =
        SignedLimbs.val ((FrModel.ofFr8 a).lane lane) ∧
      SignedLimbs.Normalized (SignedLimbs.normalise ((FrModel.ofFr8 a).lane lane)) :=
    SignedLimbs.normalise_spec (hl lane) (ha' lane).1
      (show SignedLimbs.val ((FrModel.ofFr8 a).lane lane) < (2 : ℤ) ^ 260 by
        rw [← laneInt_eq_val]; exact lazy_value_below_radix ha.1 hk lane)
  have he lane : (FrModel.ofFr8 out).lane lane =
      SignedLimbs.normalise ((FrModel.ofFr8 a).lane lane) := by
    simp [out, FrModel.Fr8.normalise, FrModel.Fr8.lane_ofLanes]
  have hn : Normalized out := by
    apply (normalized_iff_model out).mpr
    intro lane
    rw [he]
    exact (hs lane).2
  refine ⟨out, FrModel.Fr8.normalise_refines a, hn, fun lane => ⟨?_, ?_⟩⟩
  · rw [← laneInt_eq_laneNat hn, laneInt_eq_val, he, (hs lane).1, ← laneInt_eq_val]
  · rw [← lazyLaneValue_eq_laneValue hn]
    change (laneInt out lane : Fr) = values lane
    rw [laneInt_eq_val, he, (hs lane).1, ← laneInt_eq_val]
    exact ha.2 lane

private theorem lane_addRaw (a b : FrModel.Fr8) (lane : Fin 8) :
    (a.addRaw b).lane lane = SignedLimbs.addRaw (a.lane lane) (b.lane lane) := by
  ext j hj
  simp [FrModel.Fr8.addRaw, FrModel.Fr8.lane, SignedLimbs.addRaw,
    _mm512_add_epi64]

private theorem lane_subRaw (a b offset : FrModel.Fr8) (lane : Fin 8) :
    (a.subRaw b offset).lane lane =
      SignedLimbs.subRaw (a.lane lane) (b.lane lane) (offset.lane lane) := by
  ext j hj
  simp [FrModel.Fr8.subRaw, FrModel.Fr8.lane, SignedLimbs.subRaw,
    _mm512_add_epi64, _mm512_sub_epi64]

theorem add_raw_lazy_refinement {k m k' m' : Nat}
    (a b : fr8.Fr8) (values other : Fin 8 → Fr)
    (ha : LazyRep k m a values) (hb : LazyRep k' m' b other)
    (hm : m + m' ≤ 1024) :
    ∃ out, fr8.Fr8.add_raw a b = ok out ∧
      LazyRep (k + k') (m + m') out (fun lane => values lane + other lane) ∧
      ∀ lane, laneInt out lane = laneInt a lane + laneInt b lane := by
  let out := FrModel.toFr8 ((FrModel.ofFr8 a).addRaw (FrModel.ofFr8 b))
  have hr : ((m : ℤ) + m') * 2 ^ 52 ≤ 2 ^ 63 := by
    have hm' : (m : ℤ) + m' ≤ 1024 := by exact_mod_cast hm
    linarith
  have ha' := (lazy_iff_model a k m).mp ha.1
  have hb' := (lazy_iff_model b k' m').mp hb.1
  have hs lane := SignedLimbs.addRaw_spec (ha' lane).2.2 (hb' lane).2.2 hr
  have he lane : laneInt out lane = laneInt a lane + laneInt b lane := by
    simpa only [laneInt_eq_val, out, FrModel.ofFr8_toFr8, lane_addRaw]
      using (hs lane).1
  refine ⟨out, FrModel.Fr8.add_raw_refines a b, ⟨?_, ?_⟩, he⟩
  · apply (lazy_iff_model out (k + k') (m + m')).mpr
    intro lane
    simp only [out, FrModel.ofFr8_toFr8, lane_addRaw]
    rw [(hs lane).1]
    refine ⟨by linarith [(ha' lane).1, (hb' lane).1], ?_, ?_⟩
    · push_cast
      nlinarith [(ha' lane).2.1, (hb' lane).2.1]
    · simpa only [Nat.cast_add] using (hs lane).2
  · intro lane
    simp only [lazyLaneValue, he, Int.cast_add]
    exact congrArg₂ (· + ·) (ha.2 lane) (hb.2 lane)

theorem sub_raw_lazy_refinement {k m k' m' c : Nat}
    (a b offset : fr8.Fr8) (values other : Fin 8 → Fr)
    (ha : LazyRep k m a values) (hb : LazyRep k' m' b other)
    (ho : Normalized offset) (hov : ∀ lane, laneNat offset lane = c * Fr.modulus)
    (hc : k' ≤ c) (hm : m + m' + 1 ≤ 1024) :
    ∃ out, fr8.Fr8.sub_raw a b offset = ok out ∧
      LazyRep (k + c) (m + m' + 1) out (fun lane => values lane - other lane) ∧
      ∀ lane, laneInt out lane = laneInt a lane + (c : ℤ) * Fr.modulus - laneInt b lane := by
  let out := FrModel.toFr8 ((FrModel.ofFr8 a).subRaw (FrModel.ofFr8 b) (FrModel.ofFr8 offset))
  have hr : ((m : ℤ) + m' + 1) * 2 ^ 52 ≤ 2 ^ 63 := by
    have hm' : (m : ℤ) + m' + 1 ≤ 1024 := by exact_mod_cast hm
    linarith
  have ha' := (lazy_iff_model a k m).mp ha.1
  have hb' := (lazy_iff_model b k' m').mp hb.1
  have ho' := (normalized_iff_model offset).mp ho
  have hs lane := SignedLimbs.subRaw_spec (ha' lane).2.2 (hb' lane).2.2 (ho' lane)
    (by positivity) (by positivity) hr
  have hov' lane : laneInt offset lane = (c : ℤ) * Fr.modulus := by
    rw [laneInt_eq_laneNat ho, hov]
    push_cast
    rfl
  have he lane : laneInt out lane =
      laneInt a lane + (c : ℤ) * Fr.modulus - laneInt b lane := by
    rw [← hov' lane]
    simpa only [laneInt_eq_val, out, FrModel.ofFr8_toFr8, lane_subRaw]
      using (hs lane).1
  refine ⟨out, FrModel.Fr8.sub_raw_refines a b offset, ⟨?_, ?_⟩, he⟩
  · intro lane
    have hc' : (k' : ℤ) * Fr.modulus ≤ (c : ℤ) * Fr.modulus :=
      mul_le_mul_of_nonneg_right (by exact_mod_cast hc) (by positivity)
    refine ⟨?_, ?_, ?_⟩
    · rw [he]
      linarith [(ha.1 lane).1, (hb.1 lane).2.1]
    · rw [he]
      push_cast
      nlinarith [(ha.1 lane).2.1, (hb.1 lane).1]
    · have hbound : SignedLimbs.Bounded ((FrModel.ofFr8 out).lane lane) (m + m' + 1) := by
        simpa only [out, FrModel.ofFr8_toFr8, lane_subRaw, Nat.cast_add, Nat.cast_one]
          using (hs lane).2
      simpa only [SignedLimbs.Bounded, Fin.getElem_fin, getElem_lane_ofFr8] using hbound
  · intro lane
    simp only [lazyLaneValue, he, Int.cast_sub, Int.cast_add, Int.cast_mul,
      Int.cast_natCast]
    have hz : (Fr.modulus : Fr) = 0 := ZMod.natCast_self Fr.modulus
    rw [hz]
    change (laneInt a lane : ZMod Fr.modulus) + (c : ZMod Fr.modulus) * 0 -
      (laneInt b lane : ZMod Fr.modulus) = values lane - other lane
    simp only [mul_zero, add_zero]
    exact congrArg₂ (· - ·) (ha.2 lane) (hb.2 lane)

end LeanBlsSimd.Kzg.Extender.Kernel
