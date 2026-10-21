import LeanBlsSimd.Refines.Fr8Core
import LeanBlsSimd.Model.SignedLimbs

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.FrModel

def Fr8.normalise (a : Fr8) : Fr8 :=
  Fr8.ofLanes (.ofFn fun lane => SignedLimbs.normalise (a.lane lane))

theorem Fr8.normalise_refines (a : fr8.Fr8) :
    fr8.Fr8.normalise a = ok (toFr8 (ofFr8 a).normalise) := by
  unfold fr8.Fr8.normalise fr8.Fr8.normalise_loop
  simp only [MASK52_refines, Simd.splat_refines, bind_tc_ok, LIMBS_refines,
    ofU64_toU64]
  have hsub : 5#usize - 1#usize = ok 4#usize := by
    change UScalar.sub _ _ = _
    simp [UScalar.sub]
    apply UScalar.eq_of_val_eq
    exact usize_ofNat_val 4 (by decide)
  rw [hsub]
  simp only [bind_tc_ok, bind_return]
  simpa only [toFr8, Fr8.normalise, Fr8.limbs_ofLanes_ofFn, Fr8.lane_eq, limbs_ofFr8]
    using SignedLimbs.normalise_loop_refines (n := 5#usize) 4#usize rfl (by decide) a

def Fr8.addRaw (a b : Fr8) : Fr8 :=
  ⟨.ofFn fun j => _mm512_add_epi64 a.limbs[j] b.limbs[j]⟩

def Fr8.subRaw (a b offset : Fr8) : Fr8 :=
  ⟨.ofFn fun j => _mm512_sub_epi64
    (_mm512_add_epi64 a.limbs[j] offset.limbs[j]) b.limbs[j]⟩

theorem Fr8.add_raw_refines (a b : fr8.Fr8) :
    fr8.Fr8.add_raw a b = ok (toFr8 ((ofFr8 a).addRaw (ofFr8 b))) := by
  unfold fr8.Fr8.add_raw fr8.Fr8.add_raw_loop
  simp only [Simd.zero_refines, bind_tc_ok, LIMBS_refines, bind_return]
  simpa only [Fr8.addRaw, toFr8, ofFr8] using SignedLimbs.add_raw_loop_refines a b

theorem Fr8.sub_raw_refines (a b offset : fr8.Fr8) :
    fr8.Fr8.sub_raw a b offset =
      ok (toFr8 ((ofFr8 a).subRaw (ofFr8 b) (ofFr8 offset))) := by
  unfold fr8.Fr8.sub_raw fr8.Fr8.sub_raw_loop
  simp only [Simd.zero_refines, bind_tc_ok, LIMBS_refines, bind_return]
  simpa only [Fr8.subRaw, toFr8, ofFr8] using SignedLimbs.sub_raw_loop_refines a b offset

end LeanBlsSimd.FrModel
