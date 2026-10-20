import LeanBlsSimd.Kzg.Extender.Kernel.Basic
import LeanBlsSimd.Refines.Fr8Lazy

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel
open FrModel

def modulusMultiple (c : Nat) : fr8.Fr8 :=
  FrModel.toFr8 ⟨.ofFn fun j =>
    FrModel.Simd.splat (.ofNat ((c * Fr.modulus / 2 ^ (52 * j.val)) % 2 ^ 52))⟩

private def offsetStep (c : Nat) (m : Vector M512 FrModel.LIMBS × Nat) (j : Fin FrModel.LIMBS) :=
  let n := (FrModel.Limbs.ofList FrModel.P)[j].toNat * c + m.2
  (m.1.set j (FrModel.Simd.splat (UInt64.ofNat n &&& .ofNat FrModel.MASK52)), n / 2^52)

private def offsetModel (c : Nat) : fr8.Fr8 :=
  toArray id (((List.finRange FrModel.LIMBS).foldl (offsetStep c)
    (Vector.replicate FrModel.LIMBS FrModel.Simd.zero, 0)).1)

private theorem offset_bounds (c carry : Nat) (j : Fin FrModel.LIMBS) (hc : c ≤ 35)
    (hcarry : carry ≤ 35) :
    (FrModel.Limbs.ofList FrModel.P)[j].toNat * c + carry < 36 * 2^52 := by
  have hp := FrModel.normal_ofList_P j
  have hm := Nat.mul_le_mul (show (FrModel.Limbs.ofList FrModel.P)[j].toNat ≤ 2^52-1 by omega) hc
  omega

private theorem u64_ofNatCore (n : Nat) (hn : n < 2^64) :
    UScalar.ofNatCore (ty := .U64) n hn = toU64 (UInt64.ofNat n) := by
  apply UScalar.eq_of_val_eq
  simp only [UScalar.ofNatCore_val_eq, val_toU64, UInt64.toNat_ofNat']
  omega

private theorem shift_ofNat52 (n : Nat) (hn : n < 2^64) :
    (toU64 (UInt64.ofNat n)) >>> 52#u32 = ok (toU64 (.ofNat (n / 2^52))) := by
  rw [shiftRight_ok _ _ (by decide)]
  apply congrArg Result.ok
  apply UScalar.eq_of_val_eq
  simp [UScalar.val, BitVec.toNat_ushiftRight, Nat.shiftRight_eq_div_pow]
  omega

private theorem offset_loop_refines (c : U64) (hc : c.val ≤ 35) :
    fr8.Fr8.multiple_of_r c = ok (offsetModel c.val) := by
  unfold fr8.Fr8.multiple_of_r fr8.Fr8.multiple_of_r_loop
  have hc' : c ≤ 35#u64 := by scalar_tac
  simp only [massert, hc', if_true, bind_tc_ok, FrModel.Simd.zero_refines,
    FrModel.LIMBS_refines]
  have hbind {α : Type} (x : Result α) : (x >>= ok) = x := by cases x <;> rfl
  simp only [hbind]
  rw [repeat_eq_toArray_id FrModel.Simd.zero (show (5#usize).val = FrModel.LIMBS from rfl)]
  let enc := fun m : Vector M512 FrModel.LIMBS × Nat => (toArray (n := 5#usize) id m.1,
    toU64 (UInt64.ofNat m.2))
  have hi : ∀ m (j : Fin FrModel.LIMBS), m.2 ≤ 35 → (offsetStep c.val m j).2 ≤ 35 := by
    intro m j hm
    have := offset_bounds c.val m.2 j hc hm
    simp only [offsetStep]
    omega
  change loop _ _ = ok (toArray id (((List.finRange FrModel.LIMBS).drop 0).foldl
    (offsetStep c.val) (Vector.replicate FrModel.LIMBS FrModel.Simd.zero, 0)).1)
  refine loop_range_inv (n := FrModel.LIMBS) _ 5#usize rfl enc (offsetStep c.val)
    (fun m => toArray (n := 5#usize) id m.1) (fun _ m => m.2 ≤ 35) hi ?_ ?_
    0#usize (Vector.replicate FrModel.LIMBS FrModel.Simd.zero, 0) (by decide) (by decide)
  · intro r m hr hs hm hnext
    simp_body fr8.Fr8.multiple_of_r_loop.body hnext
    rfl
  · intro r r' m j hr hs hr' hs' hm hnext
    have hj : r.start.val < (5#usize).val := by rw [hs]; exact j.isLt
    have hn := offset_bounds c.val m.2 j hc hm
    have hp := FrModel.normal_ofList_P j
    have hm64 : m.2 < 2^64 := by omega
    simp_body fr8.Fr8.multiple_of_r_loop.body hnext
    simp only [enc, FrModel.P_refines]
    rw [index_usize_toArray _ _ _ _ (show r.start.val < FrModel.LIMBS from hj)]
    simp only [bind_tc_ok, hs]
    have hpMul : (toU64 (FrModel.Limbs.ofList FrModel.P)[j.val]).val * c.val < 2^64 := by
      change (FrModel.Limbs.ofList FrModel.P)[j].toNat * c.val < 2^64
      omega
    rw [mul_ok _ _ hpMul]
    simp only [bind_tc_ok]
    rw [add_ok _ _ (by
      simp only [UScalar.ofNatCore_val_eq, val_toU64, UInt64.toNat_ofNat',
        Nat.mod_eq_of_lt hm64]
      exact (hn.trans (by norm_num)))]
    simp only [bind_tc_ok, FrModel.MASK52_refines, FrModel.Simd.splat_refines,
      fr8.LIMB_BITS]
    simp only [lift, bind_tc_ok, UScalar.ofNatCore_val_eq, val_toU64,
      UInt64.toNat_ofNat', Nat.mod_eq_of_lt hm64]
    rw [update_eq _ _ _ hj]
    simp only [bind_tc_ok]
    simp only [u64_ofNatCore]
    rw [shift_ofNat52 _ (by exact hn.trans (by norm_num))]
    simp only [bind_tc_ok]
    refine congrArg (fun st => ok (cont (r', st))) (Prod.ext ?_ ?_)
    · apply Subtype.ext
      simp [offsetStep, hs, List.map_set, Vector.toList_set]
    · rfl

theorem multiple_of_r_nat_refinement (c : Nat) (hc : c ≤ 35) :
    fr8.Fr8.multiple_of_r (UScalar.ofNatCore (ty := .U64) c (by scalar_tac)) =
        ok (modulusMultiple c) ∧
      Normalized (modulusMultiple c) ∧
      ∀ lane, laneNat (modulusMultiple c) lane = c * Fr.modulus := by
  rw [offset_loop_refines _ (by simpa only [UScalar.ofNatCore_val_eq] using hc)]
  simp only [UScalar.ofNatCore_val_eq]
  interval_cases c <;> constructor
  all_goals first | rfl | (constructor <;> (try unfold Normalized) <;> decide +kernel)

theorem multiple_of_r_refinement (c : U64) (hc : c.val ≤ 35) :
    ∃ out, fr8.Fr8.multiple_of_r c = ok out ∧ Normalized out ∧
      ∀ lane, laneNat out lane = c.val * Fr.modulus := by
  have h := multiple_of_r_nat_refinement c.val hc
  have he : UScalar.ofNatCore (ty := .U64) c.val (by scalar_tac) = c := by
    apply UScalar.eq_of_val_eq
    rfl
  rw [he] at h
  exact ⟨modulusMultiple c.val, h⟩

end LeanBlsSimd.Kzg.Extender.Kernel
