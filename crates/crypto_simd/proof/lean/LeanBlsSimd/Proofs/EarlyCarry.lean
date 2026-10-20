import LeanBlsSimd.Proofs.Limbs

namespace LeanBlsSimd.Lane

theorem carry_of_cleared_eq (t p pinv : UInt64)
    (hinv : (lo52 pinv * lo52 p + 1) % 2 ^ 52 = 0) :
    srli 52 (madd52lo t p (madd52lo 0 t pinv)) =
      srli 52 (t + UInt64.ofNat (2 ^ 52 - 1)) := by
  let q := madd52lo 0 t pinv
  have hq : q.toNat = lo52 t * lo52 pinv % 2 ^ 52 := by
    simp [q, madd52lo, UInt64.toNat_ofNat']
    omega
  have hqlt : q.toNat < 2 ^ 52 := by
    rw [hq]
    exact Nat.mod_lt _ (by norm_num)
  have hmod : (t.toNat + lo52 p * lo52 q) % 2 ^ 52 = 0 := by
    apply Nat.mod_eq_zero_of_dvd
    rw [← ZMod.natCast_eq_zero_iff]
    have h1 : ((lo52 pinv * lo52 p + 1 : ℕ) : ZMod (2 ^ 52)) = 0 :=
      (ZMod.natCast_eq_zero_iff _ _).mpr (Nat.dvd_of_mod_eq_zero hinv)
    rw [lo52_of_lt hqlt, hq]
    unfold lo52 at h1 ⊢
    push_cast [ZMod.natCast_mod] at h1 ⊢
    linear_combination (t.toNat : ZMod (2 ^ 52)) * h1
  have hsmall : lo52 p * lo52 q % 2 ^ 52 < 2 ^ 52 :=
    Nat.mod_lt _ (by norm_num)
  have hsum : (t.toNat % 2 ^ 52 + lo52 p * lo52 q % 2 ^ 52) % 2 ^ 52 = 0 := by
    simpa only [Nat.add_mod, Nat.mod_mod] using hmod
  apply UInt64.toNat_inj.mp
  rw [toNat_srli52, toNat_srli52]
  change (t + UInt64.ofNat (lo52 p * lo52 q % 2 ^ 52)).toNat / 2 ^ 52 = _
  rw [UInt64.toNat_add, UInt64.toNat_add, UInt64.toNat_ofNat', UInt64.toNat_ofNat']
  have ht := t.toNat_lt_size
  simp only [UInt64.size] at ht ⊢
  omega

end LeanBlsSimd.Lane
