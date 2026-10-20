import LeanBlsSimd.Kzg.Extender.Kernel.Basic

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

def pairFirst (half n : Nat) : Nat := n / half * (2 * half) + n % half

def pairNumber (half v : Nat) : Nat := v / (2 * half) * half + v % half

theorem pairFirst_eq (half n : Nat) (hhalf : 0 < half) :
    pairFirst half n = 2 * n - n % half := by
  have hd := Nat.div_add_mod n half
  have hr := Nat.mod_lt n hhalf
  unfold pairFirst
  have he : n / half * (2 * half) = 2 * (half * (n / half)) := by ring
  rw [he]
  omega

theorem pairFirst_div (half n : Nat) (hhalf : 0 < half) :
    pairFirst half n / (2 * half) = n / half := by
  have hr : n % half < 2 * half := lt_of_lt_of_le (Nat.mod_lt n hhalf) (by omega)
  simp only [pairFirst, Nat.mul_comm (n / half), Nat.mul_add_div (by omega : 0 < 2 * half),
    Nat.div_eq_of_lt hr, Nat.add_zero]

theorem pairFirst_mod (half n : Nat) (hhalf : 0 < half) :
    pairFirst half n % (2 * half) = n % half := by
  have hr : n % half < 2 * half := lt_of_lt_of_le (Nat.mod_lt n hhalf) (by omega)
  simp only [pairFirst, Nat.mul_comm (n / half), Nat.mul_add_mod, Nat.mod_eq_of_lt hr]

theorem pairSecond_div (half n : Nat) (hhalf : 0 < half) :
    (pairFirst half n + half) / (2 * half) = n / half := by
  have hr : n % half + half < 2 * half := by have := Nat.mod_lt n hhalf; omega
  simp only [pairFirst, Nat.add_assoc, Nat.mul_comm (n / half),
    Nat.mul_add_div (by omega : 0 < 2 * half), Nat.div_eq_of_lt hr, Nat.add_zero]

theorem pairSecond_mod (half n : Nat) (hhalf : 0 < half) :
    (pairFirst half n + half) % (2 * half) = n % half + half := by
  have hr : n % half + half < 2 * half := by have := Nat.mod_lt n hhalf; omega
  simp only [pairFirst, Nat.add_assoc, Nat.mul_comm (n / half), Nat.mul_add_mod,
    Nat.mod_eq_of_lt hr]

theorem pairNumber_first (half n : Nat) (hhalf : 0 < half) :
    pairNumber half (pairFirst half n) = n := by
  have hm : pairFirst half n % half = n % half := by
    rw [← Nat.mod_mul_left_mod (pairFirst half n) 2 half, pairFirst_mod half n hhalf,
      Nat.mod_mod]
  simp only [pairNumber, pairFirst_div half n hhalf, hm]
  simpa only [Nat.mul_comm] using Nat.div_add_mod n half

theorem pairNumber_second (half n : Nat) (hhalf : 0 < half) :
    pairNumber half (pairFirst half n + half) = n := by
  have hm : (pairFirst half n + half) % half = n % half := by
    rw [← Nat.mod_mul_left_mod (pairFirst half n + half) 2 half,
      pairSecond_mod half n hhalf, Nat.add_mod_right, Nat.mod_mod]
  simp only [pairNumber, pairSecond_div half n hhalf, hm]
  simpa only [Nat.mul_comm] using Nat.div_add_mod n half

theorem pairFirst_lower (half n : Nat) (hhalf : 0 < half) :
    pairFirst half n % (2 * half) < half := by
  rw [pairFirst_mod half n hhalf]
  exact Nat.mod_lt n hhalf

theorem pairSecond_upper (half n : Nat) (hhalf : 0 < half) :
    half ≤ (pairFirst half n + half) % (2 * half) := by
  rw [pairSecond_mod half n hhalf]
  omega

theorem pairFirst_pairNumber (half v : Nat) (hhalf : 0 < half) :
    pairFirst half (pairNumber half v) = v / (2 * half) * (2 * half) + v % half := by
  have hr := Nat.mod_lt v hhalf
  simp only [pairNumber, pairFirst, Nat.mul_comm (v / (2 * half)),
    Nat.mul_add_div hhalf, Nat.div_eq_of_lt hr, Nat.add_zero, Nat.mul_add_mod, Nat.mod_mod]

theorem pair_partition_lower (half v : Nat) (hhalf : 0 < half)
    (hlo : v % (2 * half) < half) : v = pairFirst half (pairNumber half v) := by
  rw [pairFirst_pairNumber half v hhalf]
  have hm : v % half = v % (2 * half) := by
    rw [← Nat.mod_mul_left_mod v 2 half, Nat.mod_eq_of_lt hlo]
  rw [hm]
  simpa only [Nat.mul_comm] using (Nat.div_add_mod v (2 * half)).symm

theorem pair_partition_upper (half v : Nat) (hhalf : 0 < half)
    (hhi : half ≤ v % (2 * half)) : v = pairFirst half (pairNumber half v) + half := by
  rw [pairFirst_pairNumber half v hhalf]
  have hr := Nat.mod_lt v (by omega : 0 < 2 * half)
  have hm : v % half + half = v % (2 * half) := by
    rw [← Nat.mod_mul_left_mod v 2 half, Nat.mod_eq_sub_mod hhi,
      Nat.mod_eq_of_lt (by omega : v % (2 * half) - half < half)]
    omega
  have hd := Nat.div_add_mod v (2 * half)
  rw [Nat.mul_comm (2 * half)] at hd
  omega

theorem pair_partition (half v : Nat) (hhalf : 0 < half) :
    v = pairFirst half (pairNumber half v) ∨
    v = pairFirst half (pairNumber half v) + half := by
  by_cases hlo : v % (2 * half) < half
  · exact Or.inl (pair_partition_lower half v hhalf hlo)
  · exact Or.inr (pair_partition_upper half v hhalf (by omega))

theorem pairs_disjoint (half n m : Nat) (hhalf : 0 < half) (hne : n ≠ m) :
    pairFirst half n ≠ pairFirst half m ∧
    pairFirst half n ≠ pairFirst half m + half ∧
    pairFirst half n + half ≠ pairFirst half m ∧
    pairFirst half n + half ≠ pairFirst half m + half := by
  have hf := pairNumber_first half n hhalf
  have hs := pairNumber_second half n hhalf
  have hfm := pairNumber_first half m hhalf
  have hsm := pairNumber_second half m hhalf
  constructor
  · intro h; apply hne; simpa only [hf, hfm] using congrArg (pairNumber half) h
  constructor
  · intro h; apply hne; simpa only [hf, hsm] using congrArg (pairNumber half) h
  constructor
  · intro h; apply hne; simpa only [hs, hfm] using congrArg (pairNumber half) h
  · intro h; apply hne; simpa only [hs, hsm] using congrArg (pairNumber half) h

theorem pairFirst_add_half_lt (half n N : Nat) (hhalf : 0 < half)
    (hdiv : 2 * half ∣ N) (hn : n < N / 2) : pairFirst half n + half < N := by
  obtain ⟨k, rfl⟩ := hdiv
  have hN : 2 * half * k / 2 = half * k := by
    rw [Nat.mul_assoc, Nat.mul_div_cancel_left _ (by decide : 0 < 2)]
  rw [hN] at hn
  have hq : n / half < k := (Nat.div_lt_iff_lt_mul hhalf).mpr (by simpa [Nat.mul_comm] using hn)
  have hr := Nat.mod_lt n hhalf
  unfold pairFirst
  nlinarith

theorem pairNumber_lt (half v N : Nat) (hhalf : 0 < half)
    (hdiv : 2 * half ∣ N) (hv : v < N) : pairNumber half v < N / 2 := by
  obtain ⟨k, rfl⟩ := hdiv
  have hN : 2 * half * k / 2 = half * k := by
    rw [Nat.mul_assoc, Nat.mul_div_cancel_left _ (by decide : 0 < 2)]
  rw [hN]
  have hq : v / (2 * half) < k :=
    (Nat.div_lt_iff_lt_mul (by omega : 0 < 2 * half)).mpr (by simpa [Nat.mul_comm] using hv)
  have hr := Nat.mod_lt v hhalf
  unfold pairNumber
  nlinarith

theorem twiddle_mask_val (n mask : Usize) (half stage : Nat)
    (hhalf : half = 2 ^ stage) (hmask : mask.val = half - 1) :
    (n &&& mask).val = n.val % half := by
  rw [UScalar.val_and, hmask, hhalf, Nat.and_two_pow_sub_one_eq_mod]

theorem first_of_pair_refinement (n half : Usize) (stage : Nat)
    (hhalf : half.val = 2 ^ stage) (hn : n.val < 512) :
    ∃ i, fft8.first_of_pair n half = ok i ∧ i.val = pairFirst half.val n.val := by
  have hp : 0 < half.val := by rw [hhalf]; exact Nat.two_pow_pos stage
  obtain ⟨twice, htwice, htwiceval⟩ := WP.spec_imp_exists
    (Usize.mul_spec (x := 2#usize) (y := n) (by scalar_tac))
  simp only [UScalar.ofNatCore_val_eq] at htwiceval
  obtain ⟨mask, hmask, hmaskval, _⟩ := WP.spec_imp_exists
    (Usize.sub_spec (x := half) (y := 1#usize)
      (by simp only [UScalar.ofNatCore_val_eq]; omega))
  simp only [UScalar.ofNatCore_val_eq] at hmaskval
  have hand := twiddle_mask_val n mask half.val stage hhalf hmaskval
  obtain ⟨i, hi, hival, _⟩ := WP.spec_imp_exists
    (Usize.sub_spec (x := twice) (y := n &&& mask)
      (by rw [htwiceval, hand]; have := Nat.mod_le n.val half.val; omega))
  refine ⟨i, ?_, ?_⟩
  · simp [fft8.first_of_pair, htwice, hmask, hi, lift]
  · rw [hival, htwiceval, hand, pairFirst_eq half.val n.val hp]

end LeanBlsSimd.Kzg.Extender.Kernel
