import LeanBlsSimd.Msm8.Batch

namespace LeanBlsSimd.Portable.Msm.Batch
open BatchedRefines

abbrev ChainField := BatchedRefines.ChainField

def chainKey (i : ℕ) : Fin 4 := ⟨i%4, Nat.mod_lt _ (by decide)⟩

def chainPrefix (values : ℕ → ChainField) (i : ℕ) : ChainField :=
  chainValues values (i+1) (chainKey i)

theorem previous_prefix (values : ℕ → ChainField) (i : ℕ) :
    (if i < 4 then 1 else chainPrefix values (i-4)) = chainValues values i (chainKey i) := by
  have h := chainValues_previous values i
  change chainValues values i (chainKey i) = _ at h
  rw [h]
  by_cases hi : i < 4
  · simp [hi]
  · have hcount : i-4+1 = i-3 := by omega
    have hkey : chainKey (i-4) = chainKey i := by apply Fin.ext; simp only [chainKey]; omega
    simp only [hi,if_false,chainPrefix,hcount,hkey]
    rfl

theorem recovered_inverse (values : ℕ → ChainField) (i : ℕ)
    (h : ∀ j < i+1, values j ≠ 0) :
    (chainValues values (i+1) (chainKey i))⁻¹ *
      (if i < 4 then 1 else chainPrefix values (i-4)) = (values i)⁻¹ := by
  have ha := chainValues_nonzero values i (fun j hj => h j (by omega)) (chainKey i)
  simp only [chainKey] at ha
  rw [previous_prefix]
  simp only [chainValues,chainKey,Function.update_self,mul_inv_rev,mul_assoc,
    inv_mul_cancel₀ ha,mul_one]

theorem advanced_inverse (values : ℕ → ChainField) (i : ℕ)
    (h : ∀ j < i+1, values j ≠ 0) :
    (chainValues values (i+1) (chainKey i))⁻¹ * values i = (chainValues values i (chainKey i))⁻¹ := by
  have ha := chainValues_nonzero values i (fun j hj => h j (by omega)) (chainKey i)
  have hb := h i (by omega)
  simp only [chainValues,chainKey,Function.update_self]
  field_simp [ha,hb]

end LeanBlsSimd.Portable.Msm.Batch
