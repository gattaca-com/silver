import LeanBlsSimd.Msm8.StoreFlat

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd

def convertedRows (n : ℕ) (point : ℕ → Limbs × Limbs) : List Limbs :=
  (List.range n).flatMap fun j => [(point j).1, (point j).2]

@[simp] theorem convertedRows_length (n : ℕ) (point : ℕ → Limbs × Limbs) :
    (convertedRows n point).length = 2 * n := by
  induction n with
  | zero => rfl
  | succ n ih =>
    simp only [convertedRows, List.range_succ, List.flatMap_append, List.flatMap_cons,
      List.flatMap_nil, List.append_nil, List.length_append, List.length_cons, List.length_nil]
    change (convertedRows n point).length + (1 + (1 + 0)) = _
    rw [ih]
    omega

end LeanBlsSimd
