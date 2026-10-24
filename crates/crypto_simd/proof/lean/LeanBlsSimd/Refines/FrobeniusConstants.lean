import LeanBlsSimd.Spec.Cyclotomic.Constants
import LeanBlsSimd.Extracted.Funs

namespace LeanBlsSimd.FrobeniusConstants

open Aeneas.Std silver_crypto_simd Cyclotomic.Bls

set_option maxRecDepth 4096
set_option maxHeartbeats 2000000
set_option exponentiation.threshold 4096

def words (j : Fin 6) : Nat × Nat :=
  powBy mulFp2 (1,0) 762 (1,1) (j.val*((p-1)/6))

theorem words_spec (j : Fin 6) :
    toFp2 (QuadraticAlgebra.omega : K) (words j) = xi^(j.val*((p-1)/6)) := by
  apply xi_power
  have hj := j.isLt
  have h : 5*((p-1)/6) < 2^762 := by decide +kernel
  exact lt_of_le_of_lt (Nat.mul_le_mul_right _ (by omega : j.val ≤ 5)) h

def limbValue (bits : Nat) {n : Usize} (a : Aeneas.Std.Array U64 n) : Nat :=
  a.val.foldr (fun w acc => w.val + 2^bits*acc) 0

def portableRow (j : Fin 6) (i : Fin 2) : portable.fp.Fp :=
  portable.constants.FROBENIUS[j.val]!.val[i.val]!

def laneRow (j : Fin 6) (i : Fin 2) : Aeneas.Std.Array U64 8#usize :=
  bls.constants.FROBENIUS_MONT[j.val]!.val[i.val]!

/-- Both generated tables encode the same ordinary coefficient in their respective radices. -/
theorem table_certificates (j : Fin 6) :
    limbValue 64 (portableRow j 0) = (words j).1 * 2^384 % p ∧
    limbValue 64 (portableRow j 1) = (words j).2 * 2^384 % p ∧
    limbValue 52 (laneRow j 0) = (words j).1 * 2^416 % p ∧
    limbValue 52 (laneRow j 1) = (words j).2 * 2^416 % p := by
  fin_cases j <;> decide +kernel

theorem table_bounds (j : Fin 6) (i : Fin 2) :
    limbValue 64 (portableRow j i) < p ∧ limbValue 52 (laneRow j i) < p ∧
    ∀ w ∈ (laneRow j i).val, w.val < 2^52 := by
  fin_cases j <;> fin_cases i <;> decide +kernel

end LeanBlsSimd.FrobeniusConstants
