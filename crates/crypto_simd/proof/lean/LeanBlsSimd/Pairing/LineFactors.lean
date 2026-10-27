import LeanBlsSimd.Pairing.FixedTableMeaning
import LeanBlsSimd.Spec.Line

open Aeneas.Std
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing

abbrev Factors := Fin 2 → Fin 3 → Fp

def factorLine (step : Fin 68) (pair : Fin 2) (v : Factors) : Fp12 :=
  Portable.Fp12.line (Fp2.ofFp (v pair 0))
    (coefficient step pair 0 * Fp2.ofFp (v pair 1))
    (coefficient step pair 1 * Fp2.ofFp (v pair 2))

def pairApply (step : Fin 68) (v : Factors) (present : Array Bool 2#usize)
    (pair : Fin 2) (f : Fp12) : Fp12 :=
  if present.val[pair.val]'(by simp; omega) then f * factorLine step pair v else f

end LeanBlsSimd.Pairing
