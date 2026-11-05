import LeanBlsSimd.Kzg.Model
import EthLib.Cryptography.Proofs.Kzg.CoefficientPolynomial
import Mathlib.LinearAlgebra.Lagrange

open EthLib.Cryptography Bls Kzg Kzg.BitReversal
open scoped EthLib.Cryptography.Bls.Fr

namespace LeanBlsSimd.Kzg

noncomputable def cellInterpolant (c : Nat) :=
  Lagrange.interpolate Finset.univ (fun j : Fin 64 => (rootsOfUnityBrp 8192)[64*c+j.val]!)

def cellIfft (c : Nat) (values : Array Fr) : Array Fr :=
  shiftVals (fftField (bitReversalPermutation values) (computeRootsOfUnity 64) true)
    (Model.cosetShift c).inverse

end LeanBlsSimd.Kzg
