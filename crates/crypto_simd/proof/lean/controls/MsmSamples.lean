import controls.ContractSamples
import LeanBlsSimd.Kzg.PortableMsmContract

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd LeanBlsSimd.Kzg
open LeanBlsSimd.Controls.ContractSamples

namespace LeanBlsSimd.Controls.MsmSamples

def samePoint (a b : G1) : Bool :=
  a.isInfinity == b.isInfinity && a.toAffine == b.toAffine

#eval
  letI : RuntimeFeatures := ⟨false,false,false⟩
  (do
    let .ok initial := portable.msm.Msm.Insts.CoreDefaultDefault.default
      | throw (IO.userError "portable MSM default failed")
    let mut state := initial
    let cases := [([G1.generator], [1]), ([G1.generator,G1.generator], [2,3]),
      ([G1.generator,G1.zero,G1.mul G1.generator 7], [5,9,Fr.modulus-1]),
      ([G1.generator,G1.generator], [1,Fr.modulus-1]), ([],[])]
    for (ps,ks) in cases do
      check "MSM fixture alignment" (ps.length == ks.length)
      check "MSM fixture scalars" (ks.all (fun k => decide (k < Fr.modulus)))
      let .ok (point,next) := state.msm (slice (ps.map g1Affine))
          (slice (ks.map (words 4#usize)))
        | throw (IO.userError "portable MSM failed")
      state := next
      let want := G1.msm (ps.map (fun p => g1ReadAffine (g1Affine p))).toArray
        (ks.map Fr.ofNat).toArray
      check "portable MSM group sum" (samePoint (g1ReadJacobian point) want)
    let .ok (wrong,_) := state.msm (slice [g1Affine G1.generator]) (slice [words 4#usize 2])
      | throw (IO.userError "MSM mutation failed before comparison")
    check "wrong MSM weight accepted" (!(samePoint (g1ReadJacobian wrong) G1.generator))
    IO.println "generated portable MSM: reused-scratch samples and negative control passed"
    : IO Unit)

end LeanBlsSimd.Controls.MsmSamples
