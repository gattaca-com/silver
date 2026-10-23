import controls.ContractSamples
import LeanBlsSimd.Kzg.PairingContract

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd LeanBlsSimd.Kzg
open LeanBlsSimd.Controls.ContractSamples

namespace LeanBlsSimd.Controls.PairingSamples

def toPortable (p : G1) : portable.g1.G1 :=
  let j := g1Jacobian p
  { x := j.x.l, y := j.y.l, z := j.z.l }

def hexBytes (s : String) : ByteArray := Id.run do
  let digits := s.toList.toArray
  let digit (c : Char) : Nat := if c ≤ '9' then c.toNat - '0'.toNat else c.toNat - 'a'.toNat + 10
  let mut out := ByteArray.empty
  for i in [:digits.size / 2] do
    out := out.push (UInt8.ofNat (16 * digit digits[2*i]! + digit digits[2*i+1]!))
  return out

#eval
  letI : RuntimeFeatures := ⟨false,false,false⟩
  (do
    let .ok lines := portable.pairing.PairingLines.new kzg.pairing_lines.PAIRING_LINES
      | throw (IO.userError "portable pairing table failed")
    -- The setup relation supplies a nonzero true case without knowing the trapdoor.
    let .ok s64 := G1.uncompress (hexBytes Kzg.TrustedSetupData.g1MonomialHex[64]!)
      | throw (IO.userError "setup G1 point 64 failed to decode")
    check "positive pairing fixture is infinity" (!s64.isInfinity && !G1.generator.isInfinity)
    for (p,q,want) in [(G1.zero,G1.zero,true), (G1.generator,G1.generator,false),
        (G1.generator,G1.zero,false), (G1.generator,s64,true), (G1.generator,G1.neg s64,false)] do
      check "pairing fixture subgroup" (p.inSubgroup && q.inSubgroup)
      let spec := Bls.pairingCheck #[(p,SetupPoints.g2Point64),(q,G2.neg SetupPoints.g2Point0)]
      check "pairing fixture expected verdict" (spec == want)
      let .ok got := portable.pairing.PairingLines.pairing_check lines
          (Array.make 2#usize [toPortable p,toPortable q] (by rfl))
        | throw (IO.userError "generated portable pairing failed")
      check "portable pairing verdict" (got == spec)
    IO.println "generated portable pairing: nonzero true, false and sign-mutation samples passed"
    : IO Unit)

end LeanBlsSimd.Controls.PairingSamples
