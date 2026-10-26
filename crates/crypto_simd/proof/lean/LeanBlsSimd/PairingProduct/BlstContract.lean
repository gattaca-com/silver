import LeanBlsSimd.Kzg.Representation
import LeanBlsSimd.Spec.PairingProduct

open Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd.bls

namespace LeanBlsSimd.PairingProduct

def specPairs (pairs : Slice pairing_product.AffinePair) : _root_.Array (G1 × G2) :=
  (pairs.val.map fun pair => (Kzg.g1ReadAffine pair.p, Kzg.g2ReadAffine pair.q)).toArray

/-- The raw blst multi-Miller call receives finite canonical subgroup inputs. -/
structure BlstMatchesSpec [PairingExternals] : Prop where
  check : ∀ pairs, (∀ pair ∈ pairs.val, Kzg.G1AffineValid pair.p ∧ Kzg.G2AffineValid pair.q) →
    (∀ pair ∈ pairs.val, (Kzg.g1ReadAffine pair.p).isInfinity = false ∧
      (Kzg.g2ReadAffine pair.q).isInfinity = false) →
    PairingExternals.check pairs = pairingCheck (specPairs pairs)

theorem blst_is_one_eq_spec [PairingExternals] (h : BlstMatchesSpec)
    (inputs : pairing_product.PairingInputs)
    (valid : ∀ pair ∈ inputs.pairs.val, Kzg.G1AffineValid pair.p ∧ Kzg.G2AffineValid pair.q)
    (finite : ∀ pair ∈ inputs.pairs.val, (Kzg.g1ReadAffine pair.p).isInfinity = false ∧
      (Kzg.g2ReadAffine pair.q).isInfinity = false) :
    pairing_product.PairingInputs.blst_is_one inputs = ok (pairingCheck (specPairs inputs.pairs)) := by
  exact congrArg ok (h.check inputs.pairs valid finite)

end LeanBlsSimd.PairingProduct
