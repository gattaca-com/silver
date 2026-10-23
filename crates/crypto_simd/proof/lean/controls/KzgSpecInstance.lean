import LeanBlsSimd.Kzg
import LeanBlsSimd.Kzg.SpecExternals

open Aeneas.Std Result silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls LeanBlsSimd.Kzg

/-- A conditional consumer of all actual generated-operation contracts.
The independent spec-model witness is `specExternals_correct`. -/
theorem LeanBlsSimd.Kzg.specInstance [cpu : RuntimeFeatures]
    (hfr : FrCorrect) (hbytes : FrBytesCorrect) (hsha : ShaCorrect)
    (hfp : PortableFpCorrect) (hg1 : LeanBlsSimd.G1DecoderCorrect)
    (hmsm : PortableMsmCorrect) (hpairing : PairingCorrect) :
    ∃ initial, verify.CellBatchVerifier.new = ok initial ∧ StateInvariant initial ∧
      ∀ (v : verify.CellBatchVerifier), StateInvariant v →
      ∀ (i : Input), i.Representable →
      ∃ (verdict : Bool) (next : verify.CellBatchVerifier),
        Input.generated i v = ok (verdict, next) ∧ StateInvariant next ∧
        Model.rejectErrors i.embeddedSpec = verdict :=
  verify_eq_spec hfr hbytes hsha hfp hg1 hmsm hpairing

#print axioms LeanBlsSimd.Kzg.specInstance
