import LeanBlsSimd.Kzg
import LeanBlsSimd.Kzg.SpecExternals

open Aeneas.Std Result silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls LeanBlsSimd.Kzg

theorem LeanBlsSimd.Kzg.specInstance :
    ∃ initial, @verify.CellBatchVerifier.new specExternals = ok initial ∧ StateInvariant initial ∧
      ∀ (v : verify.CellBatchVerifier), StateInvariant v →
      ∀ (i : Input), i.Representable →
      ∃ (verdict : Bool) (next : verify.CellBatchVerifier),
        @Input.generated specExternals i v = ok (verdict, next) ∧ StateInvariant next ∧
        Model.rejectErrors i.embeddedSpec = verdict :=
  @verify_eq_spec specExternals specExternals_correct.1 specExternals_correct.2.1

#print axioms LeanBlsSimd.Kzg.specInstance
