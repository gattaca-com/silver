import LeanBlsSimd.Kzg.SpecExternals

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Controls

private theorem serialization_preserves_blst
    (serialize : blst.blst_fr → Result (Aeneas.Std.Array U8 32#usize)) :
    BlstCorrect { specExternals with frToBytes := serialize } := by
  rcases specExternals_correct.1 with
    ⟨hdecode, hbytes, hu64, hadd, hsub, hmul, hinverse, hhash,
      haffine, hpointAdd, hneg, hg2neg, hlincomb, hpairing⟩
  exact ⟨hdecode, hbytes, hu64, hadd, hsub, hmul, hinverse, hhash,
    haffine, hpointAdd, hneg, hg2neg, hlincomb, hpairing⟩

@[reducible] def eraseSerialization : KzgExternals :=
  { specExternals with frToBytes := fun _ => ok (specFrBytes 0) }

theorem eraseSerialization_blst_correct : BlstCorrect eraseSerialization :=
  serialization_preserves_blst _

theorem eraseSerialization_rejected : ¬ FrToBytesCorrect eraseSerialization := by
  intro h
  obtain ⟨result, hserialize, hbytes⟩ := h 1
  have hresult : specFrBytes 0 = result := Result.ok.inj hserialize
  rw [← hresult] at hbytes
  exact (by decide +kernel : arrayBytes (specFrBytes 0) ≠ blsFieldToBytes 1) hbytes

@[reducible] def failSerialization : KzgExternals :=
  { specExternals with frToBytes := fun _ => fail .panic }

theorem failSerialization_blst_correct : BlstCorrect failSerialization :=
  serialization_preserves_blst _

theorem failSerialization_rejected : ¬ FrToBytesCorrect failSerialization := by
  intro h
  obtain ⟨result, hserialize, _⟩ := h 0
  change fail Error.panic = ok result at hserialize
  cases hserialize

end LeanBlsSimd.Kzg.Extender.Controls

#print axioms LeanBlsSimd.Kzg.Extender.Controls.eraseSerialization_blst_correct
#print axioms LeanBlsSimd.Kzg.Extender.Controls.eraseSerialization_rejected
#print axioms LeanBlsSimd.Kzg.Extender.Controls.failSerialization_blst_correct
#print axioms LeanBlsSimd.Kzg.Extender.Controls.failSerialization_rejected
