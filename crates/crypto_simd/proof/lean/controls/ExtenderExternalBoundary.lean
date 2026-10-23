import LeanBlsSimd.Kzg.ScalarContracts

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Controls

/-- A pure serialization fixture; this is not an implementation dictionary. -/
def serializationBytes (x : Fr) : Aeneas.Std.Array U8 32#usize :=
  ⟨x.toBytesBE.data.toList.map (fun b => ⟨b.toBitVec⟩), by simp [Fr.toBytesBE]⟩

def SerializationLaw (serialize : Fr → Result (Aeneas.Std.Array U8 32#usize)) : Prop :=
  ∀ x, ∃ result, serialize x = ok result ∧ arrayBytes result = blsFieldToBytes x

def eraseSerialization (_ : Fr) : Result (Aeneas.Std.Array U8 32#usize) :=
  ok (serializationBytes 0)

theorem eraseSerialization_zero_output (x : Fr) :
    eraseSerialization x = ok (serializationBytes 0) := rfl

theorem eraseSerialization_rejected : ¬ SerializationLaw eraseSerialization := by
  intro h
  obtain ⟨result, hserialize, hbytes⟩ := h 1
  have hresult : serializationBytes 0 = result := Result.ok.inj hserialize
  rw [← hresult] at hbytes
  exact (by decide +kernel : arrayBytes (serializationBytes 0) ≠ blsFieldToBytes 1) hbytes

def failSerialization (_ : Fr) : Result (Aeneas.Std.Array U8 32#usize) := fail .panic

theorem failSerialization_is_failure (x : Fr) :
    failSerialization x = fail Error.panic := rfl

theorem failSerialization_rejected : ¬ SerializationLaw failSerialization := by
  intro h
  obtain ⟨result, hserialize, _⟩ := h 0
  change fail Error.panic = ok result at hserialize
  cases hserialize

end LeanBlsSimd.Kzg.Extender.Controls

#print axioms LeanBlsSimd.Kzg.Extender.Controls.eraseSerialization_zero_output
#print axioms LeanBlsSimd.Kzg.Extender.Controls.eraseSerialization_rejected
#print axioms LeanBlsSimd.Kzg.Extender.Controls.failSerialization_is_failure
#print axioms LeanBlsSimd.Kzg.Extender.Controls.failSerialization_rejected
