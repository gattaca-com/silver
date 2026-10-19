import LeanBlsSimd.Kzg.Extender.Basic

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg

namespace LeanBlsSimd.Kzg.Extender

theorem blob_bytes_size (blob : Blob) : (arrayBytes blob).size = 131072 := by
  simp [arrayBytes, bytes, ByteArray.size, blob.property]

theorem blob_chunk_size (blob : Blob) (i : Nat) (hi : i < 4096) :
    ((arrayBytes blob).extract (i * 32) ((i + 1) * 32)).size = 32 := by
  simp only [ByteArray.size_extract, blob_bytes_size]
  omega

theorem field_decode_exists_iff (b : ByteArray) (hs : b.size = 32) :
    (∃ f, bytesToBlsField b = .ok f) ↔ Fr.bytesBEToNat b < Fr.modulus := by
  by_cases h : Fr.bytesBEToNat b < Fr.modulus <;>
    simp [bytesToBlsField, Constants.BYTES_PER_FIELD_ELEMENT, Fr.fromBytesBE, hs, h]

theorem blob_aux_exists_iff (blob : ByteArray) (start count : Nat) :
    (∃ fs, blobToPolynomialAux blob start count = .ok fs) ↔
      ∀ i, start ≤ i → i < start + count →
        ∃ f, bytesToBlsField (blob.extract (i * 32) ((i + 1) * 32)) = .ok f := by
  induction count generalizing start with
  | zero =>
    simp only [blobToPolynomialAux, Except.ok.injEq, exists_eq', true_iff, Nat.add_zero]
    intro i hlo hhi
    omega
  | succ count ih =>
    constructor
    · rintro ⟨fs, hfs⟩ i hlo hhi
      cases hd : bytesToBlsField (blob.extract (start * 32) ((start + 1) * 32)) with
      | error err => simp [blobToPolynomialAux, Constants.BYTES_PER_FIELD_ELEMENT, hd] at hfs
      | ok f =>
        by_cases he : i = start
        · exact ⟨f, by simpa [he] using hd⟩
        · cases ht : blobToPolynomialAux blob (start + 1) count with
          | error err =>
            simp [blobToPolynomialAux, Constants.BYTES_PER_FIELD_ELEMENT, hd, ht] at hfs
          | ok rest =>
            exact (ih (start + 1)).mp ⟨rest, ht⟩ i (by omega) (by omega)
    · intro h
      obtain ⟨f, hf⟩ := h start (by omega) (by omega)
      obtain ⟨fs, hfs⟩ := (ih (start + 1)).mpr (by
        intro i hlo hhi
        exact h i (by omega) (by omega))
      exact ⟨f :: fs, by
        simp [blobToPolynomialAux, Constants.BYTES_PER_FIELD_ELEMENT, hf, hfs]⟩

theorem blob_decode_exists_iff (blob : Blob) :
    (∃ values, blobToPolynomial (arrayBytes blob) = .ok values) ↔ Canonical blob := by
  have hsize : (arrayBytes blob).size = Constants.BYTES_PER_BLOB := blob_bytes_size blob
  have hdecode : (∃ values, blobToPolynomial (arrayBytes blob) = .ok values) ↔
      ∃ fs, blobToPolynomialAux (arrayBytes blob) 0 4096 = .ok fs := by
    cases h : blobToPolynomialAux (arrayBytes blob) 0 4096 <;>
      simp [blobToPolynomial, hsize, Constants.FIELD_ELEMENTS_PER_BLOB, h]
  rw [hdecode, blob_aux_exists_iff]
  constructor
  · intro h i
    exact (field_decode_exists_iff _ (blob_chunk_size blob i.val i.isLt)).mp
      (h i.val (Nat.zero_le _) i.isLt)
  · intro h i _ hi
    exact (field_decode_exists_iff _ (blob_chunk_size blob i hi)).mpr (h ⟨i, hi⟩)

theorem model_acceptance (blob : Blob) :
    (Model.extend (arrayBytes blob)).isOk = true ↔ Canonical blob := by
  rw [← blob_decode_exists_iff]
  cases h : blobToPolynomial (arrayBytes blob) <;>
    simp [Model.extend, h, Except.isOk, Except.toBool]

theorem cellBytes_injective : Function.Injective cellBytes := by
  intro a b h
  apply Subtype.ext
  apply List.ext_getElem (by simp [a.property, b.property])
  intro i hi hj
  have hab : arrayBytes a.val[i] = arrayBytes b.val[i] := by
    have hx := congrArg (fun xs : _root_.Array Cell => xs[i]!) h
    simpa [cellBytes, List.getElem?_eq_getElem hi, List.getElem?_eq_getElem hj] using hx
  apply Subtype.ext
  have hx := congrArg (fun bs : ByteArray =>
    bs.data.toList.map (fun x : UInt8 => (⟨x.toBitVec⟩ : U8))) hab
  simpa [arrayBytes, bytes, List.map_map, Function.comp_def] using hx

end LeanBlsSimd.Kzg.Extender
