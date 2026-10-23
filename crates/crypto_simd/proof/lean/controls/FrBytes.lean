import LeanBlsSimd.Kzg.Fr.ByteEncode

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg
open EthLib.Cryptography Bls
open LeanBlsSimd LeanBlsSimd.Word64 LeanBlsSimd.FrScalar

namespace LeanBlsSimd.Controls.FrBytes

set_option maxRecDepth 4000

def modulusBytes : Array U8 32#usize :=
  Array.make 32#usize [0x73#u8, 0xed#u8, 0xa7#u8, 0x53#u8, 0x29#u8, 0x9d#u8, 0x7d#u8, 0x48#u8, 0x33#u8, 0x39#u8, 0xd8#u8, 0x08#u8, 0x09#u8, 0xa1#u8, 0xd8#u8, 0x05#u8, 0x53#u8, 0xbd#u8, 0xa4#u8, 0x02#u8, 0xff#u8, 0xfe#u8, 0x5b#u8, 0xfe#u8, 0xff#u8, 0xff#u8, 0xff#u8, 0xff#u8, 0x00#u8, 0x00#u8, 0x00#u8, 0x01#u8] (by rfl)

theorem modulus_rejected : fr.fr_from_bytes modulusBytes = ok none := by
  rw [fr_from_bytes_refines]
  rfl

theorem accepting_modulus_rejected (x : blst.blst_fr) :
    fr.fr_from_bytes modulusBytes ≠ ok (some x) := by
  rw [modulus_rejected]
  intro h
  cases h

def oneBytes : Array U8 32#usize :=
  Array.make 32#usize (List.replicate 31 0#u8 ++ [1#u8]) (by decide)

theorem wrong_byte_order_rejected :
    fr.words_from_be_bytes oneBytes ≠ ok (LeanBlsSimd.Kzg.words 4#usize (2^248)) := by
  intro h
  have heq := Result.ok.inj ((words_from_be_bytes_refines oneBytes).symm.trans h)
  have hv := readWords_value oneBytes
  rw [heq,ordinary_words_value (2^248) (by decide)] at hv
  have hone : Fr.bytesBEToNat (LeanBlsSimd.Kzg.arrayBytes oneBytes) = 1 := by decide +kernel
  rw [hone] at hv
  norm_num at hv

theorem maximal_digest_reduced :
    fr.fr_from_bytes_reduced (Array.repeat 32#usize 255#u8) =
      ok (LeanBlsSimd.Kzg.frEncode (Fr.ofNat (2^256-1))) := by
  rw [fr_from_bytes_reduced_refines]
  have hn : Fr.bytesBEToNat (LeanBlsSimd.Kzg.arrayBytes (Array.repeat 32#usize 255#u8)) = 2^256-1 := by
    decide +kernel
  rw [hn]

def littleEndianOneBytes : Array U8 32#usize :=
  Array.make 32#usize (1#u8 :: List.replicate 31 0#u8) (by decide)

theorem little_endian_serialization_rejected :
    fr.fr_to_bytes (LeanBlsSimd.Kzg.frEncode (Fr.ofNat 1)) ≠ ok littleEndianOneBytes := by
  intro h
  obtain ⟨result, hresult, hbytes⟩ := fr_to_bytes_refines (Fr.ofNat 1)
  have heq := Result.ok.inj (hresult.symm.trans h)
  rw [heq] at hbytes
  exact (by decide +kernel : LeanBlsSimd.Kzg.arrayBytes littleEndianOneBytes ≠
    EthLib.Cryptography.Kzg.blsFieldToBytes (Fr.ofNat 1)) hbytes

end LeanBlsSimd.Controls.FrBytes
