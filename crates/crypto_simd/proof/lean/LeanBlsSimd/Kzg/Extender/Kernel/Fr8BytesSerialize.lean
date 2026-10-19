import LeanBlsSimd.Kzg.Extender.Kernel.Fr8BytesDecode
import LeanBlsSimd.Kzg.ByteSerialization

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel.BytePacking

theorem bytes_eq_field (xs : List U8) (f : Fr) (hlen : xs.length = 32)
    (hval : bytesVal (xs.map ofU8) = f.val) :
    bytes xs = blsFieldToBytes f := by
  symm
  apply blsFieldToBytes_of_decode
  have hs : (bytes xs).size = 32 := by simp [bytes, ByteArray.size, hlen]
  have hv : Fr.bytesBEToNat (bytes xs) = f.val := by
    simpa [bytes] using (bytesBEToNat_eq_bytesVal (bytes xs)).trans hval
  simp only [bytesToBlsField, Constants.BYTES_PER_FIELD_ELEMENT, hs, ne_eq,
    not_true_eq_false, ↓reduceIte, Fr.fromBytesBE, hv, f.isLt, ↓reduceDIte]

theorem bytes_eq_lane (xs : List U8) (a : fr8.Fr8) (lane : Fin 8)
    (hlen : xs.length = 32) (hval : bytesVal (xs.map ofU8) = laneNat a lane % Fr.modulus) :
    bytes xs = blsFieldToBytes (laneValue a lane) :=
  bytes_eq_field xs (laneValue a lane) hlen hval

theorem extract_eq_bytes (out : Slice U8) (xs : List U8) (start width : Nat)
    (hlen : xs.length = width) (hbound : start + width ≤ out.val.length)
    (hget : ∀ i, i < width → out.val[start+i]! = xs[i]!) :
    (bytes out.val).extract start (start+width) = bytes xs := by
  have hlist : (out.val.drop start).take width = xs := by
    apply List.ext_getElem
    · simp [hlen]
      omega
    · intro i hi hj
      have hiw : i < width := by simpa [hlen] using hj
      have hio : start+i < out.val.length := by omega
      simpa [getElem!_pos out.val (start+i) hio, getElem!_pos xs i hj] using hget i hiw
  apply ByteArray.ext
  apply _root_.Array.toList_inj.mp
  simpa [bytes, ByteArray.data_extract, _root_.Array.toList_extract,
    List.extract_eq_take_drop, List.map_take, List.map_drop] using congrArg (List.map ofU8) hlist

end LeanBlsSimd.Kzg.Extender.Kernel.BytePacking
