import LeanBlsSimd.Kzg.Fr.Arithmetic
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Arithmetic
import LeanBlsSimd.Refines.Fp8
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Bytes
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Transpose
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8BytesDecode
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8BytesEncode

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

set_option exponentiation.threshold 1000
set_option maxRecDepth 4000
set_option maxHeartbeats 2000000

theorem encoded_multiplier_limbs (w : Fr) :
    limbs (frEncode (w * Fr.ofNat 16)).l.val = (w.val * 2 ^ 260) % Fr.modulus := by
  unfold frEncode
  rw [limbs_words_four _ (Nat.lt_trans (Nat.mod_lt _ Fr.modulus_pos) (by decide))]
  change (((w.val * (16 % Fr.modulus)) % Fr.modulus) * 2^256) % Fr.modulus = _
  rw [show 16 % Fr.modulus = 16 by decide, Nat.mod_mul_mod]
  exact congrArg (fun n => n % Fr.modulus) (by ring)

theorem zero_refinement :
    ∃ out, fr8.Fr8.zero = ok out ∧ Represents out (fun _ => 0) := by
  refine ⟨Array.repeat 5#usize Simd.zero, rfl, ?_⟩
  have hlimb (j : Fin 5) (lane : Fin 8) :
      ((Array.repeat 5#usize Simd.zero).val[j.val]!)[lane].toNat = 0 := by
    fin_cases j <;> simp [Array.repeat, Simd.zero, _mm512_setzero_si512]
  have hz : ∀ lane, laneNat (Array.repeat 5#usize Simd.zero) lane = 0 := by
    intro lane
    rw [laneNat]
    simp_rw [hlimb]
    simp
  refine ⟨⟨?_, fun lane => by rw [hz]; exact Nat.mul_pos (by decide) Fr.modulus_pos⟩, ?_⟩
  · intro j lane
    rw [hlimb]
    decide
  · intro lane
    simp [laneValue, hz, Fr.ofNat]

theorem load_refinement (input : Slice blst.blst_fr) (offset : Usize)
    (hsize : offset.val + 8 ≤ input.val.length) :
    ∃ out, fr8.Fr8.load input offset = ok out ∧ Normalized out ∧
      ∀ lane, laneNat out lane = limbs input.val[offset.val + lane.val]!.l.val := by
  refine ⟨toArray id (BytePacking.transpose (BytePacking.loadedLanes input offset)),
    BytePacking.load_refines input offset hsize, ?_, ?_⟩
  · intro j lane
    rw [BytePacking.get_limb_toArray]
    simp only [BytePacking.transpose, BytePacking.loadedLanes, Fin.getElem_fin, Vector.getElem_ofFn]
    exact (BytePacking.unpack_spec (ofArray ofU64 input.val[offset.val + lane.val]!.l)).1 j
  · intro lane
    rw [BytePacking.laneNat_transpose]
    simp only [BytePacking.loadedLanes, Fin.getElem_fin, Vector.getElem_ofFn]
    rw [(BytePacking.unpack_spec _).2, BytePacking.limbs_ofArray]

theorem multiplier_refinement (w : Fr) :
    fr8.multiplier (frEncode w) = ok (frEncode (w * Fr.ofNat 16)) ∧
      limbs (frEncode (w * Fr.ofNat 16)).l.val = (w.val * 2 ^ 260) % Fr.modulus := by
  refine ⟨?_, encoded_multiplier_limbs w⟩
  rw [fr8.multiplier, fr8_scale_eq]
  exact FrScalar.fr_mul_refines _ _

theorem load_multiplier_refinement (input : Slice blst.blst_fr) (offset : Usize)
    (values : Fin 8 → Fr) (hsize : offset.val + 8 ≤ input.val.length)
    (hvalues : ∀ lane, input.val[offset.val + lane.val]! = frEncode (values lane * Fr.ofNat 16)) :
    ∃ out, fr8.Fr8.load input offset = ok out ∧ MultiplierRep out values := by
  obtain ⟨out, hout, hn, hv⟩ := load_refinement input offset hsize
  have hl : ∀ lane, laneNat out lane = (values lane |>.val) * 2 ^ 260 % Fr.modulus := by
    intro lane
    rw [hv, hvalues, encoded_multiplier_limbs]
  refine ⟨out, hout, ⟨⟨⟨hn, ?_⟩, ?_⟩, ?_⟩⟩
  · intro lane
    rw [hl]
    have := Nat.mod_lt ((values lane).val * 2 ^ 260) Fr.modulus_pos
    omega
  · intro lane
    apply Fin.ext
    change (laneNat out lane) % Fr.modulus =
      ((values lane).val * (2^260 % Fr.modulus)) % Fr.modulus
    rw [hl, Nat.mod_mod, Nat.mul_mod, Nat.mod_eq_of_lt (values lane).isLt]
  · intro lane
    rw [hl]
    exact Nat.mod_lt _ Fr.modulus_pos

theorem transpose_refinement (data : Slice fr8.Fr8) (offset : Usize)
    (hsize : offset.val + 8 ≤ data.val.length) :
    ∃ out, fr8.Fr8.transpose data offset = ok out ∧
      ∀ (row lane : Fin 8) (j : Fin 5),
        ((out.val[row.val]!).val[j.val]!)[lane] =
          ((data.val[offset.val + lane.val]!).val[j.val]!)[row] := by
  refine ⟨toArray (toArray id) (TransposePacking.store (TransposePacking.columns data offset)),
    TransposePacking.transpose_refines data offset hsize, ?_⟩
  intro row lane j
  simp only [getElem!_pos, toArray_val, List.length_map, Vector.length_toList,
    row.isLt, j.isLt, List.getElem_map, Vector.getElem_toList, id_eq]
  have h := TransposePacking.getElem_store (TransposePacking.columns data offset) row j
  simp only [Fin.getElem_fin] at h
  refine (congrArg (fun v : M512 => v[lane]) h).trans ?_
  simp only [TransposePacking.columns, LeanBlsSimd.transpose8, Fin.getElem_fin,
    Vector.getElem_ofFn]

theorem from_bytes_refinement (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 256 ≤ input.val.length) :
    ∃ out mask, fr8.Fr8.from_bytes input offset = ok (out, mask) ∧ Normalized out ∧
      (∀ lane : Fin 8,
        laneNat out lane = Fr.bytesBEToNat
          ((bytes input.val).extract (offset.val + 32 * lane.val) (offset.val + 32 * (lane.val + 1))) ∧
        (mask.val.testBit lane.val = true ↔ laneNat out lane < Fr.modulus)) ∧
      (mask = 255#u8 ↔ ∀ lane, laneNat out lane < Fr.modulus) := by
  exact BytePacking.decoded_bytes_refinement input offset hsize

theorem to_bytes_refinement (a : fr8.Fr8) (ha : Bounded a) (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 256 ≤ input.val.length) :
    ∃ out, fr8.Fr8.to_bytes a input offset = ok out ∧ out.val.length = input.val.length ∧
      (∀ lane : Fin 8,
        (bytes out.val).extract (offset.val + 32 * lane.val) (offset.val + 32 * (lane.val + 1)) =
          blsFieldToBytes (laneValue a lane)) ∧
      (∀ i : Fin input.val.length, i.val < offset.val ∨ offset.val + 256 ≤ i.val →
        out.val[i.val]? = input.val[i.val]?) := by
  exact BytePacking.encoded_bytes_refinement a ha input offset hsize

end LeanBlsSimd.Kzg.Extender.Kernel
