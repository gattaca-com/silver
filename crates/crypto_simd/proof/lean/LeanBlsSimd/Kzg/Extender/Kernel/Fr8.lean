import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Arithmetic
import LeanBlsSimd.Refines.Fp8
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Bytes
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8BytesDecode
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8BytesEncode

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
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

theorem multiplier_refinement [e : KzgExternals] (hblst : BlstCorrect e) (w : Fr) :
    fr8.multiplier (frEncode w) = ok (frEncode (w * Fr.ofNat 16)) ∧
      limbs (frEncode (w * Fr.ofNat 16)).l.val = (w.val * 2 ^ 260) % Fr.modulus := by
  refine ⟨?_, encoded_multiplier_limbs w⟩
  have hs : fr8.SCALE = ok 16#u64 := by
    unfold fr8.SCALE
    rw [fr8.LIMBS, fr8.LIMB_BITS]
    have hc : UScalar.cast .U32 5#usize = 5#u32 := by
      apply UScalar.eq_of_val_eq
      simp
    rw [hc]
    rfl
  simp [fr8.multiplier, hs, blst_ops.fr_from_u64, blst_ops.fr_mul,
    hblst.fr_u64, hblst.fr_mul]

theorem load_multiplier_refinement (input : Slice blst.blst_fr) (offset : Usize)
    (values : Fin 8 → Fr) (hsize : offset.val + 8 ≤ input.val.length)
    (hvalues : ∀ lane, input.val[offset.val + lane.val]! = frEncode (values lane * Fr.ofNat 16)) :
    ∃ out, fr8.Fr8.load input offset = ok out ∧ MultiplierRep out values := by
  obtain ⟨out, hout, hn, hv⟩ := load_refinement input offset hsize
  have hl : ∀ lane, laneNat out lane = (values lane |>.val) * 2 ^ 260 % Fr.modulus := by
    intro lane
    rw [hv, hvalues, encoded_multiplier_limbs]
  refine ⟨out, hout, ⟨⟨hn, ?_⟩, ?_⟩⟩
  · intro lane
    rw [hl]
    have := Nat.mod_lt ((values lane).val * 2 ^ 260) Fr.modulus_pos
    omega
  · intro lane
    apply Fin.ext
    change (laneNat out lane) % Fr.modulus =
      ((values lane).val * (2^260 % Fr.modulus)) % Fr.modulus
    rw [hl, Nat.mod_mod, Nat.mul_mod, Nat.mod_eq_of_lt (values lane).isLt]

theorem permute_refinement (a b : fr8.Fr8) (index : M512) :
    ∃ out, fr8.Fr8.permute a index b = ok out ∧
      (∀ (j : Fin 5) (lane : Fin 8),
        (out.val[j.val]!)[lane] =
          if index[lane].toNat.testBit 3 then
            (b.val[j.val]!)[index[lane].toNat % 8]
          else (a.val[j.val]!)[index[lane].toNat % 8]) ∧
      (Bounded a → Bounded b → Bounded out) := by
  let out := toArray (n := 5#usize) id (BytePacking.permute (ofArray id a) (ofArray id b) index)
  have hp (j : Fin 5) (lane : Fin 8) :
      (out.val[j.val]!)[lane] = if index[lane].toNat.testBit 3 then
        (b.val[j.val]!)[index[lane].toNat % 8] else
        (a.val[j.val]!)[index[lane].toNat % 8] := by
    simp [out, BytePacking.permute, _mm512_permutex2var_epi64]
  refine ⟨out, BytePacking.permute_refines a b index, hp, ?_⟩
  intro ha hb
  refine ⟨?_, ?_⟩
  · intro j lane
    rw [hp]
    split
    · exact hb.1 j ⟨index[lane].toNat % 8, Nat.mod_lt _ (by decide)⟩
    · exact ha.1 j ⟨index[lane].toNat % 8, Nat.mod_lt _ (by decide)⟩
  · intro lane
    let source : Fin 8 := ⟨index[lane].toNat % 8, Nat.mod_lt _ (by decide)⟩
    have hval : laneNat out lane = if index[lane].toNat.testBit 3 then
        laneNat b source else laneNat a source := by
      unfold laneNat
      simp_rw [hp]
      cases index[lane].toNat.testBit 3 <;> rfl
    rw [hval]
    split
    · exact hb.2 source
    · exact ha.2 source

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
