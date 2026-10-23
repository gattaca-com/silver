import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Bytes

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel.BytePacking

set_option exponentiation.threshold 1000

def wordLane (w : Vector M512 4) (lane : Fin 8) : Vector UInt64 4 := laneOf w lane

def vectorPack (v : Vector M512 5) : Vector M512 4 :=
  Vector.ofFn fun k => Vector.ofFn fun lane => (pack (laneOf v lane))[k]

def fromBlocks (blocks : Vector M512 4) : Vector M512 4 :=
  Vector.ofFn fun k => Vector.ofFn fun lane =>
    blocks[(⟨lane.val / 2, by omega⟩ : Fin 4)][(⟨4 * (lane.val % 2) + 3 - k.val, by omega⟩ : Fin 8)]

def wordBlocks (w : Vector M512 4) : Vector M512 4 :=
  Vector.ofFn fun b => Vector.ofFn fun i =>
    w[(⟨3 - i.val % 4, by omega⟩ : Fin 4)][(⟨2 * b.val + i.val / 4, by omega⟩ : Fin 8)]

theorem add_shift_eq_or (a b s : UInt64) (hs : s.toNat < 64)
    (ha : a.toNat < 2^s.toNat) :
    a + (b <<< s) = a ||| (b <<< s) := by
  apply UInt64.eq_iff_toBitVec_eq.mpr
  simp only [UInt64.toBitVec_add, UInt64.toBitVec_or, UInt64.toBitVec_shiftLeft]
  apply BitVec.add_eq_or_of_and_eq_zero
  have he : (s.toBitVec % 64).toNat = s.toNat := by
    simp [BitVec.toNat_umod, Nat.mod_eq_of_lt hs]
  ext i hi
  simp only [BitVec.shiftLeft_eq', he, BitVec.getElem_and, BitVec.getElem_shiftLeft,
    BitVec.getElem_zero, Bool.and_eq_false_iff]
  by_cases his : i < s.toNat
  · right
    simp [his]
  · left
    apply Bool.eq_false_iff.mpr
    intro ht
    have hb := BitVec.two_pow_le_toNat_of_getElem_eq_true hi ht
    have hp : 2^s.toNat ≤ (2:Nat)^i := Nat.pow_le_pow_right (by decide) (by omega)
    simp only [UInt64.toNat_toBitVec] at hb
    omega

private theorem lowWords (a b : M512) :
    _mm512_permutex2var_epi64 a (_mm512_set_epi64 14 10 6 2 15 11 7 3) b =
      #v[a[3], a[7], b[3], b[7], a[2], a[6], b[2], b[6]] := by
  ext i hi
  interval_cases i <;> norm_num [_mm512_permutex2var_epi64, _mm512_set_epi64] <;> rfl

private theorem highWords (a b : M512) :
    _mm512_permutex2var_epi64 a (_mm512_set_epi64 12 8 4 0 13 9 5 1) b =
      #v[a[1], a[5], b[1], b[5], a[0], a[4], b[0], b[4]] := by
  ext i hi
  interval_cases i <;> norm_num [_mm512_permutex2var_epi64, _mm512_set_epi64] <;> rfl

private theorem firstHalves (a b : M512) :
    _mm512_permutex2var_epi64 a (_mm512_set_epi64 11 10 9 8 3 2 1 0) b =
      #v[a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]] := by
  ext i hi
  interval_cases i <;> norm_num [_mm512_permutex2var_epi64, _mm512_set_epi64] <;> rfl

private theorem secondHalves (a b : M512) :
    _mm512_permutex2var_epi64 a (_mm512_set_epi64 15 14 13 12 7 6 5 4) b =
      #v[a[4], a[5], a[6], a[7], b[4], b[5], b[6], b[7]] := by
  ext i hi
  interval_cases i <;> norm_num [_mm512_permutex2var_epi64, _mm512_set_epi64] <;> rfl

private theorem evenBlock (a b : M512) :
    _mm512_permutex2var_epi64 a (_mm512_set_epi64 1 5 9 13 0 4 8 12) b =
      #v[b[4], b[0], a[4], a[0], b[5], b[1], a[5], a[1]] := by
  ext i hi
  interval_cases i <;> norm_num [_mm512_permutex2var_epi64, _mm512_set_epi64] <;> rfl

private theorem oddBlock (a b : M512) :
    _mm512_permutex2var_epi64 a (_mm512_set_epi64 3 7 11 15 2 6 10 14) b =
      #v[b[6], b[2], a[6], a[2], b[7], b[3], a[7], a[3]] := by
  ext i hi
  interval_cases i <;> norm_num [_mm512_permutex2var_epi64, _mm512_set_epi64] <;> rfl

theorem from_blocks_refines (blocks : Vector M512 4) :
    fr8.u256x8.U256x8.from_blocks (toArray id blocks) = ok (toArray id (fromBlocks blocks)) := by
  unfold fr8.u256x8.U256x8.from_blocks
  simp [fr8.u256x8.half_selectors, bls.fp8.index_vector,
    index_usize_eq (n := 8#usize) _ 0#usize (by decide), index_usize_eq (n := 8#usize) _ 1#usize (by decide),
    index_usize_eq (n := 8#usize) _ 2#usize (by decide), index_usize_eq (n := 8#usize) _ 3#usize (by decide),
    index_usize_eq (n := 8#usize) _ 4#usize (by decide), index_usize_eq (n := 8#usize) _ 5#usize (by decide),
    index_usize_eq (n := 8#usize) _ 6#usize (by decide), index_usize_eq (n := 8#usize) _ 7#usize (by decide),
    index_usize_eq (n := 4#usize) _ 0#usize (by decide), index_usize_eq (n := 4#usize) _ 1#usize (by decide),
    index_usize_eq (n := 4#usize) _ 2#usize (by decide), index_usize_eq (n := 4#usize) _ 3#usize (by decide),
    core.core_arch.x86.avx512f._mm512_set_epi64,
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64, bind_tc_ok, Array.make, lowWords, highWords, firstHalves, secondHalves]

  apply Subtype.ext
  apply List.ext_getElem
  · simp [toArray]
  · intro k hk hk'
    have hk4 : k < 4 := by simpa using hk
    apply Vector.ext
    intro lane hl
    interval_cases k <;> interval_cases lane <;>
      simp [toArray, fromBlocks]

theorem blocks_refines (w : Vector M512 4) :
    fr8.u256x8.U256x8.blocks (toArray id w) = ok (toArray id (wordBlocks w)) := by
  unfold fr8.u256x8.U256x8.blocks
  simp [fr8.u256x8.half_selectors, bls.fp8.index_vector,
    index_usize_eq (n := 8#usize) _ 0#usize (by decide), index_usize_eq (n := 8#usize) _ 1#usize (by decide),
    index_usize_eq (n := 8#usize) _ 2#usize (by decide), index_usize_eq (n := 8#usize) _ 3#usize (by decide),
    index_usize_eq (n := 8#usize) _ 4#usize (by decide), index_usize_eq (n := 8#usize) _ 5#usize (by decide),
    index_usize_eq (n := 8#usize) _ 6#usize (by decide), index_usize_eq (n := 8#usize) _ 7#usize (by decide),
    index_usize_eq (n := 4#usize) _ 0#usize (by decide), index_usize_eq (n := 4#usize) _ 1#usize (by decide),
    index_usize_eq (n := 4#usize) _ 2#usize (by decide), index_usize_eq (n := 4#usize) _ 3#usize (by decide),
    core.core_arch.x86.avx512f._mm512_set_epi64,
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64, bind_tc_ok, Array.make, firstHalves, secondHalves, evenBlock, oddBlock]

  apply Subtype.ext
  apply List.ext_getElem
  · simp [toArray]
  · intro k hk hk'
    have hk4 : k < 4 := by simpa using hk
    apply Vector.ext
    intro lane hl
    interval_cases k <;> interval_cases lane <;>
      simp [toArray, wordBlocks]

private theorem unpack_add (x : Vector UInt64 4) :
    unpack x = #v[x[0] &&& UInt64.ofNat MASK52,
      ((x[0] >>> 52) + (x[1] <<< 12)) &&& UInt64.ofNat MASK52,
      ((x[1] >>> 40) + (x[2] <<< 24)) &&& UInt64.ofNat MASK52,
      ((x[2] >>> 28) + (x[3] <<< 36)) &&& UInt64.ofNat MASK52,
      x[3] >>> 16] := by
  have h0 := x[0].toNat_lt
  have h1 := x[1].toNat_lt
  have h2 := x[2].toNat_lt
  have h52 : (x[0] >>> 52).toNat < 2^12 := by
    rw [UInt64.toNat_shiftRight, Nat.shiftRight_eq_div_pow]
    change x[0].toNat / 2^52 < 2^12
    omega
  have h40 : (x[1] >>> 40).toNat < 2^24 := by
    rw [UInt64.toNat_shiftRight, Nat.shiftRight_eq_div_pow]
    change x[1].toNat / 2^40 < 2^24
    omega
  have h28 : (x[2] >>> 28).toNat < 2^36 := by
    rw [UInt64.toNat_shiftRight, Nat.shiftRight_eq_div_pow]
    change x[2].toNat / 2^28 < 2^36
    omega
  apply Vector.ext
  intro k hk
  interval_cases k <;> simp [unpack]
  all_goals apply congrArg (fun y : UInt64 => y &&& UInt64.ofNat MASK52)
  · exact (add_shift_eq_or _ _ 12 (by decide) h52).symm
  · exact (add_shift_eq_or _ _ 24 (by decide) h40).symm
  · exact (add_shift_eq_or _ _ 36 (by decide) h28).symm

private theorem pack_add (x : Vector UInt64 5)
    (hn : ∀ j : Fin 5, x[j].toNat < 2^52) :
    pack x = #v[x[0] + (x[1] <<< 52), (x[1] >>> 12) + (x[2] <<< 40),
      (x[2] >>> 24) + (x[3] <<< 28), (x[3] >>> 36) + (x[4] <<< 16)] := by
  have h0 : x[0].toNat < 2^52 := hn 0
  have h1 : x[1].toNat < 2^52 := hn 1
  have h2 : x[2].toNat < 2^52 := hn 2
  have h3 : x[3].toNat < 2^52 := hn 3
  have h12 : (x[1] >>> 12).toNat < 2^40 := by
    rw [UInt64.toNat_shiftRight, Nat.shiftRight_eq_div_pow]
    change x[1].toNat / 2^12 < 2^40
    omega
  have h24 : (x[2] >>> 24).toNat < 2^28 := by
    rw [UInt64.toNat_shiftRight, Nat.shiftRight_eq_div_pow]
    change x[2].toNat / 2^24 < 2^28
    omega
  have h36 : (x[3] >>> 36).toNat < 2^16 := by
    rw [UInt64.toNat_shiftRight, Nat.shiftRight_eq_div_pow]
    change x[3].toNat / 2^36 < 2^16
    omega
  apply Vector.ext
  intro k hk
  interval_cases k <;> simp [pack]
  · exact (add_shift_eq_or _ _ 52 (by decide) h0).symm
  · exact (add_shift_eq_or _ _ 40 (by decide) h12).symm
  · exact (add_shift_eq_or _ _ 28 (by decide) h24).symm
  · exact (add_shift_eq_or _ _ 16 (by decide) h36).symm

theorem vectorUnpack_refines (w : Vector M512 4) :
    fr8.u256x8.U256x8.limbs (toArray id w) =
      ok (toArray id (transpose (Vector.ofFn fun lane => unpack (wordLane w lane)))) := by
  unfold fr8.u256x8.U256x8.limbs
  simp [FrModel.MASK52_refines, FrModel.Simd.splat_refines,
    index_usize_eq (n := 4#usize) _ 0#usize (by decide), index_usize_eq (n := 4#usize) _ 1#usize (by decide),
    index_usize_eq (n := 4#usize) _ 2#usize (by decide), index_usize_eq (n := 4#usize) _ 3#usize (by decide),
    core.core_arch.x86.avx512f._mm512_and_si512,
    core.core_arch.x86.avx512f._mm512_add_epi64,
    core.core_arch.x86.avx512f._mm512_slli_epi64,
    core.core_arch.x86.avx512f._mm512_srli_epi64, bind_tc_ok, Array.make]
  apply Subtype.ext
  apply List.ext_getElem
  · simp [toArray]
  · intro k hk hk'
    have hk5 : k < 5 := by simpa using hk
    apply Vector.ext
    intro lane hl
    interval_cases k <;>
      simp [toArray, transpose, unpack_add, wordLane, laneOf,
        _mm512_and_si512, _mm512_add_epi64, _mm512_slli_epi64, _mm512_srli_epi64,
        slli, srli, FrModel.Simd.splat] <;> rfl

theorem vectorPack_refines (v : Vector M512 5)
    (hn : ∀ j : Fin 5, ∀ lane : Fin 8, v[j][lane].toNat < 2^52) :
    fr8.u256x8.U256x8.from_limbs (toArray id v) = ok (toArray id (vectorPack v)) := by
  unfold fr8.u256x8.U256x8.from_limbs
  simp [index_usize_eq (n := 5#usize) _ 0#usize (by decide),
    index_usize_eq (n := 5#usize) _ 1#usize (by decide), index_usize_eq (n := 5#usize) _ 2#usize (by decide),
    index_usize_eq (n := 5#usize) _ 3#usize (by decide), index_usize_eq (n := 5#usize) _ 4#usize (by decide),
    core.core_arch.x86.avx512f._mm512_add_epi64,
    core.core_arch.x86.avx512f._mm512_slli_epi64,
    core.core_arch.x86.avx512f._mm512_srli_epi64, bind_tc_ok, Array.make]
  apply Subtype.ext
  apply List.ext_getElem
  · simp [toArray]
  · intro k hk hk'
    have hk4 : k < 4 := by simpa using hk
    apply Vector.ext
    intro lane hl
    have hn' : ∀ j : Fin 5, (laneOf v ⟨lane, hl⟩)[j].toNat < 2^52 := by
      intro j
      simpa only [Fin.getElem_fin, getElem_laneOf] using hn j ⟨lane, hl⟩
    interval_cases k <;>
      simp [toArray, vectorPack, pack_add _ hn',
        _mm512_add_epi64, _mm512_slli_epi64, _mm512_srli_epi64, slli, srli]

end LeanBlsSimd.Kzg.Extender.Kernel.BytePacking
