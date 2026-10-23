import LeanBlsSimd.Refines.G1
import LeanBlsSimd.Spec.G1Encoding
import LeanBlsSimd.Proofs.G1Finite

/-! Mutation and boundary controls for G1. Arithmetic proofs use Lean's kernel; the full
canonicality mutation has a checked evaluation. Model wrapper controls permit arbitrary
scalar observations; generated wrapper controls use the portable decoder contract. -/

namespace LeanBlsSimd.G1Controls

open EthLib.Cryptography Bls
open DecompressG1
open DecompressG2 (FLAG_COMPRESSED FLAG_INFINITY FLAG_LARGER_ROOT fp_words less_than_p)

set_option linter.unreachableTactic false
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

/-! The endomorphism applies beta twice; the Scott comparison negates Y. -/

private def generatorX : ZMod Fp.modulus := G1.generator.x

example : (beta : ZMod Fp.modulus) ^ 2 * generatorX ≠
    (beta : ZMod Fp.modulus) * generatorX := by decide +kernel

example : (-(G1.generator.y : ZMod Fp.modulus)) ≠ G1.generator.y := by decide +kernel

example : val (.ofList BETA_MONT) = beta * R % Fp.modulus := by decide +kernel

example : val (.ofList (BETA_MONT.set 0 0)) ≠ beta * R % Fp.modulus := by decide +kernel

example : True := by
  fail_if_success
    have : val (.ofList (BETA_MONT.set 0 0)) = beta * R % Fp.modulus := by decide +kernel
  trivial

/-! The infinity-flag mutation marks a finite larger-root encoding undecided during decoding.
That flag requests scalar fallback; the control establishes only this routing effect. -/

def decodeStepWith (flagInf : UInt8) (canonical : Vector UInt64 6 → Bool)
    (inputs : Vector Encoding 8) (d : Decoded) (lane : Fin 8) : Decoded :=
  let bytes := inputs[lane]
  let bit : Mmask8 := 1 <<< lane.val.toUInt8
  let flags := bytes[0] &&& 0xe0
  if flags &&& FLAG_COMPRESSED = 0 then { d with invalid := d.invalid ||| bit }
  else if flags &&& flagInf ≠ 0 then { d with undecided := d.undecided ||| bit }
  else
    let d := if flags &&& FLAG_LARGER_ROOT ≠ 0 then
      { d with larger_root := d.larger_root ||| bit } else d
    let words := fp_words bytes
    let words := words.set 5 (words[5] &&& 0x1fffffffffffffff)
    if !canonical words then { d with invalid := d.invalid ||| bit }
    else { d with x := d.x.set lane (unpack52 words) }

example : decodeStepWith FLAG_INFINITY less_than_p = decodeStep := rfl

def largerRootBytes : Encoding := (Vector.replicate 48 0).set 0 0xa0

example : (decodeStep (.replicate 8 largerRootBytes) decodeInit 0).undecided = 0 ∧
    (decodeStepWith FLAG_LARGER_ROOT less_than_p
      (.replicate 8 largerRootBytes) decodeInit 0).undecided = 1 := by decide +kernel

/-! Skipping canonicality accepts the noncanonical x + p encoding of 2G. Its x + p
fits below 2^381, and the mutated kernel decides it valid rather than falling back. -/

def twoGPlusP : Encoding := ⟨#[
  0xbf, 0x73, 0xdd, 0xd4, 0xc9, 0xcd, 0x4d, 0xe0,
  0xd3, 0x24, 0x70, 0xa1, 0x93, 0xf4, 0xf1, 0xe3,
  0xfb, 0x99, 0x26, 0xb5, 0x84, 0xad, 0x13, 0xe4,
  0xaa, 0xc0, 0xff, 0xab, 0xba, 0x09, 0x9c, 0x4f,
  0x01, 0x3b, 0x75, 0xba, 0x40, 0x70, 0x7c, 0x42,
  0x7d, 0x99, 0x8c, 0x55, 0x29, 0xbe, 0xb9, 0xf9], rfl⟩

example :
    let n := val64 ((fp_words twoGPlusP).set 5
      ((fp_words twoGPlusP)[5] &&& 0x1fffffffffffffff))
    Fp.modulus ≤ n ∧ n < 2 ^ 381 := by decide +kernel

def decompressWith (dec : Vector Encoding 8 → Decoded) (inputs : Vector Encoding 8) : Batch :=
  let decoded := dec inputs
  let x := Fp8.from_plain decoded.x
  let rhs := (x.square.mul x).add (Fp8.splat_limbs (.ofList FOUR_MONT))
  let root := rhs.sqrt_candidate
  let on_curve := root.square.eq_mask rhs
  let flip := root.is_larger_root_mask ^^^ decoded.larger_root
  let y := Fp8.select flip root root.neg
  let undecided := decoded.undecided ||| y.is_zero_mask
  let membership := G1x8.scott_membership x y
  let undecided := (undecided ||| membership.undecided) &&& ~~~decoded.invalid
  let valid := on_curve &&& membership.members &&& ~~~undecided &&& ~~~decoded.invalid
  let xs := x.to_blst_limbs
  let ys := y.to_blst_limbs
  let points := (List.finRange 8).foldl
    (fun points lane => points.set lane (point xs[lane] ys[lane])) (.replicate 8 default)
  ⟨points, valid, undecided⟩

example : decompressWith DecompressG1.decode = decompress := rfl

def decodeWithoutCanonicality (inputs : Vector Encoding 8) : Decoded :=
  (List.finRange 8).foldl (decodeStepWith FLAG_INFINITY (fun _ => true) inputs) decodeInit

example : (decodeStep (.replicate 8 twoGPlusP) decodeInit 0).invalid = 1 ∧
    (decodeStepWith FLAG_INFINITY (fun _ => true)
      (.replicate 8 twoGPlusP) decodeInit 0).invalid = 0 := by decide +kernel

example : G1Spec.verdict twoGPlusP = none := by
  rw [G1Spec.verdict_eq_decode]
  split
  · rfl
  · rename_i P hP
    exact False.elim (DecompressG1.uncompress_of_invalid (by decide +kernel) (by decide +kernel) P hP)

-- The full kernel runs the square root and both Scott multiplication chains.
/-- info: (255, 0, false) -/
#guard_msgs in
#eval
  let batch := decompressWith decodeWithoutCanonicality (.replicate 8 twoGPlusP)
  (batch.valid.toNat, batch.undecided.toNat, (G1Spec.verdict twoGPlusP).isSome)

example : True := by
  fail_if_success
    have : (decodeStepWith FLAG_INFINITY (fun _ => true)
        (.replicate 8 twoGPlusP) decodeInit 0).invalid =
        (decodeStep (.replicate 8 twoGPlusP) decodeInit 0).invalid := by decide +kernel
  trivial

/-! Affine output keeps x before y, including when either coordinate is zero. -/

def pointWith (swap : Bool) (x y : Vector UInt64 6) : BlstP1Affine :=
  if swap then point y x else point x y

example : pointWith false = point := rfl

example : (pointWith true (.replicate 6 1) (.replicate 6 2)).x.l ≠
    (point (.replicate 6 1) (.replicate 6 2)).x.l := by decide

/-! Infinity is accepted only in its canonical form; its affine limbs are zero. -/

example : G1Spec.verdict G1Spec.infinity = some (point (.replicate 6 0) (.replicate 6 0)) :=
  G1Spec.infinity_verdict

example : G1.uncompress (G1Spec.toBytes (G1Spec.infinity.set 47 1)) ≠ .ok G1.zero := by
  intro hd
  have h := (G1Spec.infinity_decoding_iff _).mp hd
  have := congrArg (fun b : Encoding => b[47]) h
  revert this
  decide

/-! SIMD disabled and partial tails preserve the supplied fallback exactly.
A complete chunk uses a decided kernel lane, while an undecided lane still falls back. -/

open UncompressG1

theorem scalar_model (blst : Encoding → Option BlstP1Affine) (inputs : List Encoding) :
    uncompress false blst inputs = inputs.map blst := by
  apply List.ext_getElem
  · simp
  · intro i hi hj
    rw [getElem_uncompress_scalar false blst inputs i (by simpa using hi) (Or.inl rfl)]
    simp [getElem!_pos, show i < inputs.length by simpa using hi]

example (blst : Encoding → Option BlstP1Affine) (b : Encoding) :
    uncompress true blst [b] = [blst b] := by simp [uncompress, usesKernel]

example (simd : Bool) (blst : Encoding → Option BlstP1Affine) :
    uncompress simd blst [] = [] := by simp [uncompress]

example (inputs : List Encoding) (hn : inputs.length = 9)
    (hu : (decompress (chunkAt inputs 7)).undecided.toNat.testBit 7 = false) :
    usesKernel true inputs 7 = true ∧ usesKernel true inputs 8 = false := by
  simp [usesKernel, hn, hu]

example (inputs : List Encoding) (hn : inputs.length = 8)
    (hu : (decompress (chunkAt inputs 7)).undecided.toNat.testBit 7 = true) :
    usesKernel true inputs 7 = false := by simp [usesKernel, hn, hu]

example (blst : Encoding → Option BlstP1Affine) (inputs : List Encoding)
    (hn : inputs.length = 9) :
    (uncompress true blst inputs)[8]'(by simp [hn]) = blst inputs[8]! :=
  getElem_uncompress_scalar true blst inputs 8 (by omega) (Or.inr (by omega))

example (inputs : List Encoding) (hn : inputs.length = 9) : True := by
  have hf : usesKernel true inputs 8 = false := by simp [usesKernel, hn]
  fail_if_success
    have : usesKernel true inputs 8 = true := by rw [hf]; decide
  trivial

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

example [RuntimeFeatures] (hdec : G1DecoderCorrect) (hs : RuntimeFeatures.simdAvailable = false)
    (inputs : Slice (Aeneas.Std.Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val = inputs.val.map UncompressG1.specVerdict := by
  obtain ⟨result, hr, hv⟩ := uncompress_refines hdec inputs out hlen
  refine ⟨result, hr, ?_⟩
  rw [hv, hs, scalar_model]
  simp [modelBlst, List.map_map, Option.map_map, Function.comp_def, toArray_ofArray]

example [cpu : RuntimeFeatures] (inputs : Slice (Aeneas.Std.Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) (hi : inputs.val = []) (ho : out.val = []) :
    silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok out := by
  rcases inputs with ⟨ins, hins⟩
  rcases out with ⟨outs, houts⟩
  change ins = [] at hi
  change outs = [] at ho
  subst ins
  subst outs
  have hlen (α : Type) (h : ([] : List α).length ≤ Usize.max) :
      Slice.len (⟨[], h⟩ : Slice α) = 0#usize := by
    apply UScalar.eq_of_val_eq
    rfl
  have hd2 : (0#usize / 2#usize) = ok 0#usize := by rfl
  have hm2 : (0#usize * 2#usize) = ok 0#usize := by
    rw [mul_ok _ _ (by scalar_tac)]
    rfl
  have hd8 : (0#usize / 8#usize) = ok 0#usize := by rfl
  have hm8 : (0#usize * 8#usize) = ok 0#usize := by
    rw [mul_ok _ _ (by scalar_tac)]
    rfl
  have hpLoop (i : Slice (Aeneas.Std.Array U8 48#usize))
      (o : Slice (Option blst.blst_p1_affine)) :
      portable.decompress.uncompress_all_in_g1_loop i o 0#usize 0#usize = ok (o, 0#usize) := by
    unfold portable.decompress.uncompress_all_in_g1_loop
    rw [loop.eq_1]
    rfl
  have hbLoop (i : Slice (Aeneas.Std.Array U8 48#usize))
      (o : Slice (Option blst.blst_p1_affine)) :
      uncompress_in_g1_loop i o 0#usize 0#usize = ok o := by
    unfold uncompress_in_g1_loop
    rw [loop.eq_1]
    rfl
  have hs : portable.decompress.uncompress_all_in_g1
      (⟨[], by simp⟩ : Slice (Aeneas.Std.Array U8 48#usize))
      (⟨[], by simp⟩ : Slice (Option blst.blst_p1_affine)) = ok ⟨[], by simp⟩ := by
    simp [portable.decompress.uncompress_all_in_g1, hlen, hd2, hm2, hpLoop]
  cases hcpu : cpu.simdAvailable
  · simpa [silver_crypto_simd.bls.uncompress_in_g1, ifma_available, hcpu] using hs
  · simp [silver_crypto_simd.bls.uncompress_in_g1, ifma_available, hcpu, hlen,
      LANES, hd8, hm8, hbLoop,
      core.slice.index.SliceIndexRangeUsizeSlice.index,
      core.slice.index.SliceIndexRangeUsizeSlice.index_mut,
      Slice.length, List.slice, List.setSlice!, hs]

end LeanBlsSimd.G1Controls
