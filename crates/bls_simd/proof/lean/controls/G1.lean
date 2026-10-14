import LeanBlsSimd.Refines.G1
import LeanBlsSimd.Spec.G1Encoding

/-! Mutation and boundary controls for G1. Concrete arithmetic uses Lean's kernel.
The scalar external remains arbitrary in the wrapper controls. -/

namespace LeanBlsSimd.G1Controls

open EthCryptographySpecs Bls
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

/-! Changing the infinity flag confuses a finite larger-root encoding with infinity.
Skipping the canonical-coordinate test accepts x = p. -/

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

def modulusBytes : Encoding := ⟨#[
  0x9a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a,
  0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
  0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf,
  0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
  0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff,
  0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab], rfl⟩

example : val64 ((fp_words modulusBytes).set 5
    ((fp_words modulusBytes)[5] &&& 0x1fffffffffffffff)) = Fp.modulus := by decide +kernel

example : (decodeStep (.replicate 8 largerRootBytes) decodeInit 0).undecided = 0 ∧
    (decodeStepWith FLAG_LARGER_ROOT less_than_p
      (.replicate 8 largerRootBytes) decodeInit 0).undecided = 1 := by decide +kernel

example : (decodeStep (.replicate 8 modulusBytes) decodeInit 0).invalid = 1 ∧
    (decodeStepWith FLAG_INFINITY (fun _ => true)
      (.replicate 8 modulusBytes) decodeInit 0).invalid = 0 := by decide +kernel

example : True := by
  fail_if_success
    have : (decodeStepWith FLAG_INFINITY (fun _ => true)
        (.replicate 8 modulusBytes) decodeInit 0).invalid =
        (decodeStep (.replicate 8 modulusBytes) decodeInit 0).invalid := by decide +kernel
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
open silver_bls_simd

example [G1Externals] (hs : G1Externals.simdAvailable = false)
    (inputs : Slice (Aeneas.Std.Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_bls_simd.uncompress_in_g1 inputs out = ok result ∧
      result.val = inputs.val.map G1Externals.uncompress := by
  obtain ⟨result, hr, hv⟩ := uncompress_refines inputs out hlen
  refine ⟨result, hr, ?_⟩
  rw [hv, hs, scalar_model]
  simp [modelBlst, List.map_map, Option.map_map, Function.comp_def, toArray_ofArray]

example [G1Externals] (inputs : Slice (Aeneas.Std.Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) (hi : inputs.val = []) (ho : out.val = []) :
    silver_bls_simd.uncompress_in_g1 inputs out = ok out := by
  obtain ⟨result, hr, hv⟩ := uncompress_refines inputs out (by simp [hi, ho])
  have he : result = out := by
    apply Subtype.ext
    simp [hv, hi, ho, uncompress]
  simpa [he] using hr

end LeanBlsSimd.G1Controls
