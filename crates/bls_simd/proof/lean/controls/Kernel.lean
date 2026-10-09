import LeanBlsSimd.Proofs.Kernel

/-! Controls for `LeanBlsSimd.Proofs.Kernel`: the input-dependent premises of its theorems hold
on concrete inputs. Scott completeness stays assumed. Each `example` must pass.

- Eight lanes holding the compressed encoding of the spec's generator G: every lane is decided
  and valid, `G2.uncompress` returns G, and both sides of `decompress_eq_spec` are
  `some (blstLimbs G)`.
- Eight lanes of 96 zero bytes, whose compression flag is clear: every lane is decided and not
  valid, `G2.uncompress` fails, and both sides of `decompress_eq_spec` are `none`.

Lean's kernel cannot evaluate `decompress` in practice, so both go through `decompress_lane` and
the lane functions. `decide +kernel` evaluates the bytes and the Scott test on G. The square root,
whose exponents have about 380 bits, follows from `Kernel.sqrt_snd_iff` and `selectRoot_eq`
instead. Neither example needs `ScottComplete`. -/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls DecompressG2 Kernel

local notation "gx" => Fp2.toField G2.generator.x
local notation "gy" => Fp2.toField G2.generator.y

/-! ## A valid lane: the generator -/

/-- The compressed encoding of the spec's generator: x1 then x0, big-endian, with the compression
flag set and the sign flag clear. `uncompress_genBytes` decodes it to `G2.generator`. -/
def genBytes : Vector UInt8 G2_COMPRESSED_LEN := ⟨#[
  0x93, 0xe0, 0x2b, 0x60, 0x52, 0x71, 0x9f, 0x60, 0x7d, 0xac, 0xd3, 0xa0, 0x88, 0x27, 0x4f, 0x65,
  0x59, 0x6b, 0xd0, 0xd0, 0x99, 0x20, 0xb6, 0x1a, 0xb5, 0xda, 0x61, 0xbb, 0xdc, 0x7f, 0x50, 0x49,
  0x33, 0x4c, 0xf1, 0x12, 0x13, 0x94, 0x5d, 0x57, 0xe5, 0xac, 0x7d, 0x05, 0x5d, 0x04, 0x2b, 0x7e,
  0x02, 0x4a, 0xa2, 0xb2, 0xf0, 0x8f, 0x0a, 0x91, 0x26, 0x08, 0x05, 0x27, 0x2d, 0xc5, 0x10, 0x51,
  0xc6, 0xe4, 0x7a, 0xd4, 0xfa, 0x40, 0x3b, 0x02, 0xb4, 0x51, 0x0b, 0x64, 0x7a, 0xe3, 0xd1, 0x77,
  0x0b, 0xac, 0x03, 0x26, 0xa8, 0x05, 0xbb, 0xef, 0xd4, 0x80, 0x56, 0xc8, 0xc1, 0x21, 0xbd, 0xb8],
  rfl⟩

def genInputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8 := .replicate 8 genBytes

theorem genBytes_flags :
    (decodeLane genBytes).invalid = false ∧ (decodeLane genBytes).undecided = false ∧
      (decodeLane genBytes).largerRoot = Fp2.signBit G2.generator.y := by
  decide +kernel

theorem laneX_genBytes : laneX genBytes = gx := by
  decide +kernel

theorem rhs_gx : rhs gx = gy ^ 2 := by
  decide +kernel

theorem sqrt_genBytes : (sqrt (rhs (laneX genBytes))).2 = true := by
  rw [laneX_genBytes, sqrt_snd_iff, rhs_gx, sq]
  exact ⟨gy, rfl⟩

theorem laneY_genBytes : laneY genBytes = gy := by
  have h : (sqrt (rhs (laneX genBytes))).1 ^ 2 = gy ^ 2 := by
    rw [sqrt_fst_sq sqrt_genBytes, laneX_genBytes, rhs_gx]
  rw [laneY, selectRoot_eq h, genBytes_flags.2.2, if_pos rfl]

theorem laneOnCurve_genBytes : laneOnCurve genBytes = true := by
  rw [laneOnCurve, sqrt_genBytes, genBytes_flags.1, genBytes_flags.2.1]
  rfl

theorem laneUndecided_genBytes : laneUndecided genBytes = false := by
  rw [laneUndecided, genBytes_flags.2.1, laneX_genBytes, laneY_genBytes, scottMembership_generator]
  rfl

theorem laneValid_genBytes : laneValid genBytes = true := by
  rw [laneValid, laneUndecided_genBytes, laneOnCurve_genBytes, laneX_genBytes, laneY_genBytes,
    scottMembership_generator]
  rfl

theorem genInputs_lane (l : Fin 8) : LaneVerdicts (decompress genInputs) genBytes l := by
  have hl : genInputs[l] = genBytes := Vector.getElem_replicate ..
  have h := decompress_lane genInputs l
  rwa [hl] at h

/-- Every lane is decided and valid: `decompress_eq_spec`'s hypothesis holds, and its left side
is `some`. -/
example (l : Fin 8) : (decompress genInputs).undecided.toNat.testBit l = false ∧
    (decompress genInputs).valid.toNat.testBit l = true :=
  ⟨(genInputs_lane l).undecided.trans laneUndecided_genBytes,
    (genInputs_lane l).valid.trans laneValid_genBytes⟩

theorem uncompress_genBytes : G2.uncompress (toBytes genBytes) = .ok G2.generator := by
  obtain ⟨hon, hpt⟩ := laneOnCurve_iff laneUndecided_genBytes
  obtain ⟨P, hP⟩ := hon.mp laneOnCurve_genBytes
  obtain ⟨hz, hx, hy⟩ := hpt P hP
  rw [laneX_genBytes] at hx
  rw [laneY_genBytes] at hy
  obtain ⟨x, y, z⟩ := P
  simp only at hz hx hy
  rw [Fp2.toField.injective hx, Fp2.toField.injective hy, hz] at hP
  exact hP

/-- Both sides of `decompress_eq_spec`, computed without `ScottComplete`, are the generator in
blst's limbs. -/
example (l : Fin 8) :
    (if (decompress genInputs).valid.toNat.testBit l then some (decompress genInputs).points[l]
      else none) = some (blstLimbs G2.generator) ∧
    (match G2.uncompress (toBytes genInputs[l]) with
      | .error _ => none
      | .ok P => if G2.inSubgroup P then some (blstLimbs P) else none) =
      some (blstLimbs G2.generator) := by
  have hl : genInputs[l] = genBytes := Vector.getElem_replicate ..
  have hu := (genInputs_lane l).undecided.trans laneUndecided_genBytes
  have hv := (genInputs_lane l).valid.trans laneValid_genBytes
  have hpt := (decode_lane genInputs l hu).2 G2.generator (by rw [hl]; exact uncompress_genBytes)
  have hg : G2.inSubgroup G2.generator = true :=
    G2.inSubgroup_of_psi (G2.valid_mk_one (x := G2.generator.x) (y := G2.generator.y)
      nonsingular_generator) psi_generator
  rw [hv, if_pos rfl, hpt, hl, uncompress_genBytes]
  refine ⟨rfl, ?_⟩
  dsimp only
  rw [if_pos hg]

/-! ## A rejected lane: zero bytes -/

def zeroInputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8 := .replicate 8 (.replicate 96 0)

theorem zeroBytes_flags :
    (decodeLane (.replicate 96 0)).invalid = true ∧
      (decodeLane (.replicate 96 0)).undecided = false := by
  decide +kernel

theorem laneOnCurve_zeroBytes : laneOnCurve (.replicate 96 0) = false := by
  rw [laneOnCurve, zeroBytes_flags.1, Bool.true_or, Bool.not_true, Bool.and_false]

theorem zeroInputs_lane (l : Fin 8) :
    LaneVerdicts (decompress zeroInputs) (.replicate 96 0) l := by
  have hl : zeroInputs[l] = .replicate 96 0 := Vector.getElem_replicate ..
  have h := decompress_lane zeroInputs l
  rwa [hl] at h

/-- Every lane is decided and not valid, `G2.uncompress` fails, and both sides of
`decompress_eq_spec` are `none`. -/
example (l : Fin 8) : (decompress zeroInputs).undecided.toNat.testBit l = false ∧
    (decompress zeroInputs).valid.toNat.testBit l = false ∧
    (∀ P, G2.uncompress (toBytes zeroInputs[l]) ≠ .ok P) := by
  have hl : zeroInputs[l] = .replicate 96 0 := Vector.getElem_replicate ..
  refine ⟨?_, ?_, ?_⟩
  · rw [(zeroInputs_lane l).undecided, laneUndecided, zeroBytes_flags.2, laneOnCurve_zeroBytes,
      Bool.and_false, Bool.false_or]
  · rw [(zeroInputs_lane l).valid, laneValid, laneOnCurve_zeroBytes, Bool.and_false,
      Bool.false_and]
  · rw [hl]
    exact uncompress_of_invalid zeroBytes_flags.2 zeroBytes_flags.1

end LeanBlsSimd
