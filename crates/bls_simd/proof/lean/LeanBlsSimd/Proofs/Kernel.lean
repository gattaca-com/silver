import LeanBlsSimd.Proofs.DecompressG2
import LeanBlsSimd.Spec.Generator

/-!
# `decompress` against the spec's signature check

The spec reads a signature's 96 bytes with `G2.uncompress`, then tests the point with
`G2.inSubgroup` (`coreVerify` in `EthCryptographySpecs/Bls/Signatures.lean`). The program reads
lane `l` of a `Batch` in `decompress_g2_chunk` of `lib.rs`: an `undecided` lane goes to blst;
otherwise a `valid` lane gives `Some(points[l])`, and any other lane `None`. Bit `l` of a mask
`m` is `m.toNat.testBit l`, which is Rust's `m & (1 << l) != 0`
(`Mmask8.and_one_shiftLeft_ne_zero`).

On a lane whose `undecided` bit is clear:

- `decode_lane`: `on_curve` is set exactly when `G2.uncompress` succeeds, and `points` then holds
  the decoded point in blst's limbs.
- `valid_sound`: a `valid` lane decodes to a point of the subgroup, and `points` holds it. This
  needs no Scott completeness and no separate decided-lane premise: `valid` implies a clear
  `undecided` bit.
- `valid_complete`: a lane that decodes to a point of the subgroup is `valid`, given Scott
  completeness (`ScottComplete`).
- `decompress_eq_spec`: the lane's result in `decompress_g2_chunk` is the spec's, mapped through
  `blstLimbs`, given Scott completeness.

Nothing is claimed about a lane whose `undecided` bit is set.

`psi_generator` proves `ScottComplete`'s claim for the spec's generator. So the constants of ψ and
the sign of z do not make that hypothesis false.
-/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls DecompressG2 Kernel

theorem Mmask8.and_one_shiftLeft_ne_zero (m : Mmask8) (l : Fin 8) :
    m &&& (1 : Mmask8) <<< l.val.toUInt8 ≠ 0 ↔ m.toNat.testBit l = true := by
  have hbit (i : Fin 8) : (m &&& (1 : Mmask8) <<< l.val.toUInt8).toNat.testBit i =
      (m.toNat.testBit i && decide (i = l)) := by
    rw [Mmask8.testBit_and, Mmask8.testBit_one_shiftLeft]
  constructor
  · intro h
    by_contra hl
    apply h
    apply Mmask8.eq_zero_of_testBit
    intro i
    rw [hbit]
    by_cases hi : i = l
    · subst hi
      simpa using hl
    · simp [hi]
  · intro h h0
    have := hbit l
    rw [h0, Mmask8.testBit_zero, h] at this
    simp at this

namespace DecompressG2

/-- On a lane that is not undecided, a point that `G2.uncompress` returns is a nonsingular
Jacobian point, so `G2.toPoint` reads it faithfully. -/
theorem valid_of_uncompress {inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8} {l : Fin 8}
    (hu : (decompress inputs).undecided.toNat.testBit l = false) {P : G2}
    (hP : G2.uncompress (toBytes inputs[l]) = .ok P) : G2.Valid P := by
  have hu' : laneUndecided inputs[l] = false := (decompress_lane inputs l).undecided.symm.trans hu
  obtain ⟨hon, hpt⟩ := laneOnCurve_iff hu'
  obtain ⟨hz, hx, hy⟩ := hpt P hP
  have hn := laneOnCurve_nonsingular (hon.mpr ⟨P, hP⟩)
  rw [← hx, ← hy] at hn
  obtain ⟨x, y, z⟩ := P
  simp only at hz
  subst hz
  exact G2.valid_mk_one hn

/-- On a lane that is not undecided, `on_curve` is set exactly when `G2.uncompress` of the
lane's bytes succeeds, and then `points` holds that point in blst's limbs. -/
theorem decode_lane (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8)
    (hu : (decompress inputs).undecided.toNat.testBit l = false) :
    ((decompress inputs).on_curve.toNat.testBit l = true ↔
        ∃ P, G2.uncompress (toBytes inputs[l]) = .ok P) ∧
      ∀ P, G2.uncompress (toBytes inputs[l]) = .ok P →
        (decompress inputs).points[l] = blstLimbs P :=
  decompress_onCurve inputs l hu

/-- No false accept: a `valid` lane's bytes decode to a point of the subgroup, and `points`
holds that point in blst's limbs. -/
theorem valid_sound (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8)
    (hv : (decompress inputs).valid.toNat.testBit l = true) :
    ∃ P, G2.uncompress (toBytes inputs[l]) = .ok P ∧ G2.inSubgroup P = true ∧
      (decompress inputs).points[l] = blstLimbs P := by
  have hu := decompress_undecided_of_valid hv
  obtain ⟨P, hP, hψ⟩ := (decompress_valid inputs l hu).mp hv
  exact ⟨P, hP, G2.inSubgroup_of_psi (valid_of_uncompress hu hP) hψ,
    (decode_lane inputs l hu).2 P hP⟩

/-- No false reject, given Scott completeness: on a lane that is not undecided, bytes that decode
to a point of the subgroup give a `valid` lane. -/
theorem valid_complete (hC : ScottComplete) (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8)
    (l : Fin 8) (hu : (decompress inputs).undecided.toNat.testBit l = false)
    (h : ∃ P, G2.uncompress (toBytes inputs[l]) = .ok P ∧ G2.inSubgroup P = true) :
    (decompress inputs).valid.toNat.testBit l = true := by
  obtain ⟨P, hP, hg⟩ := h
  exact (decompress_valid inputs l hu).mpr
    ⟨P, hP, hC _ ((G2.inSubgroup_iff (valid_of_uncompress hu hP)).mp hg)⟩

/-- Given Scott completeness, a lane that is not undecided gives the spec's result. The left side
is `decompress_g2_chunk`'s result for the lane in `lib.rs`, past its `undecided` test. The right
side is `coreVerify`'s reading of the bytes: `G2.uncompress`, then `G2.inSubgroup`, with `none` on
either failure, and the point in blst's limbs. -/
theorem decompress_eq_spec (hC : ScottComplete)
    (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8)
    (hu : (decompress inputs).undecided.toNat.testBit l = false) :
    (if (decompress inputs).valid.toNat.testBit l then some (decompress inputs).points[l]
      else none) =
    (match G2.uncompress (toBytes inputs[l]) with
      | .error _ => none
      | .ok P => if G2.inSubgroup P then some (blstLimbs P) else none) := by
  cases hd : G2.uncompress (toBytes inputs[l]) with
  | error e =>
    have hv : (decompress inputs).valid.toNat.testBit l = false := by
      cases hv : (decompress inputs).valid.toNat.testBit l
      · rfl
      · obtain ⟨P, hP, -⟩ := valid_sound inputs l hv
        rw [hP] at hd
        cases hd
    rw [hv]
    rfl
  | ok P =>
    dsimp only
    by_cases hg : G2.inSubgroup P = true
    · rw [if_pos (valid_complete hC inputs l hu ⟨P, hd, hg⟩), if_pos hg,
        (decode_lane inputs l hu).2 P hd]
    · have hv : (decompress inputs).valid.toNat.testBit l = false := by
        cases hv : (decompress inputs).valid.toNat.testBit l
        · rfl
        · obtain ⟨Q, hQ, hQg, -⟩ := valid_sound inputs l hv
          rw [hd] at hQ
          cases hQ
          exact absurd hQg hg
      rw [hv, if_neg hg]
      rfl

end DecompressG2

end LeanBlsSimd
