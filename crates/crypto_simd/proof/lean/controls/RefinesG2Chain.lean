import controls.G1Fallback
import LeanBlsSimd.Refines.DecompressG2
import LeanBlsSimd.Refines.G2x8
import LeanBlsSimd.Proofs.Convert
import LeanBlsSimd.Refines.G1Wrapper

/-! Mutation controls for `LeanBlsSimd/Refines/`. Each `fail_if_success` checks that a proof script
rejects a mutation; each plain `example` must pass.

Each mutated definition takes the changed part as a parameter. An `rfl` check identifies its
unmutated instance with the original, and the same proof script succeeds on that instance.
Separate concrete examples refute the mutated claims where described below. -/

namespace LeanBlsSimd

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

-- A mutated proof stops at its first failing step, so the linters flag the steps after it.
set_option linter.unreachableTactic false
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

/-! ## `G2x8::times_minus_z`: the bits that add

The countdown compares the counter with `Z_BITS[1]` to `Z_BITS[5]` and adds the point at each. A
generated loop whose last comparison reads `Z_BITS[4]` again never adds at bit 16, and must not
refine the model's loop. The script fails on the mutant. A concrete refutation of the entire
loop would require evaluating both chains past bit 16, with thousands of lane multiplications.

The concrete check instead refutes the step required by `loop_countdown`. At counter 17, from
the point (0, 1, 1) with the affine point (0, 0) and mask 0, the mutant body returns mask 0 and
`chainStep` returns 255. Doubling (0, 1, 1) gives x = 0, so the addition's H = 0 · Z² − 0 is zero
on every lane. -/

def timesMinusZBodyWith (k : Usize) (px py : fp2x8.Fp2x8) (undecided : U8) (r : g2x8.G2x8)
    (bit : U32) : Result (ControlFlow (U8 × g2x8.G2x8 × U32) (g2x8.G2x8 × U8)) := do
  if bit > 0#u32
  then
    let bit1 ← bit - 1#u32
    let (d, u) ← g2x8.G2x8.double r
    let undecided1 ← lift (undecided ||| u)
    let i ← Array.index_usize constants.Z_BITS 1#usize
    if bit1 = i
    then
      let (a, u1) ← g2x8.G2x8.add_affine d px py
      let undecided2 ← lift (undecided1 ||| u1)
      ok (cont (undecided2, a, bit1))
    else
      let i1 ← Array.index_usize constants.Z_BITS 2#usize
      if bit1 = i1
      then
        let (a, u1) ← g2x8.G2x8.add_affine d px py
        let undecided2 ← lift (undecided1 ||| u1)
        ok (cont (undecided2, a, bit1))
      else
        let i2 ← Array.index_usize constants.Z_BITS 3#usize
        if bit1 = i2
        then
          let (a, u1) ← g2x8.G2x8.add_affine d px py
          let undecided2 ← lift (undecided1 ||| u1)
          ok (cont (undecided2, a, bit1))
        else
          let i3 ← Array.index_usize constants.Z_BITS 4#usize
          if bit1 = i3
          then
            let (a, u1) ← g2x8.G2x8.add_affine d px py
            let undecided2 ← lift (undecided1 ||| u1)
            ok (cont (undecided2, a, bit1))
          else
            let i4 ← Array.index_usize constants.Z_BITS k
            if bit1 = i4
            then
              let (a, u1) ← g2x8.G2x8.add_affine d px py
              let undecided2 ← lift (undecided1 ||| u1)
              ok (cont (undecided2, a, bit1))
            else ok (cont (undecided1, d, bit1))
  else ok (done (r, undecided))

def timesMinusZLoopWith (k : Usize) (px py : fp2x8.Fp2x8) (undecided : U8) (r : g2x8.G2x8)
    (bit : U32) : Result (g2x8.G2x8 × U8) :=
  loop (fun (undecided1, r1, bit1) => timesMinusZBodyWith k px py undecided1 r1 bit1)
    (undecided, r, bit)

example : timesMinusZLoopWith 5#usize = g2x8.G2x8.times_minus_z_loop := rfl

set_option hygiene false in
/-- The proof of `G2x8.times_minus_z_loop_refines`, over `timesMinusZLoopWith`. -/
local macro "times_minus_z_loop_proof" : tactic => `(tactic| (
  intro px py m c n hcn hn
  unfold timesMinusZLoopWith
  refine loop_countdown _ (fun (m : G2x8 × Mmask8) c => (toU8 m.2, toG2x8 m.1, c))
    (G2x8.chainStep (ofFp2x8 px) (ofFp2x8 py)) (Prod.map toG2x8 toU8) n ?_ ?_ c m hcn
  · intro m c hc
    simp [timesMinusZBodyWith, hc]
    rfl
  · intro ⟨r, u⟩ c c' hc hcn
    obtain ⟨⟨d, du⟩, hd⟩ : ∃ d, r.double = d := ⟨_, rfl⟩
    obtain ⟨⟨a, au⟩, ha⟩ : ∃ a, d.add_affine (ofFp2x8 px) (ofFp2x8 py) = a := ⟨_, rfl⟩
    simp only [timesMinusZBodyWith]
    rw [if_pos (by simp; omega), sub_ok _ _ (by simp; omega)]
    have e : (UScalar.ofNatCore (c.val - (1#u32).val) (by have := c.hBounds; omega) : U32) =
        c' :=
      UScalar.eq_of_val_eq (by simp; omega)
    rw [e]
    simp (disch := decide) only [bind_tc_ok, G2x8.double_refines, Function.uncurry_def,
      Prod.map_fst, Prod.map_snd, ofG2x8_toG2x8, lift, Z_BITS_index, toU8_or,
      G2x8.add_affine_refines, UScalar.eq_equiv, UScalar.ofNatCore_val_eq]
    simp only [show Z_BITS[1]! = 62 from rfl, show Z_BITS[2]! = 60 from rfl,
      show Z_BITS[3]! = 57 from rfl, show Z_BITS[4]! = 48 from rfl, show Z_BITS[5]! = 16 from rfl]
    simp only [G2x8.chainStep, hd, ha]
    by_cases h : c'.val = 62 ∨ c'.val = 60 ∨ c'.val = 57 ∨ c'.val = 48 ∨ c'.val = 16
    · have hz : Z_BITS.contains c'.val := by simp [Z_BITS]; omega
      rw [if_pos hz]
      rcases h with h | h | h | h | h <;> simp [h]
    · have hz : c'.val ∉ Z_BITS := by simp [Z_BITS]; omega
      simp only [not_or] at h
      simp [h, hz]))

example : ∀ (px py : fp2x8.Fp2x8) (m : G2x8 × Mmask8) (c : U32) (n : ℕ),
    c.val = n → n ≤ 63 →
    timesMinusZLoopWith 5#usize px py (toU8 m.2) (toG2x8 m.1) c =
      ok (Prod.map toG2x8 toU8
        ((List.range n).reverse.foldl (G2x8.chainStep (ofFp2x8 px) (ofFp2x8 py)) m)) := by
  times_minus_z_loop_proof

example : True := by
  fail_if_success
    have : ∀ (px py : fp2x8.Fp2x8) (m : G2x8 × Mmask8) (c : U32) (n : ℕ),
        c.val = n → n ≤ 63 →
        timesMinusZLoopWith 4#usize px py (toU8 m.2) (toG2x8 m.1) c =
          ok (Prod.map toG2x8 toU8
            ((List.range n).reverse.foldl (G2x8.chainStep (ofFp2x8 px) (ofFp2x8 py)) m)) := by
      times_minus_z_loop_proof
  trivial

/-- The point (0, 1, 1) in Jacobian coordinates, on every lane. -/
def zeroOneOne : G2x8 := ⟨⟨Fp8.zero, Fp8.zero⟩, Fp2x8.one, Fp2x8.one⟩

theorem double_zeroOneOne_mask : (zeroOneOne.double).2 = 0 := by
  decide +kernel

theorem add_affine_zero_mask :
    (zeroOneOne.double.1.add_affine ⟨Fp8.zero, Fp8.zero⟩ ⟨Fp8.zero, Fp8.zero⟩).2 = 255 := by
  have hc : ∀ m : Mmask8, ~~~m = 0 → m = 255 := by
    intro m h
    have h' := congrArg (fun x : Mmask8 => ~~~x) h
    simpa using h'
  apply hc
  apply Mmask8.eq_zero_of_testBit
  intro l
  rw [Mmask8.testBit_not]
  have hzero : (⟨Fp8.zero, Fp8.zero⟩ : Fp2x8).Holds l 0 :=
    ⟨Fp8.holds_zero l, Fp8.holds_zero l⟩
  have hp : zeroOneOne.Holds l ![0, 1, 1] :=
    ⟨hzero, Fp2x8.holds_one l, Fp2x8.holds_one l⟩
  rw [(hp.double.1.add_affine hzero hzero).2]
  simp [Kernel.addAffine, Kernel.double, WeierstrassCurve.Jacobian.dblXYZ,
    WeierstrassCurve.Jacobian.dblX, WeierstrassCurve.Jacobian.dblU_eq,
    WeierstrassCurve.Jacobian.negY, G2.curve]


example : ¬ ∀ (px py : fp2x8.Fp2x8) (m : G2x8 × Mmask8) (c c' : U32),
    c.val = c'.val + 1 → c.val ≤ 63 →
    timesMinusZBodyWith 4#usize px py (toU8 m.2) (toG2x8 m.1) c =
      ok (cont (toU8 (G2x8.chainStep (ofFp2x8 px) (ofFp2x8 py) m c'.val).2,
        toG2x8 (G2x8.chainStep (ofFp2x8 px) (ofFp2x8 py) m c'.val).1, c')) := by
  intro h
  have e := h (toFp2x8 ⟨Fp8.zero, Fp8.zero⟩) (toFp2x8 ⟨Fp8.zero, Fp8.zero⟩) (zeroOneOne, 0) 17#u32
    16#u32 (by decide) (by decide)
  simp only [timesMinusZBodyWith] at e
  rw [if_pos (by decide), sub_ok _ _ (by decide)] at e
  simp (disch := decide) only [bind_tc_ok, G2x8.double_refines, Function.uncurry_def,
    Prod.map_fst, Prod.map_snd, ofG2x8_toG2x8, lift, Z_BITS_index, toU8_or,
    UScalar.eq_equiv, UScalar.ofNatCore_val_eq] at e
  simp only [show Z_BITS[1]! = 62 from rfl, show Z_BITS[2]! = 60 from rfl,
    show Z_BITS[3]! = 57 from rfl, show Z_BITS[4]! = 48 from rfl] at e
  rw [if_neg (by decide), if_neg (by decide), if_neg (by decide), if_neg (by decide),
    if_neg (by decide)] at e
  have hz : Z_BITS.contains 16 = true := by decide
  simp only [G2x8.chainStep, hz, if_true, ofFp2x8_toFp2x8, double_zeroOneOne_mask,
    add_affine_zero_mask, ok.injEq, cont.injEq, Prod.mk.injEq] at e
  exact absurd e.1 (by decide)


end LeanBlsSimd
