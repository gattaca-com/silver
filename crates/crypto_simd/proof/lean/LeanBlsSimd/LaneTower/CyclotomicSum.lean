import LeanBlsSimd.LaneTower.Frobenius

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.LaneTower

def cycleRe : Array I64 8#usize := Array.make 8#usize
  [7#i64, 7#i64, 7#i64, 2#i64, 7#i64, 0#i64, 7#i64, 7#i64] (by rfl)

def cycleIm : Array I64 8#usize := Array.make 8#usize
  [7#i64, 7#i64, 7#i64, 3#i64, 7#i64, 1#i64, 7#i64, 7#i64] (by rfl)

def cycleNPos : Array I64 8#usize := Array.make 8#usize
  [0#i64, 1#i64, 2#i64, 7#i64, 6#i64, 13#i64, 7#i64, 7#i64] (by rfl)

def cycleNNeg0 : Array I64 8#usize := Array.make 8#usize
  [7#i64, 7#i64, 7#i64, 7#i64, 0#i64, 1#i64, 7#i64, 7#i64] (by rfl)

def cycleNNeg1 : Array I64 8#usize := Array.make 8#usize
  [7#i64, 7#i64, 7#i64, 7#i64, 3#i64, 4#i64, 7#i64, 7#i64] (by rfl)

def cycleMPos : Array I64 8#usize := Array.make 8#usize
  [3#i64, 4#i64, 5#i64, 11#i64, 7#i64, 7#i64, 7#i64, 7#i64] (by rfl)

def cycleMNeg0 : Array I64 8#usize := Array.make 8#usize
  [7#i64, 7#i64, 7#i64, 2#i64, 7#i64, 7#i64, 7#i64, 7#i64] (by rfl)

def cycleMNeg1 : Array I64 8#usize := Array.make 8#usize
  [7#i64, 7#i64, 7#i64, 5#i64, 7#i64, 7#i64, 7#i64, 7#i64] (by rfl)

def cyclotomicT (q : P F) (m : V F) : P F :=
  let sums := (shuffle cycleRe m (fun _ => 0), shuffle cycleIm m (fun _ => 0))
  let np := shuffle2 cycleNPos q sums
  let nn := add2 (shuffle2 cycleNNeg0 q sums) (shuffle2 cycleNNeg1 q sums)
  let mp := shuffle2 cycleMPos q sums
  let mn := add2 (shuffle2 cycleMNeg0 q sums) (shuffle2 cycleMNeg1 q sums)
  (fun l => (np.1 l + mp.1 l + mn.2 l) - (nn.1 l + mn.1 l + mp.2 l),
   fun l => (np.2 l + mp.1 l + mp.2 l) - (nn.2 l + mn.1 l + mn.2 l))

def cyclotomicSum (q : P F) (m : V F) (a : P F) : P F :=
  let t := cyclotomicT q m
  let twice := add2 a a
  let signed := select2 56#u8 (sub2 (fun _ => 0, fun _ => 0) twice) twice
  add2 (add2 (add2 t t) t) signed

theorem cyclotomic_sum_raw {q : fp2x8.Fp2x8} {m : fp8.Fp8} {x : fp2x8.Fp2x8}
    {v : P F} {w : V F} {a : P F}
    (hq : Normal2 (fun _ => 2, fun _ => 2) q v)
    (hm : Normal (fun _ => 2) m w)
    (hx : Normal2 (fun _ => 256, fun _ => 256) x a) :
    ∃ out, fp12.Fp12.cyclotomic_sum q m x = ok out ∧
      Normal2 (fun _ => 572, fun _ => 572) out (cyclotomicSum v w a) := by
  obtain ⟨z, hz, rz⟩ := raw2_zero
  obtain ⟨re, hre, rre⟩ := raw_permute2 cycleRe hm.raw rz.1.raw
  obtain ⟨im, him, rim⟩ := raw_permute2 cycleIm hm.raw rz.1.raw
  have rs : Raw2 (fun _ => 2, fun _ => 2) 1 ⟨re, im⟩
      (shuffle cycleRe w (fun _ => 0), shuffle cycleIm w (fun _ => 0)) := by
    constructor
    · intro l; exact (rre l).mono (by dsimp [shuffle]; split_ifs <;> decide) (by decide)
    · intro l; exact (rim l).mono (by dsimp [shuffle]; split_ifs <;> decide) (by decide)
  obtain ⟨np, hnp, rnp⟩ := raw2_permute2 cycleNPos hq.raw rs
  obtain ⟨nn0, hnn0, rnn0⟩ := raw2_permute2 cycleNNeg0 hq.raw rs
  obtain ⟨nn1, hnn1, rnn1⟩ := raw2_permute2 cycleNNeg1 hq.raw rs
  obtain ⟨mp, hmp, rmp⟩ := raw2_permute2 cycleMPos hq.raw rs
  obtain ⟨mn0, hmn0, rmn0⟩ := raw2_permute2 cycleMNeg0 hq.raw rs
  obtain ⟨mn1, hmn1, rmn1⟩ := raw2_permute2 cycleMNeg1 hq.raw rs
  obtain ⟨nn, hnn, rnn⟩ := raw2_add rnn0 rnn1 (by decide)
  obtain ⟨mn, hmn, rmn⟩ := raw2_add rmn0 rmn1 (by decide)
  obtain ⟨p12, hp12, rp12⟩ := raw_offset 12#u64 (by decide)
  obtain ⟨cp0, hcp0, rcp0⟩ := raw_add rnp.1 rmp.1 (by decide)
  obtain ⟨cp, hcp, rcp⟩ := raw_add rcp0 rmn.2 (by decide)
  obtain ⟨cn0, hcn0, rcn0⟩ := raw_add rnn.1 rmn.1 (by decide)
  obtain ⟨cn, hcn, rcn⟩ := raw_add rcn0 rmp.2 (by decide)
  obtain ⟨r, hr, rr⟩ := raw_sub rcp rcn rp12 (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨ip0, hip0, rip0⟩ := raw_add rnp.2 rmp.1 (by decide)
  obtain ⟨ip, hip, rip⟩ := raw_add rip0 rmp.2 (by decide)
  obtain ⟨in0, hin0, rin0⟩ := raw_add rnn.2 rmn.1 (by decide)
  obtain ⟨inn, hinn, rinn⟩ := raw_add rin0 rmn.2 (by decide)
  obtain ⟨i, hi, ri⟩ := raw_sub rip rinn rp12 (by intro l; fin_cases l <;> decide +kernel) (by decide)
  have rt : Raw2 (fun _ => 20, fun _ => 20) 10 ⟨r, i⟩ (cyclotomicT v w) := by
    constructor
    · intro l; exact (rr l).mono (by fin_cases l <;> decide +kernel) (by decide)
    · intro l; exact (ri l).mono (by fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨twice, htwice, rtwice⟩ := raw2_add hx.raw hx.raw (by decide)
  obtain ⟨p512, hp512, rp512⟩ := raw_offset 512#u64 (by decide)
  obtain ⟨neg, hneg, rneg⟩ := raw2_sub rz.raw rtwice rp512
    (by intro l; exact ⟨le_rfl, le_rfl⟩) (by decide)
  obtain ⟨signed, hsigned, rsigned⟩ := raw2_select 56#u8 rneg rtwice
  obtain ⟨tt, htt, rtt⟩ := raw2_add rt rt (by decide)
  obtain ⟨ttt, httt, rttt⟩ := raw2_add rtt rt (by decide)
  obtain ⟨raw, hraw, rraw⟩ := raw2_add rttt rsigned (by decide)
  have rb : Raw2 (fun _ => 572, fun _ => 572) 34 raw (cyclotomicSum v w a) :=
    rraw.mono (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨out, hout, rout⟩ := raw2_normalise rb (by intro l; dsimp; decide) (by decide)
  refine ⟨out, ?_, rout⟩
  have hm512 : 2#u64 * fp12.BOUND = ok 512#u64 := by unfold fp12.BOUND; rfl
  dsimp only [cycleRe] at hre
  dsimp only [cycleIm] at him
  dsimp only [cycleNPos] at hnp
  dsimp only [cycleNNeg0] at hnn0
  dsimp only [cycleNNeg1] at hnn1
  dsimp only [cycleMPos] at hmp
  dsimp only [cycleMNeg0] at hmn0
  dsimp only [cycleMNeg1] at hmn1
  simp only [fp12.Fp12.cyclotomic_sum, hz, hre, him, hnp, hnn0, hnn1, hnn, hmp,
    hmn0, hmn1, hmn, hp12, hcp0, hcp, hcn0, hcn, hr, hip0, hip, hin0, hinn, hi,
    htwice, hm512, hp512, hneg, hsigned, htt, httt, hraw, hout, bind_tc_ok]

end LeanBlsSimd.LaneTower
