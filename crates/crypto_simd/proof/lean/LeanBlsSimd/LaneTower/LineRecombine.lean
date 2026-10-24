import LeanBlsSimd.LaneTower.LinePacking

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.LaneTower

def lineNPos0 : Array I64 8#usize := Array.make 8#usize
  [0#i64, 2#i64, 3#i64, 8#i64, 10#i64, 11#i64, 13#i64, 13#i64] (by rfl)

def lineNPos1 : Array I64 8#usize := Array.make 8#usize
  [13#i64, 13#i64, 1#i64, 13#i64, 13#i64, 9#i64, 13#i64, 13#i64] (by rfl)

def lineNPos2 : Array I64 8#usize := Array.make 8#usize
  [13#i64, 13#i64, 6#i64, 13#i64, 13#i64, 13#i64, 13#i64, 13#i64] (by rfl)

def lineNNeg0 : Array I64 8#usize := Array.make 8#usize
  [13#i64, 0#i64, 0#i64, 13#i64, 8#i64, 8#i64, 13#i64, 13#i64] (by rfl)

def lineNNeg1 : Array I64 8#usize := Array.make 8#usize
  [13#i64, 1#i64, 13#i64, 13#i64, 9#i64, 7#i64, 13#i64, 13#i64] (by rfl)

def lineNNeg2 : Array I64 8#usize := Array.make 8#usize
  [13#i64, 13#i64, 13#i64, 13#i64, 6#i64, 13#i64, 13#i64, 13#i64] (by rfl)

def lineMPos0 : Array I64 8#usize := Array.make 8#usize
  [4#i64, 5#i64, 13#i64, 12#i64, 13#i64, 13#i64, 13#i64, 13#i64] (by rfl)

def lineMPos1 : Array I64 8#usize := Array.make 8#usize
  [7#i64, 13#i64, 13#i64, 13#i64, 13#i64, 13#i64, 13#i64, 13#i64] (by rfl)

def lineMNeg0 : Array I64 8#usize := Array.make 8#usize
  [1#i64, 13#i64, 13#i64, 9#i64, 13#i64, 13#i64, 13#i64, 13#i64] (by rfl)

def lineMNeg1 : Array I64 8#usize := Array.make 8#usize
  [13#i64, 13#i64, 13#i64, 5#i64, 13#i64, 13#i64, 13#i64, 13#i64] (by rfl)

def lineRecombine (a : Fin 5 → V F) : P F :=
  let ra := fromTriple (a 0) (a 1) (a 2)
  let rb := fromTriple (a 3) (a 4) (shuffle lineTail (a 3) (a 4))
  let db := select2 224#u8 (sub2 rb ra) (fun _ => 0, fun _ => 0)
  let np := add2 (add2 (shuffle2 lineNPos0 ra db) (shuffle2 lineNPos1 ra db)) (shuffle2 lineNPos2 ra db)
  let nn := add2 (add2 (shuffle2 lineNNeg0 ra db) (shuffle2 lineNNeg1 ra db)) (shuffle2 lineNNeg2 ra db)
  let mp := add2 (shuffle2 lineMPos0 ra db) (shuffle2 lineMPos1 ra db)
  let mn := add2 (shuffle2 lineMNeg0 ra db) (shuffle2 lineMNeg1 ra db)
  (fun l => (np.1 l + mp.1 l + mn.2 l) - (nn.1 l + mn.1 l + mp.2 l),
   fun l => (np.2 l + mp.1 l + mp.2 l) - (nn.2 l + mn.1 l + mn.2 l))

theorem from_line_lanes {q : Array fp8.Fp8 5#usize} {a : Fin 5 → V F}
    (hq : RowsNormal 2 q a) :
    ∃ out, fp12.Fp12.from_line_lanes q = ok out ∧
      Normal2 (fun _ => 120, fun _ => 120) out (lineRecombine a) := by
  obtain ⟨z, hz, rz⟩ := raw2_zero
  obtain ⟨ra, hra, rra⟩ := raw_from_products 2#u64 (by decide)
    (hq ⟨0, by decide⟩).raw (hq ⟨1, by decide⟩).raw (hq ⟨2, by decide⟩).raw (by decide)
  obtain ⟨b2, hb2, rb2⟩ := raw_permute2 lineTail (hq ⟨3, by decide⟩).raw (hq ⟨4, by decide⟩).raw
  have rb2' : Raw (fun _ => 2) 1 b2 (shuffle lineTail (a 3) (a 4)) := by
    intro l
    exact (rb2 l).mono (by dsimp [shuffle]; split_ifs <;> rfl) (by decide)
  obtain ⟨rb, hrb, rrb⟩ := raw_from_products 2#u64 (by decide)
    (hq ⟨3, by decide⟩).raw (hq ⟨4, by decide⟩).raw rb2' (by decide)
  obtain ⟨p4, hp4, rp4⟩ := raw_offset 4#u64 (by decide)
  obtain ⟨d0, hd0, rd0⟩ := raw_sub rrb.1 rra.1 rp4 (by intro l; rfl) (by decide)
  obtain ⟨p6, hp6, rp6⟩ := raw_offset 6#u64 (by decide)
  obtain ⟨d1, hd1, rd1⟩ := raw_sub rrb.2 rra.2 rp6 (by intro l; rfl) (by decide)
  obtain ⟨db, hdb, rdb⟩ := raw2_select 224#u8
    (show Raw2 (fun _ => 8, fun _ => 12) 9 ⟨d0, d1⟩
      (sub2 (fromTriple (a 3) (a 4) (shuffle lineTail (a 3) (a 4))) (fromTriple (a 0) (a 1) (a 2))) from ⟨rd0, rd1⟩) rz.raw
  obtain ⟨npos0, hnpos0, rnpos0⟩ := raw2_permute2 lineNPos0 rra rdb
  obtain ⟨npos1, hnpos1, rnpos1⟩ := raw2_permute2 lineNPos1 rra rdb
  obtain ⟨npos2, hnpos2, rnpos2⟩ := raw2_permute2 lineNPos2 rra rdb
  obtain ⟨npos, hnpos, rnpos⟩ := raw2_add rnpos0 rnpos1 (by decide)
  obtain ⟨nposf, hnposf, rnposf⟩ := raw2_add rnpos rnpos2 (by decide)
  obtain ⟨nneg0, hnneg0, rnneg0⟩ := raw2_permute2 lineNNeg0 rra rdb
  obtain ⟨nneg1, hnneg1, rnneg1⟩ := raw2_permute2 lineNNeg1 rra rdb
  obtain ⟨nneg2, hnneg2, rnneg2⟩ := raw2_permute2 lineNNeg2 rra rdb
  obtain ⟨nneg, hnneg, rnneg⟩ := raw2_add rnneg0 rnneg1 (by decide)
  obtain ⟨nnegf, hnnegf, rnnegf⟩ := raw2_add rnneg rnneg2 (by decide)
  obtain ⟨mpos0, hmpos0, rmpos0⟩ := raw2_permute2 lineMPos0 rra rdb
  obtain ⟨mpos1, hmpos1, rmpos1⟩ := raw2_permute2 lineMPos1 rra rdb
  obtain ⟨mpos, hmpos, rmpos⟩ := raw2_add rmpos0 rmpos1 (by decide)
  obtain ⟨mneg0, hmneg0, rmneg0⟩ := raw2_permute2 lineMNeg0 rra rdb
  obtain ⟨mneg1, hmneg1, rmneg1⟩ := raw2_permute2 lineMNeg1 rra rdb
  obtain ⟨mneg, hmneg, rmneg⟩ := raw2_add rmneg0 rmneg1 (by decide)
  obtain ⟨cp0, hcp0, rcp0⟩ := raw_add rnposf.1 rmpos.1 (by decide)
  obtain ⟨cp, hcp, rcp⟩ := raw_add rcp0 rmneg.2 (by decide)
  obtain ⟨cn0, hcn0, rcn0⟩ := raw_add rnnegf.1 rmneg.1 (by decide)
  obtain ⟨cn, hcn, rcn⟩ := raw_add rcn0 rmpos.2 (by decide)
  obtain ⟨ip0, hip0, rip0⟩ := raw_add rnposf.2 rmpos.1 (by decide)
  obtain ⟨ip, hip, rip⟩ := raw_add rip0 rmpos.2 (by decide)
  obtain ⟨in0, hin0, rin0⟩ := raw_add rnnegf.2 rmneg.1 (by decide)
  obtain ⟨inn, hinn, rinn⟩ := raw_add rin0 rmneg.2 (by decide)
  obtain ⟨p66, hp66, rp66⟩ := raw_offset 66#u64 (by decide)
  obtain ⟨re, hre, rre⟩ := raw_sub rcp rcn rp66 (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨im, him, rim⟩ := raw_sub rip rinn rp66 (by intro l; fin_cases l <;> decide +kernel) (by decide)
  have rr : Raw (fun _ => 120) 127 re (lineRecombine a).1 := by
    intro l
    exact (rre l).mono (by fin_cases l <;> decide +kernel) (by decide)
  have ri : Raw (fun _ => 120) 127 im (lineRecombine a).2 := by
    intro l
    exact (rim l).mono (by fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨out0, hout0, rout0⟩ := raw_normalise rr (by intro l; decide) (by decide)
  obtain ⟨out1, hout1, rout1⟩ := raw_normalise ri (by intro l; decide) (by decide)
  refine ⟨⟨out0, out1⟩, ?_, rout0, rout1⟩
  simp only [getElem_ofArray, id_eq] at hra hb2 hrb
  dsimp only [lineTail] at hb2
  dsimp only [lineNPos0] at hnpos0
  dsimp only [lineNPos1] at hnpos1
  dsimp only [lineNPos2] at hnpos2
  dsimp only [lineNNeg0] at hnneg0
  dsimp only [lineNNeg1] at hnneg1
  dsimp only [lineNNeg2] at hnneg2
  dsimp only [lineMPos0] at hmpos0
  dsimp only [lineMPos1] at hmpos1
  dsimp only [lineMNeg0] at hmneg0
  dsimp only [lineMNeg1] at hmneg1
  simp only [fp12.Fp12.from_line_lanes,
    index_usize_eq q 0#usize (by decide),
    index_usize_eq q 1#usize (by decide),
    index_usize_eq q 2#usize (by decide),
    index_usize_eq q 3#usize (by decide),
    index_usize_eq q 4#usize (by decide),
    UScalar.ofNatCore_val_eq, hz, hra, hb2, hrb, hp4, hd0, hp6, hd1, hdb, hnpos0, hnpos1, hnpos2, hnpos, hnposf, hnneg0, hnneg1, hnneg2, hnneg, hnnegf, hmpos0, hmpos1, hmpos, hmneg0, hmneg1, hmneg, hcp0, hcp, hcn0, hcn, hip0, hip, hin0, hinn, hp66, hre, him, hout0, hout1, bind_tc_ok]

end LeanBlsSimd.LaneTower
