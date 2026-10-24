import LeanBlsSimd.LaneTower.LineRecombine

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

def lineLeftA0 : Array I64 8#usize := Array.make 8#usize
  [0#i64, 1#i64, 0#i64, 0#i64, 1#i64, 5#i64, 3#i64, 4#i64] (by rfl)

def lineLeftA1 : Array I64 8#usize := Array.make 8#usize
  [fp12.Z, fp12.Z, 1#i64, 2#i64, 2#i64, fp12.Z, fp12.Z, fp12.Z] (by rfl)

def lineRightA0 : Array I64 8#usize := Array.make 8#usize
  [0#i64, 1#i64, 0#i64, 0#i64, 1#i64, 2#i64, 2#i64, 2#i64] (by rfl)

def lineRightA1 : Array I64 8#usize := Array.make 8#usize
  [fp12.Z, fp12.Z, 1#i64, fp12.Z, fp12.Z, fp12.Z, fp12.Z, fp12.Z] (by rfl)

def lineLeftSum : Array I64 8#usize := Array.make 8#usize
  [3#i64, 4#i64, 5#i64, fp12.Z, fp12.Z, fp12.Z, fp12.Z, fp12.Z] (by rfl)

def lineLeftB0 : Array I64 8#usize := Array.make 8#usize
  [0#i64, 1#i64, 0#i64, 0#i64, 1#i64, fp12.Z, fp12.Z, fp12.Z] (by rfl)

def lineLeftB1 : Array I64 8#usize := Array.make 8#usize
  [fp12.Z, fp12.Z, 1#i64, 2#i64, 2#i64, fp12.Z, fp12.Z, fp12.Z] (by rfl)

def lineRightSum : Array I64 8#usize := Array.make 8#usize
  [fp12.Z, 2#i64, fp12.Z, fp12.Z, fp12.Z, fp12.Z, fp12.Z, fp12.Z] (by rfl)

def lineRightB0 : Array I64 8#usize := Array.make 8#usize
  [0#i64, 1#i64, 0#i64, 0#i64, 1#i64, fp12.Z, fp12.Z, fp12.Z] (by rfl)

def lineRightB1 : Array I64 8#usize := Array.make 8#usize
  [fp12.Z, fp12.Z, 1#i64, fp12.Z, fp12.Z, fp12.Z, fp12.Z, fp12.Z] (by rfl)

def lineGroupA (a : P F) (i j : Array I64 8#usize) : P F :=
  add2 (shuffle2 i a (fun _ => 0, fun _ => 0)) (shuffle2 j a (fun _ => 0, fun _ => 0))

def lineGroupB (a : P F) (s i j : Array I64 8#usize) : P F :=
  lineGroupA (add2 a (shuffle2 s a (fun _ => 0, fun _ => 0))) i j

def lineLeft (a : P F) : Fin 5 → V F :=
  lineOperands (lineGroupA a lineLeftA0 lineLeftA1)
    (lineGroupB a lineLeftSum lineLeftB0 lineLeftB1)

def lineRight (a : P F) : Fin 5 → V F :=
  lineOperands (lineGroupA a lineRightA0 lineRightA1)
    (lineGroupB a lineRightSum lineRightB0 lineRightB1)

def lineValues (a b : P F) : P F :=
  lineRecombine (fun j l => lineLeft a j l * lineRight b j l)

theorem mul_by_line_raw {x y : fp2x8.Fp2x8} {a b : P F}
    (hx : Normal2 (fun _ => 256, fun _ => 256) x a)
    (hy : Normal2 (fun _ => 256, fun _ => 256) y b) :
    ∃ out, fp12.Fp12.mul_by_line x y = ok out ∧
      Normal2 (fun _ => 120, fun _ => 120) out (lineValues a b) := by
  obtain ⟨z, hz, rz⟩ := raw2_zero
  obtain ⟨lefta0, hlefta0, rlefta0⟩ := raw2_permute2 lineLeftA0 hx.raw rz.raw
  obtain ⟨lefta1, hlefta1, rlefta1⟩ := raw2_permute2 lineLeftA1 hx.raw rz.raw
  obtain ⟨lefta, hlefta, rlefta⟩ := raw2_add rlefta0 rlefta1 (by decide)
  obtain ⟨lefttail, hlefttail, rlefttail⟩ := raw2_permute2 lineLeftSum hx.raw rz.raw
  obtain ⟨leftsum, hleftsum, rleftsum⟩ := raw2_add hx.raw rlefttail (by decide)
  obtain ⟨leftb0, hleftb0, rleftb0⟩ := raw2_permute2 lineLeftB0 rleftsum rz.raw
  obtain ⟨leftb1, hleftb1, rleftb1⟩ := raw2_permute2 lineLeftB1 rleftsum rz.raw
  obtain ⟨leftb, hleftb, rleftb⟩ := raw2_add rleftb0 rleftb1 (by decide)
  have rlefta' : Raw2 (fun _ => 1024, fun _ => 1024) 4 lefta (lineGroupA a lineLeftA0 lineLeftA1) :=
    rlefta.mono (by intro l; fin_cases l <;> decide +kernel) (by decide)
  have rleftb' : Raw2 (fun _ => 1024, fun _ => 1024) 4 leftb (lineGroupB a lineLeftSum lineLeftB0 lineLeftB1) :=
    rleftb.mono (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨left, hleft, rleft⟩ := line_operands rlefta' rleftb'
  obtain ⟨righta0, hrighta0, rrighta0⟩ := raw2_permute2 lineRightA0 hy.raw rz.raw
  obtain ⟨righta1, hrighta1, rrighta1⟩ := raw2_permute2 lineRightA1 hy.raw rz.raw
  obtain ⟨righta, hrighta, rrighta⟩ := raw2_add rrighta0 rrighta1 (by decide)
  obtain ⟨righttail, hrighttail, rrighttail⟩ := raw2_permute2 lineRightSum hy.raw rz.raw
  obtain ⟨rightsum, hrightsum, rrightsum⟩ := raw2_add hy.raw rrighttail (by decide)
  obtain ⟨rightb0, hrightb0, rrightb0⟩ := raw2_permute2 lineRightB0 rrightsum rz.raw
  obtain ⟨rightb1, hrightb1, rrightb1⟩ := raw2_permute2 lineRightB1 rrightsum rz.raw
  obtain ⟨rightb, hrightb, rrightb⟩ := raw2_add rrightb0 rrightb1 (by decide)
  have rrighta' : Raw2 (fun _ => 1024, fun _ => 1024) 4 righta (lineGroupA b lineRightA0 lineRightA1) :=
    rrighta.mono (by intro l; fin_cases l <;> decide +kernel) (by decide)
  have rrightb' : Raw2 (fun _ => 1024, fun _ => 1024) 4 rightb (lineGroupB b lineRightSum lineRightB0 lineRightB1) :=
    rrightb.mono (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨right, hright, rright⟩ := line_operands rrighta' rrightb'
  obtain ⟨z0, hz0, _⟩ := raw_zero
  obtain ⟨q, hq, rq⟩ := product_loop_start rleft rright (by decide) (Array.repeat 5#usize z0)
  obtain ⟨out, hout, rout⟩ := from_line_lanes rq
  refine ⟨out, ?_, rout⟩
  dsimp only [lineLeftA0] at hlefta0
  dsimp only [lineLeftA1] at hlefta1
  dsimp only [lineLeftSum] at hlefttail
  dsimp only [lineLeftB0] at hleftb0
  dsimp only [lineLeftB1] at hleftb1
  dsimp only [lineRightA0] at hrighta0
  dsimp only [lineRightA1] at hrighta1
  dsimp only [lineRightSum] at hrighttail
  dsimp only [lineRightB0] at hrightb0
  dsimp only [lineRightB1] at hrightb1
  simp only [fp12.Fp12.mul_by_line, hz, hlefta0, hlefta1, hlefta, hlefttail, hleftsum, hleftb0, hleftb1, hleftb, hleft, hrighta0, hrighta1, hrighta, hrighttail, hrightsum, hrightb0, hrightb1, hrightb, hright, hz0, line_loop_eq, hq, hout, bind_tc_ok]

end LeanBlsSimd.LaneTower
