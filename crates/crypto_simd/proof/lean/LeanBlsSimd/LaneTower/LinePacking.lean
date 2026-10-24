import LeanBlsSimd.LaneTower.Square

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.LaneTower

def linePack0 : Array I64 8#usize := Array.make 8#usize
  [0#i64, 1#i64, 2#i64, 3#i64, 4#i64, 8#i64, 9#i64, 10#i64] (by rfl)

def linePack1 : Array I64 8#usize := Array.make 8#usize
  [0#i64, 1#i64, 2#i64, 3#i64, 4#i64, 11#i64, 12#i64, 13#i64] (by rfl)

def lineTail : Array I64 8#usize := Array.make 8#usize
  [5#i64, 6#i64, 7#i64, 13#i64, 14#i64, 15#i64, 15#i64, 15#i64] (by rfl)

def lineOperands (a b : P F) : Fin 5 → V F :=
  ![a.1, a.2, fun l => a.1 l + a.2 l,
    shuffle linePack0 b.1 (fun l => b.1 l + b.2 l),
    shuffle linePack1 b.2 (fun l => b.1 l + b.2 l)]

theorem line_operands {x y : fp2x8.Fp2x8} {a b : P F}
    (hx : Raw2 (fun _ => 1024, fun _ => 1024) 4 x a)
    (hy : Raw2 (fun _ => 1024, fun _ => 1024) 4 y b) :
    ∃ out, fp12.line_operands x y = ok out ∧ RowsNormal 2048 out (lineOperands a b) := by
  obtain ⟨r, hr, rr⟩ := fp2_operands hx (by decide)
  obtain ⟨s, hs, rs⟩ := fp2_operands hy (by decide)
  obtain ⟨r0, hr0, rr0⟩ := raw_normalise (rr ⟨0, by decide⟩) (by intro l; decide) (by decide)
  obtain ⟨r1, hr1, rr1⟩ := raw_normalise (rr ⟨1, by decide⟩) (by intro l; decide) (by decide)
  obtain ⟨r2, hr2, rr2⟩ := raw_normalise (rr ⟨2, by decide⟩) (by intro l; decide) (by decide)
  obtain ⟨p0, hp0, rp0⟩ := raw_permute2 linePack0 (rs ⟨0, by decide⟩) (rs ⟨2, by decide⟩)
  obtain ⟨p1, hp1, rp1⟩ := raw_permute2 linePack1 (rs ⟨1, by decide⟩) (rs ⟨2, by decide⟩)
  have rb0 : Raw (fun _ => 2048) 8 p0 (shuffle linePack0 b.1 (fun l => b.1 l + b.2 l)) := by
    intro l
    exact (rp0 l).mono (by dsimp [shuffle]; split_ifs <;> rfl) (by decide)
  have rb1 : Raw (fun _ => 2048) 8 p1 (shuffle linePack1 b.2 (fun l => b.1 l + b.2 l)) := by
    intro l
    exact (rp1 l).mono (by dsimp [shuffle]; split_ifs <;> rfl) (by decide)
  obtain ⟨r3, hr3, rr3⟩ := raw_normalise rb0 (by intro l; decide) (by decide)
  obtain ⟨r4, hr4, rr4⟩ := raw_normalise rb1 (by intro l; decide) (by decide)
  refine ⟨Array.make 5#usize [r0, r1, r2, r3, r4] (by rfl), ?_, ?_⟩
  · simp only [getElem_ofArray, id_eq] at hr0 hr1 hr2 hp0 hp1
    dsimp only [linePack0, linePack1] at hp0 hp1
    simp only [fp12.line_operands, hr, hs, bind_tc_ok,
      index_usize_eq r 0#usize (by decide), index_usize_eq r 1#usize (by decide),
      index_usize_eq r 2#usize (by decide), index_usize_eq s 0#usize (by decide),
      index_usize_eq s 1#usize (by decide), index_usize_eq s 2#usize (by decide),
      UScalar.ofNatCore_val_eq, hr0, hr1, hr2, hp0, hp1, hr3, hr4]
  · intro j
    fin_cases j
    · exact rr0
    · exact rr1
    · exact rr2
    · exact rr3
    · exact rr4

end LeanBlsSimd.LaneTower
