import LeanBlsSimd.LaneTower.Basic

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.LaneTower

def squareRecombine (a : Fin 6 → V F) : P F :=
  let t := clear2 (fromTriple (a 0) (a 1) (a 2))
  let u := clear2 (sub2 (fromTriple (a 3) (a 4) (a 5)) (fromTriple (a 0) (a 1) (a 2)))
  let z := (fun _ => 0, fun _ => 0)
  let pos := slices fp12.V_Z0_NEG (slices fp12.Z0_POS z u (xi2 u)) t (xi2 t)
  let tp := slices fp12.Z3_POS z t (xi2 t)
  let neg := slices fp12.V_Z0_POS (slices fp12.Z0_NEG z u (xi2 u)) t (xi2 t)
  let tn := slices fp12.Z3_NEG z t (xi2 t)
  sub2 (add2 (add2 pos tp) tp) (add2 (add2 neg tn) tn)

theorem from_square_lanes {q : Array fp8.Fp8 5#usize} {a : Fin 5 → V F}
    (hq : RowsNormal 2 q a) :
    ∃ out, fp12.Fp12.from_square_lanes q = ok out ∧
      Normal2 (fun _ => 112, fun _ => 112) out (squareRecombine (unpack6 a)) := by
  obtain ⟨m, hm, rm⟩ := unpack_six hq
  obtain ⟨t, ht, rt⟩ := raw_from_products 2#u64 (by decide)
    (rm ⟨0, by decide⟩).raw (rm ⟨1, by decide⟩).raw (rm ⟨2, by decide⟩).raw (by decide)
  obtain ⟨s, hs, rs⟩ := raw_from_products 2#u64 (by decide)
    (rm ⟨3, by decide⟩).raw (rm ⟨4, by decide⟩).raw (rm ⟨5, by decide⟩).raw (by decide)
  obtain ⟨p4, hp4, rp4⟩ := raw_offset 4#u64 (by decide)
  obtain ⟨u0, hu0, ru0⟩ := raw_sub rs.1 rt.1 rp4 (by intro l; rfl) (by decide)
  obtain ⟨p6, hp6, rp6⟩ := raw_offset 6#u64 (by decide)
  obtain ⟨u1, hu1, ru1⟩ := raw_sub rs.2 rt.2 rp6 (by intro l; rfl) (by decide)
  obtain ⟨u, hu, ru⟩ := raw2_clear (show Raw2 (fun _ => 8, fun _ => 12) 9 ⟨u0, u1⟩
      (sub2 (fromTriple (unpack6 a 3) (unpack6 a 4) (unpack6 a 5))
        (fromTriple (unpack6 a 0) (unpack6 a 1) (unpack6 a 2))) from ⟨ru0, ru1⟩)
  obtain ⟨tc, htc, rtc⟩ := raw2_clear rt
  obtain ⟨xt, hxt, rxt⟩ := raw2_xi rtc rp6 (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨p12, hp12, rp12⟩ := raw_offset 12#u64 (by decide)
  obtain ⟨xu, hxu, rxu⟩ := raw2_xi ru rp12 (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨z, hz, rz⟩ := raw2_zero
  obtain ⟨pos0, hpos0, rpos0⟩ := raw2_slices fp12.Z0_POS rz.raw ru rxu (by decide)
  obtain ⟨pos1, hpos1, rpos1⟩ := raw2_slices fp12.V_Z0_NEG rpos0 rtc rxt (by decide)
  obtain ⟨tp, htp, rtp⟩ := raw2_slices fp12.Z3_POS rz.raw rtc rxt (by decide)
  obtain ⟨pos2, hpos2, rpos2⟩ := raw2_add rpos1 rtp (by decide)
  obtain ⟨pos3, hpos3, rpos3⟩ := raw2_add rpos2 rtp (by decide)
  obtain ⟨neg0, hneg0, rneg0⟩ := raw2_slices fp12.Z0_NEG rz.raw ru rxu (by decide)
  obtain ⟨neg1, hneg1, rneg1⟩ := raw2_slices fp12.V_Z0_POS rneg0 rtc rxt (by decide)
  obtain ⟨tn, htn, rtn⟩ := raw2_slices fp12.Z3_NEG rz.raw rtc rxt (by decide)
  obtain ⟨neg2, hneg2, rneg2⟩ := raw2_add rneg1 rtn (by decide)
  obtain ⟨neg3, hneg3, rneg3⟩ := raw2_add rneg2 rtn (by decide)
  obtain ⟨p60, hp60, rp60⟩ := raw_offset 60#u64 (by decide)
  obtain ⟨raw, hraw, rraw⟩ := raw2_sub rpos3 rneg3 rp60
    (by intro l; fin_cases l <;> decide +kernel) (by decide)
  have hb : Raw2 (fun _ => 112, fun _ => 112) 191 raw (squareRecombine (unpack6 a)) :=
    rraw.mono (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨out, hout, rout⟩ := raw2_normalise hb (by intro l; dsimp; decide) (by decide)
  refine ⟨out, ?_, rout⟩
  simp only [getElem_ofArray, id_eq] at ht hs
  simp only [fp12.Fp12.from_square_lanes, hm, hp4, hp6, hp12, hp60,
    index_usize_eq m 0#usize (by decide), index_usize_eq m 1#usize (by decide),
    index_usize_eq m 2#usize (by decide), index_usize_eq m 3#usize (by decide),
    index_usize_eq m 4#usize (by decide), index_usize_eq m 5#usize (by decide),
    UScalar.ofNatCore_val_eq, ht, hs, hu0, hu1, hu, htc, hxt, hxu, hz,
    hpos0, hpos1, htp, hpos2, hpos3, hneg0, hneg1, htn, hneg2, hneg3, hraw, hout, bind_tc_ok]

end LeanBlsSimd.LaneTower
