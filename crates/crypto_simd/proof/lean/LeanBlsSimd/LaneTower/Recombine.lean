import LeanBlsSimd.LaneTower.Inputs

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.LaneTower

def fromTriple (a b c : V F) : P F :=
  (fun l => a l - b l, fun l => c l - (a l + b l))

def xi2 (a : P F) : P F := (fun l => a.1 l - a.2 l, fun l => a.1 l + a.2 l)

def productRecombine (a : Fin 9 → V F) : P F :=
  let r0 := clear2 (fromTriple (a 0) (a 1) (a 2))
  let r1 := clear2 (fromTriple (a 3) (a 4) (a 5))
  let d := clear2 (fromTriple
    (fun l => a 6 l - (a 0 l + a 3 l))
    (fun l => a 7 l - (a 1 l + a 4 l))
    (fun l => a 8 l - (a 2 l + a 5 l)))
  let z := (fun _ => 0, fun _ => 0)
  let pos := slices fp12.Z3_POS
    (slices fp12.V_Z0_POS (slices fp12.Z0_POS z r0 (xi2 r0)) r1 (xi2 r1)) d (xi2 d)
  let neg := slices fp12.Z3_NEG
    (slices fp12.V_Z0_NEG (slices fp12.Z0_NEG z r0 (xi2 r0)) r1 (xi2 r1)) d (xi2 d)
  sub2 pos neg

theorem from_product_lanes {q : Array fp8.Fp8 7#usize} {a : Fin 7 → V F}
    (hq : RowsNormal 2 q a) :
    ∃ out, fp12.Fp12.from_product_lanes q = ok out ∧
      Normal2 (fun _ => 108, fun _ => 108) out (productRecombine (unpack9 a)) := by
  obtain ⟨m, hm, rm⟩ := unpack_nine hq
  obtain ⟨p4, hp4, rp4⟩ := raw_offset 4#u64 (by decide)
  obtain ⟨s0, hs0, rs0⟩ := raw_add (rm ⟨0, by decide⟩).raw (rm ⟨3, by decide⟩).raw (by decide)
  obtain ⟨d0, hd0, rd0⟩ := raw_sub (rm ⟨6, by decide⟩).raw rs0 rp4 (by intro l; decide) (by decide)
  obtain ⟨s1, hs1, rs1⟩ := raw_add (rm ⟨1, by decide⟩).raw (rm ⟨4, by decide⟩).raw (by decide)
  obtain ⟨d1, hd1, rd1⟩ := raw_sub (rm ⟨7, by decide⟩).raw rs1 rp4 (by intro l; decide) (by decide)
  obtain ⟨s2, hs2, rs2⟩ := raw_add (rm ⟨2, by decide⟩).raw (rm ⟨5, by decide⟩).raw (by decide)
  obtain ⟨d2, hd2, rd2⟩ := raw_sub (rm ⟨8, by decide⟩).raw rs2 rp4 (by intro l; decide) (by decide)
  obtain ⟨raw0, hraw0, rraw0⟩ := raw_from_products 2#u64 (by decide)
    (rm ⟨0, by decide⟩).raw (rm ⟨1, by decide⟩).raw (rm ⟨2, by decide⟩).raw (by decide)
  obtain ⟨r0, hr0, rr0⟩ := raw2_clear rraw0
  obtain ⟨raw1, hraw1, rraw1⟩ := raw_from_products 2#u64 (by decide)
    (rm ⟨3, by decide⟩).raw (rm ⟨4, by decide⟩).raw (rm ⟨5, by decide⟩).raw (by decide)
  obtain ⟨r1, hr1, rr1⟩ := raw2_clear rraw1
  obtain ⟨rawd, hrawd, rrawd⟩ := raw_from_products 6#u64 (by decide) rd0 rd1 rd2 (by decide)
  obtain ⟨d, hd, rd⟩ := raw2_clear rrawd
  obtain ⟨p6, hp6, rp6⟩ := raw_offset 6#u64 (by decide)
  obtain ⟨xr0, hxr0, rxr0⟩ := raw2_xi rr0 rp6 (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨xr1, hxr1, rxr1⟩ := raw2_xi rr1 rp6 (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨p18, hp18, rp18⟩ := raw_offset 18#u64 (by decide)
  obtain ⟨xd, hxd, rxd⟩ := raw2_xi rd rp18 (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨z, hz, rz⟩ := raw2_zero
  obtain ⟨pos0, hpos0, rpos0⟩ := raw2_slices fp12.Z0_POS rz.raw rr0 rxr0 (by decide)
  obtain ⟨pos1, hpos1, rpos1⟩ := raw2_slices fp12.V_Z0_POS rpos0 rr1 rxr1 (by decide)
  obtain ⟨pos, hpos, rpos⟩ := raw2_slices fp12.Z3_POS rpos1 rd rxd (by decide)
  obtain ⟨neg0, hneg0, rneg0⟩ := raw2_slices fp12.Z0_NEG rz.raw rr0 rxr0 (by decide)
  obtain ⟨neg1, hneg1, rneg1⟩ := raw2_slices fp12.V_Z0_NEG rneg0 rr1 rxr1 (by decide)
  obtain ⟨neg, hneg, rneg⟩ := raw2_slices fp12.Z3_NEG rneg1 rd rxd (by decide)
  obtain ⟨p60, hp60, rp60⟩ := raw_offset 60#u64 (by decide)
  obtain ⟨raw, hraw, rraw⟩ := raw2_sub rpos rneg rp60
    (by intro l; fin_cases l <;> decide +kernel) (by decide)
  have hb : Raw2 (fun _ => 108, fun _ => 108) 183 raw
      (productRecombine (unpack9 a)) := by
    exact rraw.mono (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨out, hout, rout⟩ := raw2_normalise hb (by intro l; dsimp; decide) (by decide)
  have ht0 : Array.index_usize (Array.make 3#usize [d0, d1, d2] (by rfl)) 0#usize = ok d0 := rfl
  have ht1 : Array.index_usize (Array.make 3#usize [d0, d1, d2] (by rfl)) 1#usize = ok d1 := rfl
  have ht2 : Array.index_usize (Array.make 3#usize [d0, d1, d2] (by rfl)) 2#usize = ok d2 := rfl
  refine ⟨out, ?_, rout⟩
  simp only [getElem_ofArray, id_eq] at hs0 hd0 hs1 hd1 hs2 hd2 hraw0 hraw1
  simp only [fp12.Fp12.from_product_lanes, hm, hp4, hp6, hp18, hp60, ht0, ht1, ht2,
    index_usize_eq m 0#usize (by decide), index_usize_eq m 1#usize (by decide),
    index_usize_eq m 2#usize (by decide), index_usize_eq m 3#usize (by decide),
    index_usize_eq m 4#usize (by decide), index_usize_eq m 5#usize (by decide),
    index_usize_eq m 6#usize (by decide), index_usize_eq m 7#usize (by decide),
    index_usize_eq m 8#usize (by decide), UScalar.ofNatCore_val_eq,
    hs0, hd0, hs1, hd1, hs2, hd2, hraw0, hr0, hraw1, hr1, hrawd, hd,
    hxr0, hxr1, hxd, hz, hpos0, hpos1, hpos, hneg0, hneg1, hneg, hraw, hout, bind_tc_ok]

end LeanBlsSimd.LaneTower
