import LeanBlsSimd.LaneTower.InverseStages

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

def invComponents : Array I64 8#usize := Array.make 8#usize
  [0#i64, 8#i64, 0#i64, 8#i64, 0#i64, 8#i64, 0#i64, 8#i64] (by rfl)
def invSwap : Array I64 8#usize := Array.make 8#usize
  [1#i64, 0#i64, 1#i64, 0#i64, 1#i64, 0#i64, 1#i64, 0#i64] (by rfl)
def invEmbed : Array I64 8#usize := Array.make 8#usize
  [0#i64, 1#i64, 2#i64, fp12.Z, fp12.Z, fp12.Z, fp12.Z, fp12.Z] (by rfl)

def repeatFirst (a : V F) : V F := shuffle (Array.repeat 8#usize 0#i64) a a

def determinantSquares (a : P F) : V F :=
  let c := shuffle invComponents a.1 a.2
  fun l => c l * c l

def determinantNorm (a : P F) : V F :=
  let s := determinantSquares a
  fun l => s l + shuffle invSwap s s l

def determinantInverse (a : P F) : P F :=
  let inv := repeatFirst (fun l => (determinantNorm a l)⁻¹)
  (fun l => repeatFirst a.1 l * inv l,
   fun l => repeatFirst (fun l => 0 - a.2 l) l * inv l)

def inverseEmbed (t d : P F) : P F :=
  shuffle2 invEmbed (mul2 t (determinantInverse d)) (fun _ => 0, fun _ => 0)

noncomputable def determinantInverseRun (det : fp2x8.Fp2x8) : Result fp2x8.Fp2x8 := do
  let c ← fp8.Fp8.permute2 det.c0 det.c1 invComponents
  let sq ← fp8.Fp8.mul c c
  let sw ← fp8.Fp8.permute sq invSwap
  let s ← fp8.Fp8.add_raw sq sw
  let norm ← fp8.Fp8.normalise s
  let i ← fp8.Fp8.inverse norm
  let inv ← fp8.Fp8.permute i (Array.repeat 8#usize 0#i64)
  let re ← fp8.Fp8.permute det.c0 (Array.repeat 8#usize 0#i64)
  let re1 ← fp8.Fp8.mul re inv
  let z ← fp8.Fp8.zero
  let p30 ← fp8.Fp8.multiple_of_p 30#u64
  let ni ← fp8.Fp8.sub_raw z det.c1 p30
  let ni1 ← fp8.Fp8.normalise ni
  let im ← fp8.Fp8.permute ni1 (Array.repeat 8#usize 0#i64)
  let im1 ← fp8.Fp8.mul im inv
  ok ⟨re1, im1⟩

noncomputable def inverseEmbedRun (t d : fp2x8.Fp2x8) : Result fp2x8.Fp2x8 := do
  let di ← determinantInverseRun d
  let r ← fp12.fp2_products t di
  let z ← fp12.zero2
  fp2x8.Fp2x8.permute2 r z invEmbed

theorem determinant_inverse_raw {x : fp2x8.Fp2x8} {a : P F}
    (hx : Normal2 (fun _ => 30, fun _ => 30) x a) :
    ∃ out, determinantInverseRun x = ok out ∧
      Normal2 (fun _ => 2, fun _ => 2) out (determinantInverse a) := by
  obtain ⟨c, hc, rc⟩ := normal_permute2 invComponents hx.1 hx.2
  have rc' : Normal (fun _ => 30) c (shuffle invComponents a.1 a.2) :=
    rc.mono (by intro l; simp [shuffle])
  obtain ⟨sq, hsq, rsq⟩ := raw_mul rc' rc' (by intro l; norm_num)
  obtain ⟨sw, hsw, rsw⟩ := normal_permute invSwap rsq
  have rsw' : Normal (fun _ => 2) sw (shuffle invSwap (determinantSquares a) (determinantSquares a)) :=
    rsw.mono (by intro l; simp [shuffle])
  obtain ⟨s, hs, rs⟩ := raw_add rsq.raw rsw'.raw (by decide)
  have rs' : Raw (fun _ => 4) 2 s (determinantNorm a) := rs
  obtain ⟨norm, hnorm, rnorm⟩ := raw_normalise rs' (by intro l; norm_num) (by decide)
  obtain ⟨i, hi, ri⟩ := inverse_raw rnorm
  obtain ⟨inv, hinv, rinv⟩ := normal_permute (Array.repeat 8#usize 0#i64) ri
  have rinv' : Normal (fun _ => 2) inv (repeatFirst (fun l => (determinantNorm a l)⁻¹)) :=
    rinv.mono (by intro l; simp [shuffle])
  obtain ⟨re, hre, rre⟩ := normal_permute (Array.repeat 8#usize 0#i64) hx.1
  have rre' : Normal (fun _ => 30) re (repeatFirst a.1) :=
    rre.mono (by intro l; simp [shuffle])
  obtain ⟨re1, hre1, rre1⟩ := raw_mul rre' rinv' (by intro l; norm_num)
  obtain ⟨z, hz, rz⟩ := raw_zero
  obtain ⟨p30, hp30, rp30⟩ := raw_offset 30#u64 (by decide)
  obtain ⟨ni, hni, rni⟩ := raw_sub rz.raw hx.2.raw rp30 (by intro l; rfl) (by decide)
  have rni' : Raw (fun _ => 30) 3 ni (fun l => 0 - a.2 l) := rni
  obtain ⟨ni1, hni1, rni1⟩ := raw_normalise rni' (by intro l; norm_num) (by decide)
  obtain ⟨im, him, rim⟩ := normal_permute (Array.repeat 8#usize 0#i64) rni1
  have rim' : Normal (fun _ => 30) im (repeatFirst (fun l => 0 - a.2 l)) :=
    rim.mono (by intro l; simp [shuffle])
  obtain ⟨im1, him1, rim1⟩ := raw_mul rim' rinv' (by intro l; norm_num)
  refine ⟨⟨re1, im1⟩, ?_, rre1, rim1⟩
  simp only [determinantInverseRun, hc, hsq, hsw, hs, hnorm, hi, hinv, hre, hre1,
    hz, hp30, hni, hni1, him, him1, bind_tc_ok]

theorem inverse_embed_raw {t d : fp2x8.Fp2x8} {a b : P F}
    (ht : Normal2 (fun _ => 18, fun _ => 18) t a)
    (hd : Normal2 (fun _ => 30, fun _ => 30) d b) :
    ∃ out, inverseEmbedRun t d = ok out ∧
      Normal2 (fun _ => 6, fun _ => 6) out (inverseEmbed a b) := by
  obtain ⟨di, hdi, rdi⟩ := determinant_inverse_raw hd
  obtain ⟨r, hr, rr⟩ := raw2_products ht rdi (by intro l; norm_num) (by intro l; norm_num)
  obtain ⟨z, hz, rz⟩ := raw2_zero
  obtain ⟨out, hout, rout⟩ := normal2_permute2 invEmbed rr rz
  refine ⟨out, ?_, rout.mono ?_⟩
  · simp only [inverseEmbedRun, hdi, hr, hz, hout, bind_tc_ok]
  · intro l; dsimp [shuffle2, shuffle]; split_ifs <;> decide

end LeanBlsSimd.LaneTower
