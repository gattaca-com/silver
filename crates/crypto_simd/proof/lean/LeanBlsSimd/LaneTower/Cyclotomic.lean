import LeanBlsSimd.LaneTower.CyclotomicSum

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

def cycleInput0 : Array I64 8#usize := Array.make 8#usize
  [0#i64, 3#i64, 1#i64, 4#i64, 2#i64, 5#i64, 0#i64, fp12.Z] (by rfl)

def cycleInput1 : Array I64 8#usize := Array.make 8#usize
  [fp12.Z, fp12.Z, fp12.Z, fp12.Z, fp12.Z, fp12.Z, 4#i64, fp12.Z] (by rfl)

def cycleSum0 : Array I64 8#usize := Array.make 8#usize
  [3#i64, 1#i64, fp12.Z, fp12.Z, fp12.Z, fp12.Z, fp12.Z, fp12.Z] (by rfl)

def cycleSum1 : Array I64 8#usize := Array.make 8#usize
  [2#i64, 5#i64, fp12.Z, fp12.Z, fp12.Z, fp12.Z, fp12.Z, fp12.Z] (by rfl)

def cyclePack : Array I64 8#usize := Array.make 8#usize
  [0#i64, 8#i64, 1#i64, 9#i64, 7#i64, 7#i64, 7#i64, 7#i64] (by rfl)

def cycleInput (a : P F) : P F :=
  add2 (shuffle2 cycleInput0 a (fun _ => 0, fun _ => 0))
    (shuffle2 cycleInput1 a (fun _ => 0, fun _ => 0))

def cycleSums (a : P F) : P F :=
  add2 (shuffle2 cycleSum0 a (fun _ => 0, fun _ => 0))
    (shuffle2 cycleSum1 a (fun _ => 0, fun _ => 0))

def cycleQ (a : P F) : P F :=
  let u := cycleInput a
  (fun l => (u.1 l + u.2 l) * (u.1 l - u.2 l), fun l => u.1 l * (u.2 l + u.2 l))

def cycleM (a : P F) : V F :=
  let s := cycleSums a
  let left := shuffle cyclePack (fun l => s.1 l + s.2 l) s.1
  let right := shuffle cyclePack (fun l => s.1 l - s.2 l) (fun l => s.2 l + s.2 l)
  fun l => left l * right l

def cyclotomicValues (a : P F) : P F := cyclotomicSum (cycleQ a) (cycleM a) a

theorem strict_cond_sub {k c : ℕ} {x o : fp8.Fp8} {a : V F}
    (hx : Strict k x a) (ho : offset c o) (hk : k ≤ 2 * c) :
    ∃ out, fp8.Fp8.cond_sub x o = ok out ∧ Strict c out a := by
  refine ⟨_, Fp8.cond_sub_refines x o, ?_⟩
  intro l
  simpa only [ofFp8_toFp8] using (hx l).cond_sub (ho l) hk

theorem strict2_cond_sub {k c : ℕ} {x : fp2x8.Fp2x8} {o : fp8.Fp8} {a : P F}
    (hx : Strict2 k x a) (ho : offset c o) (hk : k ≤ 2 * c) :
    ∃ out, fp2x8.Fp2x8.cond_sub x o = ok out ∧ Strict2 c out a := by
  obtain ⟨x0, hx0, rx0⟩ := strict_cond_sub hx.1 ho hk
  obtain ⟨x1, hx1, rx1⟩ := strict_cond_sub hx.2 ho hk
  refine ⟨⟨x0, x1⟩, ?_, rx0, rx1⟩
  simp only [fp2x8.Fp2x8.cond_sub, hx0, hx1, bind_tc_ok]

noncomputable def cyclePrepare (x : fp2x8.Fp2x8) :
    Result (fp2x8.Fp2x8 × fp2x8.Fp2x8 × fp8.Fp8) := do
  let z ← fp12.zero2
  let u0 ← fp2x8.Fp2x8.permute2 x z cycleInput0
  let u1 ← fp2x8.Fp2x8.permute2 x z cycleInput1
  let u ← fp2x8.Fp2x8.add_raw u0 u1
  let s0 ← fp2x8.Fp2x8.permute2 x z cycleSum0
  let s1 ← fp2x8.Fp2x8.permute2 x z cycleSum1
  let s ← fp2x8.Fp2x8.add_raw s0 s1
  let p ← fp8.Fp8.multiple_of_p 512#u64
  ok (u, s, p)

noncomputable def cycleQProduct (u : fp2x8.Fp2x8) (p : fp8.Fp8) : Result fp2x8.Fp2x8 := do
  let sum ← fp8.Fp8.add_raw u.c0 u.c1
  let ns ← fp8.Fp8.normalise sum
  let diff ← fp8.Fp8.sub_raw u.c0 u.c1 p
  let nd ← fp8.Fp8.normalise diff
  let re ← fp8.Fp8.mul ns nd
  let nr ← fp8.Fp8.normalise u.c0
  let twice ← fp8.Fp8.add_raw u.c1 u.c1
  let nt ← fp8.Fp8.normalise twice
  let im ← fp8.Fp8.mul nr nt
  ok ⟨re, im⟩

noncomputable def cycleMProduct (s : fp2x8.Fp2x8) (p : fp8.Fp8) : Result fp8.Fp8 := do
  let sum ← fp8.Fp8.add_raw s.c0 s.c1
  let diff ← fp8.Fp8.sub_raw s.c0 s.c1 p
  let twice ← fp8.Fp8.add_raw s.c1 s.c1
  let pl ← fp8.Fp8.permute2 sum s.c0 cyclePack
  let left ← fp8.Fp8.normalise pl
  let pr ← fp8.Fp8.permute2 diff twice cyclePack
  let right ← fp8.Fp8.normalise pr
  fp8.Fp8.mul left right

noncomputable def cycleProducts (x : fp2x8.Fp2x8) : Result (fp2x8.Fp2x8 × fp8.Fp8) := do
  let usp ← cyclePrepare x
  let q ← cycleQProduct usp.1 usp.2.2
  let m ← cycleMProduct usp.2.1 usp.2.2
  ok (q, m)

theorem cycle_schedule (x : fp2x8.Fp2x8) :
    fp12.Fp12.cyclotomic_square x = (do
      let qm ← cycleProducts x
      let r ← fp12.Fp12.cyclotomic_sum qm.1 qm.2 x
      let p512 ← fp8.Fp8.multiple_of_p 512#u64
      let r1 ← fp2x8.Fp2x8.cond_sub r p512
      let p256 ← fp8.Fp8.multiple_of_p fp12.BOUND
      fp2x8.Fp2x8.cond_sub r1 p256) := by
  have h512 : 2#u64 * fp12.BOUND = ok 512#u64 := by unfold fp12.BOUND; rfl
  simp only [fp12.Fp12.cyclotomic_square, cycleProducts, cyclePrepare, cycleQProduct,
    cycleMProduct, h512, bind_tc_ok, bind_assoc, bind_return]
  rfl

theorem cycle_prepare_raw {x : fp2x8.Fp2x8} {a : P F}
    (hx : Normal2 (fun _ => 256, fun _ => 256) x a) :
    ∃ u s p, cyclePrepare x = ok (u, s, p) ∧
      Raw2 (fun _ => 512, fun _ => 512) 2 u (cycleInput a) ∧
      Raw2 (fun _ => 512, fun _ => 512) 2 s (cycleSums a) ∧ offset 512 p := by
  obtain ⟨z, hz, rz⟩ := raw2_zero
  obtain ⟨u0, hu0, ru0⟩ := raw2_permute2 cycleInput0 hx.raw rz.raw
  obtain ⟨u1, hu1, ru1⟩ := raw2_permute2 cycleInput1 hx.raw rz.raw
  obtain ⟨u, hu, ru⟩ := raw2_add ru0 ru1 (by decide)
  have ru' : Raw2 (fun _ => 512, fun _ => 512) 2 u (cycleInput a) :=
    ru.mono (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨s0, hs0, rs0⟩ := raw2_permute2 cycleSum0 hx.raw rz.raw
  obtain ⟨s1, hs1, rs1⟩ := raw2_permute2 cycleSum1 hx.raw rz.raw
  obtain ⟨s, hs, rs⟩ := raw2_add rs0 rs1 (by decide)
  have rs' : Raw2 (fun _ => 512, fun _ => 512) 2 s (cycleSums a) :=
    rs.mono (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨p512, hp512, rp512⟩ := raw_offset 512#u64 (by decide)
  refine ⟨u, s, p512, ?_, ru', rs', rp512⟩
  simp only [cyclePrepare, hz, hu0, hu1, hu, hs0, hs1, hs, hp512, bind_tc_ok]

theorem quadratic_real_raw {u : fp2x8.Fp2x8} {p : fp8.Fp8} {a : P F}
    (hu : Raw2 (fun _ => 512, fun _ => 512) 2 u a) (hp : offset 512 p) :
    ∃ sum diff re, fp8.Fp8.add_raw u.c0 u.c1 >>= fp8.Fp8.normalise = ok sum ∧
      fp8.Fp8.sub_raw u.c0 u.c1 p >>= fp8.Fp8.normalise = ok diff ∧
      fp8.Fp8.mul sum diff = ok re ∧
      Normal (fun _ => 2) re (fun l => (a.1 l + a.2 l) * (a.1 l - a.2 l)) := by
  obtain ⟨s, hs, rs⟩ := raw_add hu.1 hu.2 (by decide)
  have rs' : Raw (fun _ => 1024) 4 s (fun l => a.1 l + a.2 l) := rs
  obtain ⟨ns, hns, rns⟩ := raw_normalise rs' (by intro l; decide) (by decide)
  obtain ⟨d, hd, rd⟩ := raw_sub hu.1 hu.2 hp (by intro l; rfl) (by decide)
  have rd' : Raw (fun _ => 1024) 5 d (fun l => a.1 l - a.2 l) := rd
  obtain ⟨nd, hnd, rnd⟩ := raw_normalise rd' (by intro l; decide) (by decide)
  have rns' : Normal (fun _ => 1024) ns (fun l => a.1 l + a.2 l) := rns
  have rnd' : Normal (fun _ => 1024) nd (fun l => a.1 l - a.2 l) := rnd
  obtain ⟨re, hre, rre⟩ := raw_mul rns' rnd' (by intro l; decide)
  exact ⟨ns, nd, re, by simp only [hs, hns, bind_tc_ok],
    by simp only [hd, hnd, bind_tc_ok], hre, rre⟩

theorem quadratic_imag_raw {u : fp2x8.Fp2x8} {a : P F}
    (hu : Raw2 (fun _ => 512, fun _ => 512) 2 u a) :
    ∃ re im prod, fp8.Fp8.normalise u.c0 = ok re ∧
      fp8.Fp8.add_raw u.c1 u.c1 >>= fp8.Fp8.normalise = ok im ∧
      fp8.Fp8.mul re im = ok prod ∧
      Normal (fun _ => 2) prod (fun l => a.1 l * (a.2 l + a.2 l)) := by
  obtain ⟨nr, hnr, rnr⟩ := raw_normalise hu.1 (by intro l; dsimp; decide) (by decide)
  obtain ⟨t, ht, rt⟩ := raw_add hu.2 hu.2 (by decide)
  have rt' : Raw (fun _ => 1024) 4 t (fun l => a.2 l + a.2 l) := rt
  obtain ⟨nt, hnt, rnt⟩ := raw_normalise rt' (by intro l; decide) (by decide)
  have rnr' : Normal (fun _ => 512) nr a.1 := rnr
  have rnt' : Normal (fun _ => 1024) nt (fun l => a.2 l + a.2 l) := rnt
  obtain ⟨prod, hprod, rprod⟩ := raw_mul rnr' rnt' (by intro l; decide)
  exact ⟨nr, nt, prod, hnr, by simp only [ht, hnt, bind_tc_ok], hprod, rprod⟩

theorem cycle_q_raw {u : fp2x8.Fp2x8} {p512 : fp8.Fp8} {a : P F}
    (ru' : Raw2 (fun _ => 512, fun _ => 512) 2 u a) (rp512 : offset 512 p512) :
    ∃ out, cycleQProduct u p512 = ok out ∧ Normal2 (fun _ => 2, fun _ => 2) out
      (fun l => (a.1 l + a.2 l) * (a.1 l - a.2 l), fun l => a.1 l * (a.2 l + a.2 l)) := by
  obtain ⟨s, d, re, hs, hd, hre, rr⟩ := quadratic_real_raw ru' rp512
  obtain ⟨r, i, im, hr, hi, him, ri⟩ := quadratic_imag_raw ru'
  refine ⟨⟨re, im⟩, ?_, rr, ri⟩
  unfold cycleQProduct
  rw [← bind_assoc, hs, bind_tc_ok, ← bind_assoc, hd, bind_tc_ok, hre, bind_tc_ok,
    hr, bind_tc_ok, ← bind_assoc, hi, bind_tc_ok, him, bind_tc_ok]

theorem cycle_m_raw {s : fp2x8.Fp2x8} {p512 : fp8.Fp8} {a : P F}
    (rs' : Raw2 (fun _ => 512, fun _ => 512) 2 s (cycleSums a)) (rp512 : offset 512 p512) :
    ∃ out, cycleMProduct s p512 = ok out ∧ Normal (fun _ => 2) out (cycleM a) := by
  obtain ⟨ssum, hssum, rssum⟩ := raw_add rs'.1 rs'.2 (by decide)
  obtain ⟨sdiff, hsdiff, rsdiff⟩ := raw_sub rs'.1 rs'.2 rp512 (by intro l; rfl) (by decide)
  obtain ⟨stwice, hstwice, rstwice⟩ := raw_add rs'.2 rs'.2 (by decide)
  obtain ⟨pl, hpl, rpl⟩ := raw_permute2 cyclePack rssum rs'.1
  obtain ⟨pr, hpr, rpr⟩ := raw_permute2 cyclePack rsdiff rstwice
  have rpl' : Raw (fun _ => 1024) 4 pl
      (shuffle cyclePack (fun l => (cycleSums a).1 l + (cycleSums a).2 l) (cycleSums a).1) := by
    intro l; exact (rpl l).mono (by dsimp [shuffle]; split_ifs <;> decide) (by decide)
  have rpr' : Raw (fun _ => 1024) 5 pr
      (shuffle cyclePack (fun l => (cycleSums a).1 l - (cycleSums a).2 l)
        (fun l => (cycleSums a).2 l + (cycleSums a).2 l)) := by
    intro l; exact (rpr l).mono (by dsimp [shuffle]; split_ifs <;> decide) (by decide)
  obtain ⟨left, hleft, rleft⟩ := raw_normalise rpl' (by intro l; decide) (by decide)
  obtain ⟨right, hright, rright⟩ := raw_normalise rpr' (by intro l; decide) (by decide)
  obtain ⟨m, hm, rm⟩ := raw_mul rleft rright (by intro l; dsimp; decide)
  refine ⟨m, ?_, rm⟩
  simp only [cycleMProduct, hssum, hsdiff, hstwice, hpl, hleft, hpr, hright, hm, bind_tc_ok]

theorem cycle_products_raw {x : fp2x8.Fp2x8} {a : P F}
    (hx : Normal2 (fun _ => 256, fun _ => 256) x a) :
    ∃ q m, cycleProducts x = ok (q, m) ∧ Normal2 (fun _ => 2, fun _ => 2) q (cycleQ a) ∧
      Normal (fun _ => 2) m (cycleM a) := by
  obtain ⟨u, s, p, hp, ru, rs, rp⟩ := cycle_prepare_raw hx
  obtain ⟨q, hq, rq⟩ := cycle_q_raw ru rp
  obtain ⟨m, hm, rm⟩ := cycle_m_raw rs rp
  refine ⟨q, m, ?_, rq, rm⟩
  simp only [cycleProducts, hp, hq, hm, bind_tc_ok]

theorem cyclotomic_raw {x : fp2x8.Fp2x8} {a : P F}
    (hx : Normal2 (fun _ => 256, fun _ => 256) x a) :
    ∃ out, fp12.Fp12.cyclotomic_square x = ok out ∧ Strict2 256 out (cyclotomicValues a) := by
  obtain ⟨q, m, hprod, rq, rm⟩ := cycle_products_raw hx
  obtain ⟨r, hr, rr⟩ := cyclotomic_sum_raw rq rm hx
  obtain ⟨p512, hp512, rp512⟩ := raw_offset 512#u64 (by decide)
  obtain ⟨r1, hr1, rr1⟩ := normal2_cond_sub rr rp512 (by decide)
  obtain ⟨p256, hp256, rp256⟩ := raw_offset 256#u64 (by decide)
  obtain ⟨out, hout, rout⟩ := strict2_cond_sub rr1 rp256 (by decide)
  refine ⟨out, ?_, rout⟩
  rw [cycle_schedule]
  simp only [hprod, hr, hp512, hr1, fp12.BOUND, hp256, hout, bind_tc_ok]

end LeanBlsSimd.LaneTower
