import LeanBlsSimd.Portable.Fp.InverseWords

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.Fp
open Word64
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

private theorem half_congruence {K : Type} [Field K] (h2 : (2 : K) ≠ 0)
    (a u x u' x' : K) (h : a*x=u) (hu : 2*u'=u) (hx : 2*x'=x) : a*x'=u' := by
  apply mul_left_cancel₀ h2
  calc
    2*(a*x') = a*(2*x') := by ring
    _ = a*x := by rw [hx]
    _ = u := h
    _ = 2*u' := hu.symm

theorem halve_mod_p_field (x : portable.fp.Fp) (hx : value x < Bls.Fp.modulus) :
    ∃ out, portable.fp.halve_mod_p x = ok out ∧ value out < Bls.Fp.modulus ∧
      (2 : ZMod Bls.Fp.modulus)*(value out : ZMod Bls.Fp.modulus) =
        (value x : ZMod Bls.Fp.modulus) := by
  obtain ⟨out,he,hb,hv⟩ := halve_mod_p_refines x hx
  refine ⟨out,he,hb,?_⟩
  have h := congrArg (fun z : ℤ => (z : ZMod Bls.Fp.modulus)) hv
  dsimp only at h
  split_ifs at h <;> simpa only [Int.cast_mul,Int.cast_add,Int.cast_ofNat,
    Int.cast_zero,Int.cast_natCast,ZMod.natCast_self,add_zero] using h

theorem halve_loop_refines (a : ZMod Bls.Fp.modulus) (u x : portable.fp.Fp)
    (hu : 0 < value u) (hx : value x < Bls.Fp.modulus)
    (hax : a*(value x : ZMod Bls.Fp.modulus) = (value u : ZMod Bls.Fp.modulus)) :
    ∃ u' x', portable.fp.inverse_words_loop0_loop0 u x = ok (u',x') ∧
      0 < value u' ∧ value u' ≤ value u ∧ value u' % (2 : ℤ) = 1 ∧
      value u' ∣ value u ∧ value x' < Bls.Fp.modulus ∧
      a*(value x' : ZMod Bls.Fp.modulus) = (value u' : ZMod Bls.Fp.modulus) := by
  induction hn : (value u).toNat using Nat.strong_induction_on generalizing u x with
  | h n ih =>
    by_cases heven : value u % (2 : ℤ) = 0
    · obtain ⟨uh,heu,hvu⟩ := halve_refines u 0#u64 (by decide)
      simp only [heven,show (0#u64).val = 0 from rfl,Nat.cast_zero,zero_mul,add_zero] at hvu
      have hpos : 0 < value uh := by omega
      have hlt : (value uh).toNat < n := by omega
      obtain ⟨xh,hex,hbx,hvx⟩ := halve_mod_p_field x hx
      have hu_field : (2 : ZMod Bls.Fp.modulus)*(value uh : ZMod Bls.Fp.modulus) =
          (value u : ZMod Bls.Fp.modulus) := by
        simpa only [Int.cast_mul,Int.cast_ofNat] using
          congrArg (fun z : ℤ => (z : ZMod Bls.Fp.modulus)) hvu
      have haxh := half_congruence (by decide +kernel : (2 : ZMod Bls.Fp.modulus) ≠ 0)
        a _ _ _ _ hax hu_field hvx
      obtain ⟨uo,xo,he,hop,hle,ho,hd,hxb,hxo⟩ := ih (value uh).toNat hlt uh xh hpos hbx haxh rfl
      refine ⟨uo,xo,?_,hop,by omega,ho,?_,hxb,hxo⟩
      · have hbody : portable.fp.inverse_words_loop0_loop0.body u x =
            ok (ControlFlow.cont (uh,xh)) := by
          simp only [portable.fp.inverse_words_loop0_loop0.body,is_even_refines,heven,
            decide_true,bind_tc_ok,if_true,heu,hex]
        rw [portable.fp.inverse_words_loop0_loop0,loop.eq_1]
        dsimp only
        rw [hbody]
        exact he
      · exact dvd_trans hd ⟨2,by omega⟩
    · have hodd : value u % (2 : ℤ) = 1 := by omega
      refine ⟨u,x,?_,hu,le_rfl,hodd,dvd_rfl,hx,hax⟩
      have hbody : portable.fp.inverse_words_loop0_loop0.body u x =
          ok (ControlFlow.done (u,x)) := by
        simp only [portable.fp.inverse_words_loop0_loop0.body,is_even_refines,heven,
          decide_false,bind_tc_ok,Bool.false_eq_true,if_false]
      rw [portable.fp.inverse_words_loop0_loop0,loop.eq_1]
      dsimp only
      rw [hbody]

theorem second_halve_loop_eq (u x : portable.fp.Fp) :
    portable.fp.inverse_words_loop0_loop1 u x = portable.fp.inverse_words_loop0_loop0 u x := rfl

theorem ordered_sub_words_refines (a b : portable.fp.Fp) (hle : value b ≤ value a) :
    ∃ out, portable.fp.sub_words a b = ok (out,false) ∧ value out = value a-value b := by
  obtain ⟨out,he,hv⟩ := sub_words_refines a b
  have ha := value_bounds a
  have hb := value_bounds b
  have hnot : ¬value a < value b := by omega
  have hfit : 0 ≤ value a-value b ∧ value a-value b < (radix : ℤ)^(6#usize).val := by omega
  rw [Int.emod_eq_of_lt hfit.1 hfit.2] at hv
  exact ⟨out,by simpa only [hnot,decide_false] using he,hv⟩

theorem coefficientSub_field (a b : portable.fp.Fp)
    (ha : value a < Bls.Fp.modulus) (hb : value b < Bls.Fp.modulus) :
    ∃ out, coefficientSub a b = ok out ∧ value out < Bls.Fp.modulus ∧
      (value out : ZMod Bls.Fp.modulus) =
        (value a : ZMod Bls.Fp.modulus)-(value b : ZMod Bls.Fp.modulus) := by
  obtain ⟨out,he,hb,hv⟩ := coefficientSub_refines a b ha hb
  refine ⟨out,he,hb,?_⟩
  rw [hv,ZMod.intCast_mod,Int.cast_sub]

theorem coefficientSub_map {β : Type} (a b : portable.fp.Fp) (f : portable.fp.Fp → β) :
    (do let (d,borrow) ← portable.fp.sub_words a b
        if borrow then
          let (out,_) ← portable.fp.add_words d bls.constants.P_U64
          ok (f out)
        else ok (f d)) = (do let out ← coefficientSub a b; ok (f out)) := by
  unfold coefficientSub
  simp only [bind_assoc]
  apply congrArg (fun k => Bind.bind (portable.fp.sub_words a b) k)
  funext pair
  rcases pair with ⟨d,borrow⟩
  cases borrow <;> simp [bind_assoc]

structure InverseInvariant (a : ZMod Bls.Fp.modulus) (u v x1 x2 : portable.fp.Fp) : Prop where
  u_bound : value u ≤ Bls.Fp.modulus
  v_pos : 0 < value v
  v_bound : value v ≤ Bls.Fp.modulus
  coprime : Int.gcd (value u) (value v) = 1
  x1_bound : value x1 < Bls.Fp.modulus
  x2_bound : value x2 < Bls.Fp.modulus
  x1_eq : a*(value x1 : ZMod Bls.Fp.modulus) = (value u : ZMod Bls.Fp.modulus)
  x2_eq : a*(value x2 : ZMod Bls.Fp.modulus) = (value v : ZMod Bls.Fp.modulus)

private theorem zero_left_forces_one (a : ZMod Bls.Fp.modulus) (u v x1 x2 : portable.fp.Fp)
    (h : InverseInvariant a u v x1 x2) (hu : value u = 0) : value v = 1 := by
  have hg := h.coprime
  rw [hu,Int.gcd_zero_left] at hg
  have habs := Int.natAbs_of_nonneg (le_of_lt h.v_pos)
  omega

private theorem field_sub_congruence {K : Type} [Field K] (a u v x y : K)
    (hu : a*x=u) (hv : a*y=v) : a*(x-y)=u-v := by rw [mul_sub,hu,hv]

private theorem inverse_body_step (u v x1 x2 uh vh xh yh : portable.fp.Fp)
    (hu1 : value u ≠ 1) (hv1 : value v ≠ 1) (hu0 : value u ≠ 0)
    (heu : portable.fp.inverse_words_loop0_loop0 u x1 = ok (uh,xh))
    (hev : portable.fp.inverse_words_loop0_loop0 v x2 = ok (vh,yh)) :
    portable.fp.inverse_words_loop0.body u v x1 x2 =
      (do let b ← portable.fp.geq uh vh
          if b then
            let (d,_) ← portable.fp.sub_words uh vh
            let out ← coefficientSub xh yh
            ok (ControlFlow.cont (d,vh,out,yh))
          else
            let (d,_) ← portable.fp.sub_words vh uh
            let out ← coefficientSub yh xh
            ok (ControlFlow.cont (uh,d,xh,out))) := by
  simp only [portable.fp.inverse_words_loop0.body,is_one_refines,hu1,hv1,
    decide_false,bind_tc_ok,Bool.false_eq_true,if_false,zero_eq_refines,hu0,
    heu,second_halve_loop_eq,hev]
  apply congrArg (fun k => Bind.bind (portable.fp.geq uh vh) k)
  funext b
  cases b
  · dsimp only
    apply congrArg (fun k => Bind.bind (portable.fp.sub_words vh uh) k)
    funext pair
    rcases pair with ⟨d,borrow⟩
    exact coefficientSub_map yh xh (fun out => ControlFlow.cont (uh,d,xh,out))
  · dsimp only
    apply congrArg (fun k => Bind.bind (portable.fp.sub_words uh vh) k)
    funext pair
    rcases pair with ⟨d,borrow⟩
    exact coefficientSub_map xh yh (fun out => ControlFlow.cont (d,vh,out,yh))

theorem inverse_loop_refines (a : ZMod Bls.Fp.modulus) (u v x1 x2 : portable.fp.Fp)
    (h : InverseInvariant a u v x1 x2) :
    ∃ out, portable.fp.inverse_words_loop0 u v x1 x2 = ok out ∧
      value out < Bls.Fp.modulus ∧ a*(value out : ZMod Bls.Fp.modulus) = 1 := by
  induction hn : (value u+value v).toNat using Nat.strong_induction_on generalizing u v x1 x2 with
  | h n ih =>
    by_cases hu1 : value u = 1
    · have hb : portable.fp.inverse_words_loop0.body u v x1 x2 = ok (ControlFlow.done x1) := by
        simp only [portable.fp.inverse_words_loop0.body,is_one_refines,hu1,
          decide_true,bind_tc_ok,if_true]
      refine ⟨x1,?_,h.x1_bound,?_⟩
      · rw [portable.fp.inverse_words_loop0,loop.eq_1]
        dsimp only
        rw [hb]
      · simpa only [hu1,Int.cast_one] using h.x1_eq
    · by_cases hv1 : value v = 1
      · have hb : portable.fp.inverse_words_loop0.body u v x1 x2 = ok (ControlFlow.done x2) := by
          simp only [portable.fp.inverse_words_loop0.body,is_one_refines,hu1,hv1,
            decide_false,decide_true,bind_tc_ok,Bool.false_eq_true,if_false,if_true]
        refine ⟨x2,?_,h.x2_bound,?_⟩
        · rw [portable.fp.inverse_words_loop0,loop.eq_1]
          dsimp only
          rw [hb]
        · simpa only [hv1,Int.cast_one] using h.x2_eq
      · have hu0 : value u ≠ 0 := fun hz => hv1 (zero_left_forces_one a u v x1 x2 h hz)
        have hu_pos : 0 < value u := by have := (value_bounds u).1; omega
        obtain ⟨uh,xh,heu,hup,hule,huodd,hud,hxb,hux⟩ :=
          halve_loop_refines a u x1 hu_pos h.x1_bound h.x1_eq
        obtain ⟨vh,yh,hev,hvp,hvle,hvodd,hvd,hyb,hvy⟩ :=
          halve_loop_refines a v x2 h.v_pos h.x2_bound h.x2_eq
        have hg : Int.gcd (value uh) (value vh) = 1 := by
          apply Nat.dvd_one.mp
          have hd := dvd_trans (Int.gcd_dvd_gcd_of_dvd_right (value uh) hvd)
            (Int.gcd_dvd_gcd_of_dvd_left (value v) hud)
          rwa [h.coprime] at hd
        have hbody := inverse_body_step u v x1 x2 uh vh xh yh hu1 hv1 hu0 heu hev
        by_cases hge : value vh ≤ value uh
        · obtain ⟨d,hd,hdv⟩ := ordered_sub_words_refines uh vh hge
          obtain ⟨xd,hxd,hdb,hdf⟩ := coefficientSub_field xh yh hxb hyb
          have hinv : InverseInvariant a d vh xd yh := by
            refine ⟨?_,hvp,?_,?_,hdb,hyb,?_,hvy⟩
            · have := h.u_bound; omega
            · have := h.v_bound; omega
            · rw [hdv,Int.gcd_sub_self_left,hg]
            · rw [hdf,mul_sub,hux,hvy,hdv,Int.cast_sub]
          have hmeasure : (value d+value vh).toNat < n := by
            have hd0 := (value_bounds d).1
            omega
          obtain ⟨out,he,hb,hf⟩ := ih _ hmeasure d vh xd yh hinv rfl
          refine ⟨out,?_,hb,hf⟩
          have hstep : portable.fp.inverse_words_loop0.body u v x1 x2 =
              ok (ControlFlow.cont (d,vh,xd,yh)) := by
            rw [hbody,geq_refines]
            simp only [hge,decide_true,bind_tc_ok,if_true,hd]
            change (do let z ← coefficientSub xh yh; ok (ControlFlow.cont (d,vh,z,yh))) = _
            rw [hxd]
            rfl
          rw [portable.fp.inverse_words_loop0,loop.eq_1]
          dsimp only
          rw [hstep]
          exact he
        · have hlt : value uh < value vh := by omega
          obtain ⟨d,hd,hdv⟩ := ordered_sub_words_refines vh uh (le_of_lt hlt)
          obtain ⟨yd,hyd,hdb,hdf⟩ := coefficientSub_field yh xh hyb hxb
          have hinv : InverseInvariant a uh d xh yd := by
            refine ⟨?_,?_,?_,?_,hxb,hdb,hux,?_⟩
            · have := h.u_bound; omega
            · omega
            · have := h.v_bound; omega
            · rw [hdv,Int.gcd_sub_self_right,hg]
            · rw [hdf,mul_sub,hvy,hux,hdv,Int.cast_sub]
          have hmeasure : (value uh+value d).toNat < n := by
            have hd0 := (value_bounds d).1
            omega
          obtain ⟨out,he,hb,hf⟩ := ih _ hmeasure uh d xh yd hinv rfl
          refine ⟨out,?_,hb,hf⟩
          have hstep : portable.fp.inverse_words_loop0.body u v x1 x2 =
              ok (ControlFlow.cont (uh,d,xh,yd)) := by
            rw [hbody,geq_refines]
            simp only [hge,decide_false,bind_tc_ok,Bool.false_eq_true,if_false,hd]
            change (do let z ← coefficientSub yh xh; ok (ControlFlow.cont (uh,d,xh,z))) = _
            rw [hyd]
            rfl
          rw [portable.fp.inverse_words_loop0,loop.eq_1]
          dsimp only
          rw [hstep]
          exact he

theorem inverse_words_zero (a : portable.fp.Fp) (ha : value a = 0) :
    portable.fp.inverse_words a = ok (Array.repeat 6#usize 0#u64) := by
  let one : portable.fp.Fp := Array.make 6#usize [1#u64,0#u64,0#u64,0#u64,0#u64,0#u64] (by rfl)
  have hp1 : value bls.constants.P_U64 ≠ 1 := by rw [modulus_words]; decide
  have hb : portable.fp.inverse_words_loop0.body a bls.constants.P_U64 one
      (Array.repeat 6#usize 0#u64) = ok (ControlFlow.done (Array.repeat 6#usize 0#u64)) := by
    simp only [portable.fp.inverse_words_loop0.body,is_one_refines,ha,hp1,
      zero_ne_one,decide_false,bind_tc_ok,Bool.false_eq_true,if_false,
      zero_eq_refines,decide_true,if_true]
  rw [portable.fp.inverse_words,portable.fp.inverse_words_loop0,loop.eq_1]
  dsimp only
  rw [hb]

theorem inverse_words_refines (a : portable.fp.Fp) (ha : value a < Bls.Fp.modulus) :
    ∃ out, portable.fp.inverse_words a = ok out ∧ value out < Bls.Fp.modulus ∧
      (value out : ZMod Bls.Fp.modulus) = (value a : ZMod Bls.Fp.modulus)⁻¹ := by
  by_cases hz : value a = 0
  · refine ⟨Array.repeat 6#usize 0#u64,inverse_words_zero a hz,?_,?_⟩
    · change (0 : ℤ) < Bls.Fp.modulus
      decide
    · change (0 : ZMod Bls.Fp.modulus) = _
      rw [hz,Int.cast_zero,inv_zero]
  · let one : portable.fp.Fp := Array.make 6#usize [1#u64,0#u64,0#u64,0#u64,0#u64,0#u64] (by rfl)
    have hone : value one = 1 := rfl
    have hzero : value (Array.repeat 6#usize 0#u64) = 0 := rfl
    have ha0 := (value_bounds a).1
    have habs := Int.natAbs_of_nonneg ha0
    have hg : Int.gcd (value a) (Bls.Fp.modulus : ℤ) = 1 := by
      rw [Int.gcd_eq_natAbs_gcd_natAbs,Int.natAbs_natCast]
      apply Nat.Coprime.gcd_eq_one
      exact (Bls.Fp.modulus_prime.coprime_iff_not_dvd.mpr
        (Nat.not_dvd_of_pos_of_lt (by omega) (by omega))).symm
    have h : InverseInvariant (value a : ZMod Bls.Fp.modulus) a bls.constants.P_U64 one
        (Array.repeat 6#usize 0#u64) := by
      refine ⟨le_of_lt ha,?_,?_,?_,?_,?_,?_,?_⟩
      · rw [modulus_words]; decide
      · rw [modulus_words]
      · rwa [modulus_words]
      · rw [hone]; decide
      · rw [hzero]; decide
      · rw [hone,Int.cast_one,mul_one]
      · rw [hzero,Int.cast_zero,mul_zero,modulus_words,Int.cast_natCast,ZMod.natCast_self]
    obtain ⟨out,he,hb,hf⟩ := inverse_loop_refines _ _ _ _ _ h
    refine ⟨out,he,hb,?_⟩
    exact eq_inv_of_mul_eq_one_right hf

end LeanBlsSimd.Portable.Fp
