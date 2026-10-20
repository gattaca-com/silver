import LeanBlsSimd.Kzg.Extender.Kernel.FftShortSteps
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Offset

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg
/- At width one, each model inner loop performs exactly the generated zero-column pair. -/
namespace LeanBlsSimd.Kzg.Extender.Kernel.ShortOne

theorem dit_inner_done (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize)
    (input product : fr8.Fr8) (group : Usize) :
    ShortModel.dit_short_loop0_loop0 table t 1#usize input product group 1#usize =
      ok (table,t) := by
  rw [ShortModel.dit_inner_step]
  simp only [ShortModel.dit_short_loop0_loop0.body, UScalar.lt_equiv,
    UScalar.ofNatCore_val_eq, Nat.lt_irrefl, if_false, bind_tc_ok]

theorem add_zero_eq (x : Usize) : x + 0#usize = ok x := by
  have he : x + 0#usize = ok (UScalar.ofNatCore (ty := .Usize) (x.val + 0) (by scalar_tac)) :=
    add_ok _ _ (by scalar_tac)
  have hx : UScalar.ofNatCore (ty := .Usize) (x.val + 0) (by scalar_tac) = x :=
    UScalar.eq_of_val_eq (by simp)
  simpa only [hx] using he

theorem dit_inner_one (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize)
    (input product : fr8.Fr8) (group : Usize) (hg : group.val < 8) :
    ShortModel.dit_short_loop0_loop0 table t 1#usize input product group 0#usize =
      (do
        let a ← Array.index_usize t group
        let i ← group + 1#usize
        let b ← Array.index_usize t i
        let f ← fr8.Fr8.add_raw a b
        let t1 ← Array.update t group f
        let f1 ← fr8.Fr8.sub_raw a b input
        let t2 ← Array.update t1 i f1
        ok (table,t2)) := by
  rw [ShortModel.dit_inner_step]
  simp only [ShortModel.dit_short_loop0_loop0.body, UScalar.lt_equiv,
    UScalar.ofNatCore_val_eq, Nat.zero_lt_one, if_true, add_zero_eq,
    bind_tc_ok, bind_assoc_eq, Function.uncurry_apply_pair]
  have hs : 0#usize + 1#usize = ok (1#usize) := add_ok _ _ (by scalar_tac)
  have hg1 : group + 1#usize =
      ok (UScalar.ofNatCore (ty := .Usize) (group.val + 1) (by scalar_tac)) :=
    add_ok _ _ (by scalar_tac)
  simp only [hs, hg1, bind_tc_ok, dit_inner_done]

theorem dit_outer_one (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize)
    (input product : fr8.Fr8) (group : Usize) (hg : group.val ≤ 9) :
    ShortModel.dit_short_loop0 table t 1#usize input product group =
      fft8.Fft8.dit_short_loop0 t 1#usize input group := by
  generalize hrem : 9 - group.val = remaining
  induction remaining using Nat.strong_induction_on generalizing group t with
  | h remaining ih =>
    rw [ShortModel.dit_outer_step, ShortModel.dit_zero_step]
    by_cases hlt : group.val < 8
    · let next : Usize := UScalar.ofNatCore (ty := .Usize) (group.val + 2) (by scalar_tac)
      have hnext : next.val = group.val + 2 := rfl
      have hs : 2#usize * 1#usize = ok (2#usize) := mul_ok _ _ (by scalar_tac)
      have hadd : group + 2#usize = ok next := add_ok _ _ (by scalar_tac)
      have hr (t1 : Array fr8.Fr8 8#usize) :
          ShortModel.dit_short_loop0 table t1 1#usize input product next =
            fft8.Fft8.dit_short_loop0 t1 1#usize input next :=
        ih (9-next.val) (by omega) t1 next (by omega) rfl
      simp only [ShortModel.dit_short_loop0.body, fft8.Fft8.dit_short_loop0.body,
        fr8.LANES, UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hlt, if_true,
        dit_inner_one table t input product group hlt, hs, hadd, bind_tc_ok,
        bind_assoc_eq, Function.uncurry_apply_pair, hr]
    · simp only [ShortModel.dit_short_loop0.body, fft8.Fft8.dit_short_loop0.body,
        fr8.LANES, UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hlt, if_false, bind_tc_ok]

theorem dif_inner_done (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize)
    (input : fr8.Fr8) (group : Usize) :
    ShortModel.dif_short_loop0_loop0 table t 1#usize input group 1#usize =
      ok (table,t) := by
  rw [ShortModel.dif_inner_step]
  simp only [ShortModel.dif_short_loop0_loop0.body, UScalar.lt_equiv,
    UScalar.ofNatCore_val_eq, Nat.lt_irrefl, if_false, bind_tc_ok]

theorem dif_inner_one (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize)
    (input : fr8.Fr8) (group : Usize) (hg : group.val < 8) :
    ShortModel.dif_short_loop0_loop0 table t 1#usize input group 0#usize =
      (do
        let a ← Array.index_usize t group
        let i ← group + 1#usize
        let b ← Array.index_usize t i
        let f ← fr8.Fr8.add a b
        let t1 ← Array.update t group f
        let f1 ← fr8.Fr8.sub a b
        let t2 ← Array.update t1 i f1
        ok (table,t2)) := by
  rw [ShortModel.dif_inner_step]
  simp only [ShortModel.dif_short_loop0_loop0.body, UScalar.lt_equiv,
    UScalar.ofNatCore_val_eq, Nat.zero_lt_one, if_true, add_zero_eq,
    bind_tc_ok, bind_assoc_eq, Function.uncurry_apply_pair]
  have hs : 0#usize + 1#usize = ok (1#usize) := add_ok _ _ (by scalar_tac)
  have hg1 : group + 1#usize =
      ok (UScalar.ofNatCore (ty := .Usize) (group.val + 1) (by scalar_tac)) :=
    add_ok _ _ (by scalar_tac)
  simp only [hs, hg1, bind_tc_ok, dif_inner_done]

theorem dif_outer_one (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize)
    (input : fr8.Fr8) (group : Usize) (hg : group.val ≤ 9) :
    ShortModel.dif_short_loop0 table t 1#usize input group =
      fft8.Fft8.dif_short_loop0 t 1#usize group := by
  generalize hrem : 9 - group.val = remaining
  induction remaining using Nat.strong_induction_on generalizing group t with
  | h remaining ih =>
    rw [ShortModel.dif_outer_step, ShortModel.dif_zero_step]
    by_cases hlt : group.val < 8
    · let next : Usize := UScalar.ofNatCore (ty := .Usize) (group.val + 2) (by scalar_tac)
      have hnext : next.val = group.val + 2 := rfl
      have hs : 2#usize * 1#usize = ok (2#usize) := mul_ok _ _ (by scalar_tac)
      have hadd : group + 2#usize = ok next := add_ok _ _ (by scalar_tac)
      have hr (t1 : Array fr8.Fr8 8#usize) :
          ShortModel.dif_short_loop0 table t1 1#usize input next =
            fft8.Fft8.dif_short_loop0 t1 1#usize next :=
        ih (9-next.val) (by omega) t1 next (by omega) rfl
      simp only [ShortModel.dif_short_loop0.body, fft8.Fft8.dif_short_loop0.body,
        fr8.LANES, UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hlt, if_true,
        dif_inner_one table t input group hlt, hs, hadd, bind_tc_ok,
        bind_assoc_eq, Function.uncurry_apply_pair, hr]
    · simp only [ShortModel.dif_short_loop0.body, fft8.Fft8.dif_short_loop0.body,
        fr8.LANES, UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hlt, if_false, bind_tc_ok]

theorem bind_right_id {α : Type} (x : Result α) : (do let y ← x; ok y) = x := by
  cases x <;> rfl

theorem dit_one (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize) :
    fft8.Fft8.dit_short table t 1#usize = ShortModel.dit_short table t 1#usize := by
  have he (t : Array fr8.Fr8 8#usize) (input product : fr8.Fr8) :=
    dit_outer_one table t input product 0#usize (by decide)
  simp only [fft8.Fft8.dit_short, ShortModel.dit_short, if_true, bind_right_id, he]

theorem dif_one (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize) :
    fft8.Fft8.dif_short table t 1#usize = ShortModel.dif_short table t 1#usize := by
  have he (t : Array fr8.Fr8 8#usize) (input : fr8.Fr8) :=
    dif_outer_one table t input 0#usize (by decide)
  simp only [fft8.Fft8.dif_short, ShortModel.dif_short, if_true, bind_right_id, he]

end LeanBlsSimd.Kzg.Extender.Kernel.ShortOne
