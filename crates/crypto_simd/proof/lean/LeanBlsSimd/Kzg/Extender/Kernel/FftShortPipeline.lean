import LeanBlsSimd.Refines.Fr8
import LeanBlsSimd.Kzg.Extender.Kernel.FftShortOne
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Offset

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel
open FrModel

private theorem array_eight (t : Array fr8.Fr8 8#usize) :
    t = Array.make 8#usize [t.val[0]!, t.val[1]!, t.val[2]!, t.val[3]!,
      t.val[4]!, t.val[5]!, t.val[6]!, t.val[7]!] (by rfl) := by
  apply Subtype.ext
  apply List.ext_getElem
  · exact t.property
  intro i hi hi'
  have hib : i < 8 := by simpa using hi'
  interval_cases i <;> simp [Array.make]

private theorem short_seven (v : alloc.vec.Vec fr8.Fr8) (hv : v.val.length = 7) :
    v = ⟨[v.val[0]!, v.val[1]!, v.val[2]!, v.val[3]!, v.val[4]!, v.val[5]!, v.val[6]!],
      by simp; scalar_tac⟩ := by
  apply Subtype.ext
  apply List.ext_getElem
  · simpa using hv
  intro i hi hi'
  have hib : i < 7 := by simpa using hi'
  interval_cases i <;> simp [List.getElem?_eq_getElem hi]

private theorem reduced_success (a : fr8.Fr8) : ∃ r, fr8.Fr8.reduced a = ok r := by
  obtain ⟨offset, ho, _, _⟩ := multiple_of_r_refinement 2#u64 (by decide)
  simp only [fr8.Fr8.reduced, ho, FrModel.Simd.sub_limbs_refines,
    FrModel.Simd.select_borrowed_refines, bind_tc_ok, Prod.map]
  exact ⟨_, rfl⟩

private noncomputable def reducedValue (a : fr8.Fr8) := (reduced_success a).choose
private theorem reduced_eq (a : fr8.Fr8) : fr8.Fr8.reduced a = ok (reducedValue a) :=
  (reduced_success a).choose_spec

/- Normalize one finite loop step while arithmetic functions remain abstract.
Each proof binds the total arithmetic functions existentially, keeping limb computations out of schedule normalization. -/
scoped macro "short_stage_eval" "[" hs:term,* "]" : conv =>
  `(conv| simp -failIfUnchanged
    (disch := (simp -failIfUnchanged only [UScalar.ofNatCore_val_eq]; decide)) only
    [$[$hs:term],*, fft8.Fft8.dit_short, ShortModel.dit_short,
      fft8.Fft8.dif_short, ShortModel.dif_short,
      fft8.Fft8.dit_short_loop0.body, fft8.Fft8.dit_short_loop1.body,
      fft8.Fft8.dif_short_loop0.body, fft8.Fft8.dif_short_loop1.body,
      ShortModel.dit_short_loop0.body, ShortModel.dit_short_loop0_loop0.body,
      ShortModel.dif_short_loop0.body, ShortModel.dif_short_loop0_loop0.body,
      fft8.dit_finish, fr8.LANES, fr8.Fr8.add, fr8.Fr8.sub,
      usize_add_ok, usize_mul_ok, mul_ok, sub_ok, UScalar.ofNatCore_val_eq,
      Array.make, Array.getElem?_Usize_eq, Slice.getElem?_Usize_eq,
      alloc.vec.Vec.getElem?_Nat_eq, Array.index_usize, Array.update, Array.to_slice_mut,
      Array.to_slice, Array.from_slice, Slice.index_usize, Slice.update,
      alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_usize, lift, bind_tc_ok,
      bind_assoc_eq, Function.uncurry_apply_pair,
      UScalar.lt_equiv, UScalar.le_equiv, UScalar.eq_equiv,
      List.getElem?_cons_zero, List.getElem?_cons_succ, List.set_cons_zero, List.set_cons_succ,
      List.length_cons, List.length_nil, Nat.reduceAdd, Nat.reduceMul,
      Nat.reduceSub, Nat.reduceLT, if_pos, if_neg, ↓reduceIte, ↓reduceDIte])

private theorem dit_two_eq_model (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize)
    (h : Usize) (hh : h.val=2)
    (hshort : table.short.val.length = 7) :
    fft8.Fft8.dit_short table t h = ShortModel.dit_short table t h := by
  obtain ⟨add, hadd⟩ : ∃ f : fr8.Fr8 → fr8.Fr8 → fr8.Fr8,
      ∀ a b, fr8.Fr8.add_raw a b = ok (f a b) :=
    ⟨fun a b => _, fun a b => FrModel.Fr8.add_raw_refines a b⟩
  obtain ⟨sub, hsub⟩ : ∃ f : fr8.Fr8 → fr8.Fr8 → fr8.Fr8 → fr8.Fr8,
      ∀ a b c, fr8.Fr8.sub_raw a b c = ok (f a b c) :=
    ⟨fun a b c => _, fun a b c => FrModel.Fr8.sub_raw_refines a b c⟩
  obtain ⟨normalise, hnorm⟩ : ∃ f : fr8.Fr8 → fr8.Fr8,
      ∀ a, fr8.Fr8.normalise a = ok (f a) :=
    ⟨fun a => _, fun a => FrModel.Fr8.normalise_refines a⟩
  obtain ⟨productFn, hprod⟩ : ∃ f : fr8.Fr8 → fr8.Fr8 → Array M512 11#usize,
      ∀ a b, fr8.Fr8.product a b = ok (f a b) :=
    ⟨Fr8.productValue, Fr8.product_refines⟩
  obtain ⟨reduceFn, hred⟩ : ∃ f : Array M512 11#usize → fr8.Fr8,
      ∀ p, fr8.Fr8.reduce p = ok (f p) :=
    ⟨Fr8.reduceValue, Fr8.reduce_refines⟩
  have hm (a b : fr8.Fr8) : fr8.Fr8.mul a b = ok (reduceFn (productFn a b)) := by
    simp only [Fr8.mul_eq_reduce_product, hprod, hred, bind_tc_ok]
  have hc (p : Array M512 11#usize) (a b : fr8.Fr8) :
      fr8.Fr8.reduce_while_multiplying p a b = ok (reduceFn p, productFn a b) := by
    simp only [Fr8.reduce_while_multiplying_eq, hprod, hred, bind_tc_ok]
  obtain ⟨input, hi, _, _⟩ := multiple_of_r_refinement
    (UScalar.ofNatCore (ty := .U64) (2*h.val) (by scalar_tac))
    (by simp only [UScalar.ofNatCore_val_eq]; omega)
  obtain ⟨product, hp, _, _⟩ := multiple_of_r_refinement 2#u64 (by decide)
  have hcast : UScalar.cast .U64 h = UScalar.ofNatCore (ty := .U64) h.val (by scalar_tac) := by
    apply UScalar.eq_of_val_eq
    simp [hh]
  have hmul : 2#u64 * UScalar.ofNatCore (ty := .U64) h.val (by scalar_tac) =
      ok (UScalar.ofNatCore (ty := .U64) (2*h.val) (by scalar_tac)) := by
    exact mul_ok _ _ (by scalar_tac)
  obtain ⟨vectors,wide,short⟩ := table
  dsimp only at hshort
  rw [array_eight t, short_seven short hshort]
  generalize t.val[0]! = a0
  generalize t.val[1]! = a1
  generalize t.val[2]! = a2
  generalize t.val[3]! = a3
  generalize t.val[4]! = a4
  generalize t.val[5]! = a5
  generalize t.val[6]! = a6
  generalize t.val[7]! = a7
  have he : h = 2#usize := UScalar.eq_of_val_eq hh
  subst h
  all_goals
    simp only [UScalar.ofNatCore_val_eq] at hi
    conv_lhs =>
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_zero_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_zero_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_zero_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_pipeline_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_pipeline_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
    conv_rhs =>
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_outer_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_outer_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_outer_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]

private theorem dit_four_eq_model (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize)
    (h : Usize) (hh : h.val=4)
    (hshort : table.short.val.length = 7) :
    fft8.Fft8.dit_short table t h = ShortModel.dit_short table t h := by
  obtain ⟨add, hadd⟩ : ∃ f : fr8.Fr8 → fr8.Fr8 → fr8.Fr8,
      ∀ a b, fr8.Fr8.add_raw a b = ok (f a b) :=
    ⟨fun a b => _, fun a b => FrModel.Fr8.add_raw_refines a b⟩
  obtain ⟨sub, hsub⟩ : ∃ f : fr8.Fr8 → fr8.Fr8 → fr8.Fr8 → fr8.Fr8,
      ∀ a b c, fr8.Fr8.sub_raw a b c = ok (f a b c) :=
    ⟨fun a b c => _, fun a b c => FrModel.Fr8.sub_raw_refines a b c⟩
  obtain ⟨normalise, hnorm⟩ : ∃ f : fr8.Fr8 → fr8.Fr8,
      ∀ a, fr8.Fr8.normalise a = ok (f a) :=
    ⟨fun a => _, fun a => FrModel.Fr8.normalise_refines a⟩
  obtain ⟨productFn, hprod⟩ : ∃ f : fr8.Fr8 → fr8.Fr8 → Array M512 11#usize,
      ∀ a b, fr8.Fr8.product a b = ok (f a b) :=
    ⟨Fr8.productValue, Fr8.product_refines⟩
  obtain ⟨reduceFn, hred⟩ : ∃ f : Array M512 11#usize → fr8.Fr8,
      ∀ p, fr8.Fr8.reduce p = ok (f p) :=
    ⟨Fr8.reduceValue, Fr8.reduce_refines⟩
  have hm (a b : fr8.Fr8) : fr8.Fr8.mul a b = ok (reduceFn (productFn a b)) := by
    simp only [Fr8.mul_eq_reduce_product, hprod, hred, bind_tc_ok]
  have hc (p : Array M512 11#usize) (a b : fr8.Fr8) :
      fr8.Fr8.reduce_while_multiplying p a b = ok (reduceFn p, productFn a b) := by
    simp only [Fr8.reduce_while_multiplying_eq, hprod, hred, bind_tc_ok]
  obtain ⟨input, hi, _, _⟩ := multiple_of_r_refinement
    (UScalar.ofNatCore (ty := .U64) (2*h.val) (by scalar_tac))
    (by simp only [UScalar.ofNatCore_val_eq]; omega)
  obtain ⟨product, hp, _, _⟩ := multiple_of_r_refinement 2#u64 (by decide)
  have hcast : UScalar.cast .U64 h = UScalar.ofNatCore (ty := .U64) h.val (by scalar_tac) := by
    apply UScalar.eq_of_val_eq
    simp [hh]
  have hmul : 2#u64 * UScalar.ofNatCore (ty := .U64) h.val (by scalar_tac) =
      ok (UScalar.ofNatCore (ty := .U64) (2*h.val) (by scalar_tac)) := by
    exact mul_ok _ _ (by scalar_tac)
  obtain ⟨vectors,wide,short⟩ := table
  dsimp only at hshort
  rw [array_eight t, short_seven short hshort]
  generalize t.val[0]! = a0
  generalize t.val[1]! = a1
  generalize t.val[2]! = a2
  generalize t.val[3]! = a3
  generalize t.val[4]! = a4
  generalize t.val[5]! = a5
  generalize t.val[6]! = a6
  generalize t.val[7]! = a7
  have he : h = 4#usize := UScalar.eq_of_val_eq hh
  subst h
  all_goals
    simp only [UScalar.ofNatCore_val_eq] at hi
    conv_lhs =>
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_zero_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_zero_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_pipeline_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_pipeline_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_pipeline_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
    conv_rhs =>
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_outer_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]
      rw [ShortModel.dit_outer_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hi, hmul, hcast]

private theorem dif_two_eq_model (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize)
    (h : Usize) (hh : h.val=2)
    (hshort : table.short.val.length = 7) :
    fft8.Fft8.dif_short table t h = ShortModel.dif_short table t h := by
  obtain ⟨add, hadd⟩ : ∃ f : fr8.Fr8 → fr8.Fr8 → fr8.Fr8,
      ∀ a b, fr8.Fr8.add_raw a b = ok (f a b) :=
    ⟨fun a b => _, fun a b => FrModel.Fr8.add_raw_refines a b⟩
  obtain ⟨sub, hsub⟩ : ∃ f : fr8.Fr8 → fr8.Fr8 → fr8.Fr8 → fr8.Fr8,
      ∀ a b c, fr8.Fr8.sub_raw a b c = ok (f a b c) :=
    ⟨fun a b c => _, fun a b c => FrModel.Fr8.sub_raw_refines a b c⟩
  obtain ⟨normalise, hnorm⟩ : ∃ f : fr8.Fr8 → fr8.Fr8,
      ∀ a, fr8.Fr8.normalise a = ok (f a) :=
    ⟨fun a => _, fun a => FrModel.Fr8.normalise_refines a⟩
  obtain ⟨productFn, hprod⟩ : ∃ f : fr8.Fr8 → fr8.Fr8 → Array M512 11#usize,
      ∀ a b, fr8.Fr8.product a b = ok (f a b) :=
    ⟨Fr8.productValue, Fr8.product_refines⟩
  obtain ⟨reduceFn, hred⟩ : ∃ f : Array M512 11#usize → fr8.Fr8,
      ∀ p, fr8.Fr8.reduce p = ok (f p) :=
    ⟨Fr8.reduceValue, Fr8.reduce_refines⟩
  have hm (a b : fr8.Fr8) : fr8.Fr8.mul a b = ok (reduceFn (productFn a b)) := by
    simp only [Fr8.mul_eq_reduce_product, hprod, hred, bind_tc_ok]
  have hc (p : Array M512 11#usize) (a b : fr8.Fr8) :
      fr8.Fr8.reduce_while_multiplying p a b = ok (reduceFn p, productFn a b) := by
    simp only [Fr8.reduce_while_multiplying_eq, hprod, hred, bind_tc_ok]
  obtain ⟨product, hp, _, _⟩ := multiple_of_r_refinement 2#u64 (by decide)
  obtain ⟨reduced, hreduced⟩ : ∃ f : fr8.Fr8 → fr8.Fr8,
      ∀ a, fr8.Fr8.reduced a = ok (f a) :=
    ⟨reducedValue, reduced_eq⟩
  obtain ⟨vectors,wide,short⟩ := table
  dsimp only at hshort
  rw [array_eight t, short_seven short hshort]
  generalize t.val[0]! = a0
  generalize t.val[1]! = a1
  generalize t.val[2]! = a2
  generalize t.val[3]! = a3
  generalize t.val[4]! = a4
  generalize t.val[5]! = a5
  generalize t.val[6]! = a6
  generalize t.val[7]! = a7
  have he : h = 2#usize := UScalar.eq_of_val_eq hh
  subst h
  all_goals
    conv_lhs =>
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_zero_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_zero_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_zero_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_pipeline_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_pipeline_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
    conv_rhs =>
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_outer_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_outer_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_outer_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]

private theorem dif_four_eq_model (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize)
    (h : Usize) (hh : h.val=4)
    (hshort : table.short.val.length = 7) :
    fft8.Fft8.dif_short table t h = ShortModel.dif_short table t h := by
  obtain ⟨add, hadd⟩ : ∃ f : fr8.Fr8 → fr8.Fr8 → fr8.Fr8,
      ∀ a b, fr8.Fr8.add_raw a b = ok (f a b) :=
    ⟨fun a b => _, fun a b => FrModel.Fr8.add_raw_refines a b⟩
  obtain ⟨sub, hsub⟩ : ∃ f : fr8.Fr8 → fr8.Fr8 → fr8.Fr8 → fr8.Fr8,
      ∀ a b c, fr8.Fr8.sub_raw a b c = ok (f a b c) :=
    ⟨fun a b c => _, fun a b c => FrModel.Fr8.sub_raw_refines a b c⟩
  obtain ⟨normalise, hnorm⟩ : ∃ f : fr8.Fr8 → fr8.Fr8,
      ∀ a, fr8.Fr8.normalise a = ok (f a) :=
    ⟨fun a => _, fun a => FrModel.Fr8.normalise_refines a⟩
  obtain ⟨productFn, hprod⟩ : ∃ f : fr8.Fr8 → fr8.Fr8 → Array M512 11#usize,
      ∀ a b, fr8.Fr8.product a b = ok (f a b) :=
    ⟨Fr8.productValue, Fr8.product_refines⟩
  obtain ⟨reduceFn, hred⟩ : ∃ f : Array M512 11#usize → fr8.Fr8,
      ∀ p, fr8.Fr8.reduce p = ok (f p) :=
    ⟨Fr8.reduceValue, Fr8.reduce_refines⟩
  have hm (a b : fr8.Fr8) : fr8.Fr8.mul a b = ok (reduceFn (productFn a b)) := by
    simp only [Fr8.mul_eq_reduce_product, hprod, hred, bind_tc_ok]
  have hc (p : Array M512 11#usize) (a b : fr8.Fr8) :
      fr8.Fr8.reduce_while_multiplying p a b = ok (reduceFn p, productFn a b) := by
    simp only [Fr8.reduce_while_multiplying_eq, hprod, hred, bind_tc_ok]
  obtain ⟨product, hp, _, _⟩ := multiple_of_r_refinement 2#u64 (by decide)
  obtain ⟨reduced, hreduced⟩ : ∃ f : fr8.Fr8 → fr8.Fr8,
      ∀ a, fr8.Fr8.reduced a = ok (f a) :=
    ⟨reducedValue, reduced_eq⟩
  obtain ⟨vectors,wide,short⟩ := table
  dsimp only at hshort
  rw [array_eight t, short_seven short hshort]
  generalize t.val[0]! = a0
  generalize t.val[1]! = a1
  generalize t.val[2]! = a2
  generalize t.val[3]! = a3
  generalize t.val[4]! = a4
  generalize t.val[5]! = a5
  generalize t.val[6]! = a6
  generalize t.val[7]! = a7
  have he : h = 4#usize := UScalar.eq_of_val_eq hh
  subst h
  all_goals
    conv_lhs =>
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_zero_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_zero_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_pipeline_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_pipeline_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_pipeline_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
    conv_rhs =>
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_outer_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_inner_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]
      rw [ShortModel.dif_outer_step]
      short_stage_eval [hnorm, hadd, hsub, hprod, hred, hc, hm, hp, hreduced]

theorem dit_short_eq_model (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize)
    (h : Usize) (hh : h.val=1 ∨ h.val=2 ∨ h.val=4)
    (hshort : table.short.val.length = 7) :
    fft8.Fft8.dit_short table t h = ShortModel.dit_short table t h := by
  rcases hh with h1 | h2 | h4
  · have he : h = 1#usize := UScalar.eq_of_val_eq h1
    subst h
    exact ShortOne.dit_one table t
  · exact dit_two_eq_model table t h h2 hshort
  · exact dit_four_eq_model table t h h4 hshort

theorem dif_short_eq_model (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize)
    (h : Usize) (hh : h.val=1 ∨ h.val=2 ∨ h.val=4)
    (hshort : table.short.val.length = 7) :
    fft8.Fft8.dif_short table t h = ShortModel.dif_short table t h := by
  rcases hh with h1 | h2 | h4
  · have he : h = 1#usize := UScalar.eq_of_val_eq h1
    subst h
    exact ShortOne.dif_one table t
  · exact dif_two_eq_model table t h h2 hshort
  · exact dif_four_eq_model table t h h4 hshort

end LeanBlsSimd.Kzg.Extender.Kernel
