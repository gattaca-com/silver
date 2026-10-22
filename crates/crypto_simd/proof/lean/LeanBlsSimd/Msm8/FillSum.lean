import LeanBlsSimd.Msm8.StrongFill

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.BucketsRefines

variable {A : Type} [AddCommGroup A]

def referencePoint (points : ℕ → A) (reference : U32) : A :=
  if reference.val / 2 ^ 31 = 1 then -points (reference.val % 2 ^ 31)
    else points (reference.val % 2 ^ 31)

def eventContribution (width : ℕ) (points : ℕ → A) (event : Event) : A :=
  2 ^ (event.window.val * width) • (event.magnitude.val • referencePoint points event.reference)

def bucketContributions (width windows : ℕ) (points : ℕ → A) (contents : BucketLists) : A :=
  ∑ window ∈ Finset.range windows, 2 ^ (window * width) •
    ∑ bucket ∈ Finset.range (2 ^ (width - 1)), (bucket + 1) •
      ((contents (listIndex width window (bucket + 1))).map (referencePoint points)).sum

theorem referencePoint_signed (points : ℕ → A) (reference : U32) (magnitude : ℕ) :
    magnitude • referencePoint points reference =
      SignedDigits.digitValue magnitude (decide (reference.val / 2 ^ 31 = 1)) •
        points (reference.val % 2 ^ 31) := by
  by_cases hs : reference.val / 2 ^ 31 = 1
  · simp [referencePoint, SignedDigits.digitValue]
  · simp [referencePoint, SignedDigits.digitValue]

theorem listIndex_injective (width window window' magnitude magnitude' : ℕ)
    (hm : 1 ≤ magnitude) (hmb : magnitude ≤ 2 ^ (width - 1))
    (hm' : 1 ≤ magnitude') (hmb' : magnitude' ≤ 2 ^ (width - 1)) :
    listIndex width window magnitude = listIndex width window' magnitude' ↔
      window = window' ∧ magnitude = magnitude' := by
  constructor
  · intro heq
    have h : window * 2 ^ (width - 1) + (magnitude - 1) =
        window' * 2 ^ (width - 1) + (magnitude' - 1) := by
      simpa only [listIndex, Nat.add_sub_assoc hm, Nat.add_sub_assoc hm'] using heq
    have hmod := congrArg (fun n => n % 2 ^ (width - 1)) h
    simp only [Nat.add_mod, Nat.mul_mod, Nat.mod_self, Nat.mul_zero, Nat.zero_mod, Nat.zero_add,
      Nat.mod_eq_of_lt (by omega : magnitude - 1 < 2 ^ (width - 1)),
      Nat.mod_eq_of_lt (by omega : magnitude' - 1 < 2 ^ (width - 1))] at hmod
    have hm_eq : magnitude = magnitude' := by omega
    subst magnitude'
    have hw : window * 2 ^ (width - 1) = window' * 2 ^ (width - 1) := by omega
    exact ⟨by nlinarith [show 0 < 2 ^ (width - 1) by positivity], rfl⟩
  · rintro ⟨rfl, rfl⟩
    rfl

theorem eventReferences_contributions (width windows : Usize) (events : List Event)
    (points : ℕ → A) (hfits : ∀ event ∈ events, Fits width windows event) :
    bucketContributions width.val windows.val points (eventReferences width events) =
      (events.map (eventContribution width.val points)).sum := by
  induction events with
  | nil => simp [bucketContributions, eventReferences]
  | cons event events ih =>
    have hfit := hfits event (by simp)
    have hrest : ∀ e ∈ events, Fits width windows e := fun e he => hfits e (by simp [he])
    have hsplit : bucketContributions width.val windows.val points (eventReferences width (event :: events)) =
        (∑ window ∈ Finset.range windows.val, 2 ^ (window * width.val) •
          ∑ bucket ∈ Finset.range (2 ^ (width.val - 1)), (bucket + 1) •
            (if event.magnitude ≠ 0#usize ∧ eventIndex width event = listIndex width.val window (bucket + 1)
              then referencePoint points event.reference else 0)) +
        bucketContributions width.val windows.val points (eventReferences width events) := by
      simp only [bucketContributions, eventReferences, List.map_append, List.sum_append,
        nsmul_add, Finset.sum_add_distrib]
      congr 1
      apply Finset.sum_congr rfl
      intro w _
      congr 1
      apply Finset.sum_congr rfl
      intro b _
      congr 1
      split <;> simp
    rw [hsplit, ih hrest, List.map_cons, List.sum_cons]
    congr 1
    by_cases hz : event.magnitude = 0#usize
    · simp [hz, eventContribution]
    · have hmv : 1 ≤ event.magnitude.val := by
        have hv : event.magnitude.val ≠ 0 := fun h => hz (UScalar.eq_of_val_eq h)
        omega
      have hm : event.magnitude.val - 1 < 2 ^ (width.val - 1) := by
        have := hfit.2
        omega
      have he (w b : ℕ) (hb : b < 2 ^ (width.val - 1)) :
          (event.magnitude ≠ 0#usize ∧ eventIndex width event = listIndex width.val w (b + 1)) ↔
          event.window.val = w ∧ event.magnitude.val - 1 = b := by
        rw [and_iff_right hz]
        unfold eventIndex
        rw [listIndex_injective _ _ _ _ _ hmv hfit.2 (by omega) (by omega)]
        omega
      have hinner (w : ℕ) :
          (∑ bucket ∈ Finset.range (2 ^ (width.val - 1)), (bucket + 1) •
            (if event.magnitude ≠ 0#usize ∧ eventIndex width event = listIndex width.val w (bucket + 1)
              then referencePoint points event.reference else 0)) =
          if event.window.val = w then event.magnitude.val • referencePoint points event.reference else 0 := by
        calc
          _ = ∑ b ∈ Finset.range (2 ^ (width.val - 1)),
              if event.window.val = w ∧ event.magnitude.val - 1 = b then
                (b + 1) • referencePoint points event.reference else 0 := by
            apply Finset.sum_congr rfl
            intro b hb
            rw [if_congr (he w b (Finset.mem_range.mp hb)) rfl rfl, smul_ite, smul_zero]
          _ = _ := by
            by_cases hw : event.window.val = w
            · simp only [hw, true_and, Finset.sum_ite_eq, Finset.mem_range, hm,
                if_true, Nat.sub_add_cancel hmv]
            · simp only [hw, false_and, if_false, Finset.sum_const_zero]
      simp_rw [hinner, smul_ite, smul_zero]
      simp only [Finset.sum_ite_eq, Finset.mem_range, hfit.1, if_true, eventContribution]

theorem indexed_events_contribution (width start index : ℕ) (events : List Event)
    (points : ℕ → A)
    (hcoords : ∀ j (hj : j < events.length),
      (events[j]'hj).window.val = start + j ∧
      (events[j]'hj).reference.val % 2 ^ 31 = index) :
    (events.map (eventContribution width points)).sum =
      2 ^ (start * width) • (SignedDigits.digitSum width (events.map eventDigit) • points index) := by
  induction events generalizing start with
  | nil => simp [SignedDigits.digitSum]
  | cons event events ih =>
    have hc := hcoords 0 (by simp)
    simp only [List.getElem_cons_zero, Nat.add_zero] at hc
    have ht : ∀ j (hj : j < events.length),
        (events[j]'hj).window.val = (start + 1) + j ∧
        (events[j]'hj).reference.val % 2 ^ 31 = index := by
      intro j hj
      have h := hcoords (j + 1) (by simpa using hj)
      exact ⟨by simpa only [List.getElem_cons_succ, Nat.add_assoc, Nat.add_comm 1 j] using h.1, h.2⟩
    simp only [List.map_cons, List.sum_cons, ih (start + 1) ht,
      eventContribution, referencePoint_signed, hc.1, hc.2,
      SignedDigits.digitSum, eventDigit, add_zsmul, mul_zsmul, nsmul_add]
    rw [show (2 : ℤ) ^ width = ((2 ^ width : ℕ) : ℤ) by simp, natCast_zsmul]
    rw [Nat.add_mul, Nat.one_mul, pow_add, mul_nsmul']

theorem window_events_contribution (words : Array U64 4#usize) (width index : Usize)
    (events : List Event) (last : silver_crypto_simd.bls.msm8.buckets.SignedDigits)
    (points : ℕ → A) (hwl : 1 ≤ width.val) (hwh : width.val ≤ 8)
    (hi : index.val < 2 ^ 31) (hscalar : SignedDigits.value words < 2 ^ 127)
    (hevents : windowEvents (windows127 width).val index 0#usize (SignedDigits.initial words width) =
      ok (events, last)) :
    (events.map (eventContribution width.val points)).sum =
      SignedDigits.value words • points index.val := by
  have hb : (windows127 width).val < 2 ^ 32 := by
    have := windows127_bits width hwh
    nlinarith
  have hc := windowEvents_coordinates (windows127 width).val index 0#usize
    (SignedDigits.initial words width) last events hi (by simpa only [UScalar.ofNatCore_val_eq, Nat.zero_add] using hb) hevents
  have hs := indexed_events_contribution width.val 0 index.val events points hc
  rw [(windowEvents_scalar words width index events last hwl hwh hi hscalar hevents).1] at hs
  simpa only [Nat.zero_mul, pow_zero, one_nsmul, natCast_zsmul] using hs

theorem scalar_events_contribution (n : ℕ) (scalars : Slice (Array U64 4#usize))
    (width index : Usize) (events : List Event) (values : ℕ → ℕ) (points : ℕ → A)
    (hwl : 1 ≤ width.val) (hwh : width.val ≤ 8)
    (hn : index.val + n ≤ scalars.val.length) (hlen : scalars.val.length < 2 ^ 31)
    (hv : ∀ j (hj : j < scalars.val.length), SignedDigits.value scalars.val[j] = values j)
    (hb : ∀ j, j < scalars.val.length → values j < 2 ^ 127)
    (hevents : scalarEvents n scalars width (windows127 width) index = ok events) :
    (events.map (eventContribution width.val points)).sum =
      ∑ j ∈ Finset.range n, values (index.val + j) • points (index.val + j) := by
  induction n generalizing index events with
  | zero =>
    simp only [scalarEvents] at hevents
    cases Result.ok.inj hevents
    simp
  | succ n ih =>
    have hil : index.val < scalars.val.length := by omega
    simp only [scalarEvents, bind_success] at hevents
    obtain ⟨words, hwords, digits, hdigits, ⟨first, last⟩, hfirst, hevents⟩ := hevents
    simp only [Function.uncurry_def, bind_success] at hevents
    obtain ⟨index', hindex, rest, hrest, hevents⟩ := hevents
    cases Result.ok.inj hevents
    have hwordsEq : words = scalars.val[index.val] := by
      simp [Slice.index_usize, List.getElem?_eq_getElem hil] at hwords
      exact hwords.symm
    have hdigitsEq : digits = SignedDigits.initial words width := by
      rw [SignedDigits.new_refines] at hdigits
      exact (Result.ok.inj hdigits).symm
    have hindexv : index'.val = index.val + 1 := by
      rw [add_ok index 1#usize (by
        change index.val + 1 < 2 ^ UScalarTy.Usize.numBits
        have := two_pow_32_le_usize
        omega)] at hindex
      cases Result.ok.inj hindex
      rfl
    have hvalue : SignedDigits.value words = values index.val := hwordsEq ▸ hv index.val hil
    have hfirstSum := window_events_contribution words width index first last points hwl hwh
      (by omega) (by rw [hvalue]; exact hb index.val hil) (hdigitsEq ▸ hfirst)
    have hrestSum := ih index' rest (by omega) hrest
    rw [List.map_append, List.sum_append, hfirstSum, hrestSum, hvalue]
    rw [Finset.sum_range_succ']
    simp only [Nat.add_zero, hindexv]
    rw [add_comm]
    congr 1
    apply Finset.sum_congr rfl
    intro j _
    congr 2 <;> omega

theorem eventReferences_all (width : Usize) (events : List Event) (i : ℕ)
    (P : U32 → Prop) (hp : ∀ e ∈ events, P e.reference) :
    ∀ r ∈ eventReferences width events i, P r := by
  induction events with
  | nil => simp [eventReferences]
  | cons e es ih =>
    intro r hr
    simp only [eventReferences, List.mem_append] at hr
    rcases hr with hr | hr
    · split at hr
      · simp only [List.mem_singleton] at hr
        subst r
        exact hp e (by simp)
      · simp at hr
    · exact ih (fun x hx => hp x (by simp [hx])) r hr

theorem window_events_references (width index : Usize)
    (events : List Event) (last : silver_crypto_simd.bls.msm8.buckets.SignedDigits)
    (digits : silver_crypto_simd.bls.msm8.buckets.SignedDigits)
    (hwl : 1 ≤ width.val) (hwh : width.val ≤ 8) (hi : index.val < 2 ^ 31)
    (hevents : windowEvents (windows127 width).val index 0#usize digits = ok (events, last)) :
    ∀ e ∈ events, e.reference.val % 2 ^ 31 = index.val := by
  have hb : (windows127 width).val < 2 ^ 32 := by
    have := windows127_bits width hwh
    nlinarith
  have hc := windowEvents_coordinates (windows127 width).val index 0#usize digits last events hi
    (by simpa only [UScalar.ofNatCore_val_eq, Nat.zero_add] using hb) hevents
  intro e he
  obtain ⟨j, rfl⟩ := List.mem_iff_get.mp he
  exact (hc j.val j.isLt).2

theorem scalar_events_references (n : ℕ) (scalars : Slice (Array U64 4#usize))
    (width index : Usize) (events : List Event)
    (hwl : 1 ≤ width.val) (hwh : width.val ≤ 8)
    (hn : index.val + n ≤ scalars.val.length) (hlen : scalars.val.length < 2 ^ 31)
    (hevents : scalarEvents n scalars width (windows127 width) index = ok events) :
    ∀ e ∈ events, e.reference.val % 2 ^ 31 < scalars.val.length := by
  induction n generalizing index events with
  | zero =>
    simp only [scalarEvents] at hevents
    cases Result.ok.inj hevents
    simp
  | succ n ih =>
    simp only [scalarEvents, bind_success] at hevents
    obtain ⟨words, hwords, digits, hdigits, ⟨first, last⟩, hfirst, hevents⟩ := hevents
    simp only [Function.uncurry_def, bind_success] at hevents
    obtain ⟨index', hindex, rest, hrest, hevents⟩ := hevents
    cases Result.ok.inj hevents
    have hindexv : index'.val = index.val + 1 := by
      rw [add_ok index 1#usize (by
        change index.val + 1 < 2 ^ UScalarTy.Usize.numBits
        have := two_pow_32_le_usize
        omega)] at hindex
      cases Result.ok.inj hindex
      rfl
    intro e he
    rcases List.mem_append.mp he with he | he
    · rw [window_events_references width index first last digits hwl hwh (by omega) hfirst e he]
      omega
    · exact ih index' rest (by omega) hrest e he

theorem fill127_contribution (state : silver_crypto_simd.bls.msm8.buckets.Buckets)
    (scalars : Slice (Array U64 4#usize)) (values : ℕ → ℕ) (points : ℕ → A)
    (hsize : scalars.val.length * (windows127 (selectedWidth scalars.val.length)).val < 2 ^ 32)
    (hlen : scalars.val.length < 2 ^ 31)
    (hv : ∀ j (hj : j < scalars.val.length), SignedDigits.value scalars.val[j] = values j)
    (hb : ∀ j, j < scalars.val.length → values j < 2 ^ 127) :
    ∃ out, state.fill scalars 127#usize = ok out ∧
      bucketContributions out.window_bits.val out.windows.val points (bucketSlice out) =
        ∑ j ∈ Finset.range scalars.val.length, values j • points j ∧
      ∀ i, i < out.windows.val * 2 ^ (out.window_bits.val - 1) →
        ∀ r ∈ bucketSlice out i, r.val % 2 ^ 31 < scalars.val.length := by
  obtain ⟨events, out, htrace, hout, _, how, hon, hrecover⟩ := fill127_refines state scalars hsize
  obtain ⟨hwl, hwh⟩ := selectedWidth_bounds scalars.val.length
  obtain ⟨events', htrace', _, hfits⟩ := scalarEvents_succeeds scalars.val.length scalars
    (selectedWidth scalars.val.length) (windows127 (selectedWidth scalars.val.length)) 0#usize
    hwl hwh (windows127_bits _ hwh) (by change 0 + scalars.val.length ≤ scalars.val.length; omega)
  have heq := Result.ok.inj (htrace.symm.trans htrace')
  subst events'
  have hsum := scalar_events_contribution scalars.val.length scalars _ 0#usize events values points
    hwl hwh (by change 0 + scalars.val.length ≤ scalars.val.length; omega) hlen hv hb htrace
  have href := scalar_events_references scalars.val.length scalars _ 0#usize events hwl hwh
    (by change 0 + scalars.val.length ≤ scalars.val.length; omega) hlen htrace
  refine ⟨out, hout, ?_, ?_⟩
  · calc
      _ = bucketContributions out.window_bits.val out.windows.val points
          (eventReferences (selectedWidth scalars.val.length) events) := by
        unfold bucketContributions
        apply Finset.sum_congr rfl
        intro w hw
        congr 1
        apply Finset.sum_congr rfl
        intro b hb'
        rw [hrecover _ (by
          have hm := Nat.mul_le_mul_right (2 ^ (out.window_bits.val - 1))
            (show w + 1 ≤ out.windows.val from by simpa only [Finset.mem_range] using hw)
          simp only [Finset.mem_range] at hb'
          unfold listIndex
          rw [Nat.add_mul, Nat.one_mul] at hm
          omega)]
      _ = (events.map (eventContribution out.window_bits.val points)).sum := by
        rw [how, hon]
        exact eventReferences_contributions _ _ events points hfits
      _ = _ := by
        rw [how]
        simpa only [UScalar.ofNatCore_val_eq, Nat.zero_add] using hsum
  · intro i hi r hr
    rw [hrecover i hi] at hr
    exact eventReferences_all _ events i (fun r => r.val % 2 ^ 31 < scalars.val.length) href r hr

end LeanBlsSimd.BucketsRefines
