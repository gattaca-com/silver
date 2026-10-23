import LeanBlsSimd.Msm8.Buckets

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8 alloc.vec

theorem bind_success {α β : Type} (r : Result α) (f : α → Result β) (out : β) :
    (r >>= f) = ok out ↔ ∃ a, r = ok a ∧ f a = ok out := by
  cases r <;> simp [Bind.bind, Aeneas.Std.bind]

theorem count_metadata (state next : buckets.Buckets) (window magnitude : Usize)
    (h : state.count window magnitude = ok next) :
    next.window_bits = state.window_bits ∧ next.windows = state.windows := by
  simp only [buckets.Buckets.count] at h
  split at h
  · rw [bind_success] at h
    obtain ⟨i, _, h⟩ := h
    rw [bind_success] at h
    obtain ⟨⟨value, back⟩, _, h⟩ := h
    simp only [Function.uncurry_def] at h
    rw [bind_success] at h
    obtain ⟨count, _, h⟩ := h
    cases Result.ok.inj h
    exact ⟨rfl, rfl⟩
  · cases Result.ok.inj h
    exact ⟨rfl, rfl⟩

theorem place_metadata (state next : buckets.Buckets) (window magnitude : Usize) (reference : U32)
    (h : state.place window magnitude reference = ok next) :
    next.window_bits = state.window_bits ∧ next.windows = state.windows := by
  simp only [buckets.Buckets.place] at h
  split at h
  · rw [bind_success] at h
    obtain ⟨i, _, h⟩ := h
    rw [bind_success] at h
    obtain ⟨start, _, h⟩ := h
    rw [bind_success] at h
    obtain ⟨len, _, h⟩ := h
    rw [bind_success] at h
    obtain ⟨address, _, h⟩ := h
    simp only [lift, bind_tc_ok] at h
    rw [bind_success] at h
    obtain ⟨⟨_, refsBack⟩, _, h⟩ := h
    simp only [Function.uncurry_def] at h
    rw [bind_success] at h
    obtain ⟨⟨value, lensBack⟩, _, h⟩ := h
    rw [bind_success] at h
    obtain ⟨count, _, h⟩ := h
    cases Result.ok.inj h
    exact ⟨rfl, rfl⟩
  · cases Result.ok.inj h
    exact ⟨rfl, rfl⟩

def fields (state : buckets.Buckets) :=
  (state.window_bits, state.windows, state.refs, state.starts, state.lens)

def windowEvents : ℕ → Usize → Usize → signed_digits.SignedDigits →
    Result (List Event × signed_digits.SignedDigits)
  | 0, _, _, digits => ok ([], digits)
  | n + 1, index, window, digits => do
    let ((magnitude, negative), digits') ← digits.next_digit
    let window' ← window + 1#usize
    let (rest, last) ← windowEvents n index window' digits'
    ok ({window, magnitude, reference := signedReference index negative} :: rest, last)

theorem count_windows_refines (state out : buckets.Buckets) (digits last : signed_digits.SignedDigits)
    (index window : Usize) (events : List Event) (n : ℕ)
    (hn : window.val + n = state.windows.val)
    (hevents : windowEvents n index window digits = ok (events, last))
    (hcount : countEvents events state = ok out) :
    buckets.Buckets.fill_loop0_loop0 state digits window = ok (fields out) := by
  induction n generalizing state digits window events with
  | zero =>
    simp only [windowEvents] at hevents
    cases Result.ok.inj hevents
    simp only [countEvents] at hcount
    cases Result.ok.inj hcount
    rw [buckets.Buckets.fill_loop0_loop0, loop.eq_1]
    simp [buckets.Buckets.fill_loop0_loop0.body, fields,
      show ¬ window < out.windows from by simp only [UScalar.lt_equiv]; omega]
  | succ n ih =>
    simp only [windowEvents] at hevents
    rw [bind_success] at hevents
    obtain ⟨⟨⟨magnitude, negative⟩, digits'⟩, hdigit, hevents⟩ := hevents
    simp only [Function.uncurry_def] at hevents
    rw [bind_success] at hevents
    obtain ⟨window', hwindow, hevents⟩ := hevents
    rw [bind_success] at hevents
    obtain ⟨⟨rest, last'⟩, hrest, hevents⟩ := hevents
    have heq := Result.ok.inj hevents
    cases heq
    simp only [countEvents] at hcount
    rw [bind_success] at hcount
    obtain ⟨next, hstep, hcount⟩ := hcount
    have hmeta := count_metadata state next window magnitude hstep
    have hwindowv : window'.val = window.val + 1 := by
      have hb : window.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
        have := state.windows.hBounds
        omega
      rw [add_ok window 1#usize hb] at hwindow
      cases Result.ok.inj hwindow
      rfl
    have hlo := ih next digits' window' rest (by rw [hmeta.2]; omega) hrest hcount
    rw [buckets.Buckets.fill_loop0_loop0, loop.eq_1]
    have hbody : buckets.Buckets.fill_loop0_loop0.body state digits window =
        ok (cont (next, digits', window')) := by
      simp only [buckets.Buckets.fill_loop0_loop0.body,
        show window < state.windows from by simp only [UScalar.lt_equiv]; omega,
        if_true, hdigit, bind_tc_ok, Function.uncurry_def, hstep, hwindow]
    simpa only [hbody] using hlo

theorem sign_product (negative : Bool) :
    UScalar.cast_fromBool .U32 negative * 2147483648#u32 =
      ok (if negative then 2147483648#u32 else 0#u32) := by
  cases negative <;> rfl

def placeSuffix (state : buckets.Buckets) (digits' : signed_digits.SignedDigits)
    (index window magnitude : Usize) (negative : Bool) :
    Result (ControlFlow (buckets.Buckets × signed_digits.SignedDigits × Usize)
      (Usize × Usize × Vec U32 × Vec U32 × Vec U32)) := do
  let bit ← lift (UScalar.cast_fromBool .U32 negative)
  let mask ← pairs.NEGATED
  let sign ← bit * mask
  let idx ← lift (UScalar.cast .U32 index)
  let reference ← lift (idx ||| sign)
  let self1 ← state.place window magnitude reference
  let window1 ← window + 1#usize
  ok (cont (self1, digits', window1))

theorem place_body_split (state : buckets.Buckets) (digits : signed_digits.SignedDigits)
    (index window : Usize) :
    buckets.Buckets.fill_loop2_loop0.body index state digits window =
      (if window < state.windows then do
        let ((magnitude, negative), digits') ← digits.next_digit
        placeSuffix state digits' index window magnitude negative
      else ok (done (fields state))) := rfl

theorem place_signed_suffix (state next : buckets.Buckets) (digits' : signed_digits.SignedDigits)
    (index window window' magnitude : Usize) (negative : Bool)
    (hstep : state.place window magnitude (signedReference index negative) = ok next)
    (hwindow : window + 1#usize = ok window') :
    placeSuffix state digits' index window magnitude negative =
      ok (cont (next, digits', window')) := by
  unfold placeSuffix
  have hh := congrArg (fun r : Result U32 => do
      let reference ← r
      let self1 ← state.place window magnitude reference
      let window1 ← window + 1#usize
      ok (cont (self1, digits', window1) : ControlFlow
        (buckets.Buckets × signed_digits.SignedDigits × Usize)
        (Usize × Usize × Vec U32 × Vec U32 × Vec U32)))
    (signedReference_refines index negative)
  simpa only [bind_assoc_eq, lift, bind_tc_ok, hstep, hwindow] using hh

theorem place_body_active (state : buckets.Buckets) (digits : signed_digits.SignedDigits)
    (index window : Usize) (hlt : window < state.windows) :
    buckets.Buckets.fill_loop2_loop0.body index state digits window =
      (do
        let ((m, neg), d) ← digits.next_digit
        placeSuffix state d index window m neg) :=
  (place_body_split state digits index window).trans (if_pos hlt)

theorem bind_nested_pair {α β γ δ : Type} (r : Result ((α × β) × γ))
    (f : α → β → γ → Result δ) (a : α) (b : β) (c : γ) (h : r = ok ((a, b), c)) :
    (do
      let ((x, y), z) ← r
      f x y z) = f a b c := by
  rw [h]
  rfl

theorem place_digit_active (state : buckets.Buckets) (digits digits' : signed_digits.SignedDigits)
    (index window magnitude : Usize) (negative : Bool)
    (hdigit : digits.next_digit = ok ((magnitude, negative), digits')) :
    (do
      let ((m, neg), d) ← digits.next_digit
      placeSuffix state d index window m neg) =
      placeSuffix state digits' index window magnitude negative :=
  bind_nested_pair digits.next_digit (fun m neg d => placeSuffix state d index window m neg)
    magnitude negative digits' hdigit

theorem place_window_step (state next : buckets.Buckets) (digits digits' : signed_digits.SignedDigits)
    (index window window' magnitude : Usize) (negative : Bool)
    (hlt : window < state.windows)
    (hdigit : digits.next_digit = ok ((magnitude, negative), digits'))
    (hstep : state.place window magnitude (signedReference index negative) = ok next)
    (hwindow : window + 1#usize = ok window') :
    buckets.Buckets.fill_loop2_loop0.body index state digits window =
      ok (cont (next, digits', window')) := by
  exact (place_body_active state digits index window hlt).trans
    ((place_digit_active state digits digits' index window magnitude negative hdigit).trans
      (place_signed_suffix state next digits' index window window' magnitude negative hstep hwindow))

theorem place_windows_refines (state out : buckets.Buckets) (digits last : signed_digits.SignedDigits)
    (index window : Usize) (events : List Event) (n : ℕ)
    (hn : window.val + n = state.windows.val)
    (hevents : windowEvents n index window digits = ok (events, last))
    (hplace : placeEvents events state = ok out) :
    buckets.Buckets.fill_loop2_loop0 state index digits window = ok (fields out) := by
  induction n generalizing state digits window events with
  | zero =>
    simp only [windowEvents] at hevents
    cases Result.ok.inj hevents
    simp only [placeEvents] at hplace
    cases Result.ok.inj hplace
    rw [buckets.Buckets.fill_loop2_loop0, loop.eq_1]
    simp [buckets.Buckets.fill_loop2_loop0.body, fields,
      show ¬ window < out.windows from by simp only [UScalar.lt_equiv]; omega]
  | succ n ih =>
    simp only [windowEvents] at hevents
    rw [bind_success] at hevents
    obtain ⟨⟨⟨magnitude, negative⟩, digits'⟩, hdigit, hevents⟩ := hevents
    simp only [Function.uncurry_def] at hevents
    rw [bind_success] at hevents
    obtain ⟨window', hwindow, hevents⟩ := hevents
    rw [bind_success] at hevents
    obtain ⟨⟨rest, last'⟩, hrest, hevents⟩ := hevents
    have heq := Result.ok.inj hevents
    cases heq
    simp only [placeEvents] at hplace
    rw [bind_success] at hplace
    obtain ⟨next, hstep, hplace⟩ := hplace
    have hmeta := place_metadata state next window magnitude (signedReference index negative) hstep
    have hwindowv : window'.val = window.val + 1 := by
      have hb : window.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
        have := state.windows.hBounds
        omega
      rw [add_ok window 1#usize hb] at hwindow
      cases Result.ok.inj hwindow
      rfl
    have hlo := ih next digits' window' rest (by rw [hmeta.2]; omega) hrest hplace
    rw [buckets.Buckets.fill_loop2_loop0, loop.eq_1]
    have hbody := place_window_step state next digits digits' index window window' magnitude negative
      (by simp only [UScalar.lt_equiv]; omega) hdigit hstep hwindow
    simpa only [hbody] using hlo

end LeanBlsSimd.BucketsRefines
namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8 alloc.vec

theorem countEvents_append (left right : List Event) (state : buckets.Buckets) :
    countEvents (left ++ right) state = (do
      let next ← countEvents left state
      countEvents right next) := by
  induction left generalizing state with
  | nil => simp [countEvents]
  | cons event rest ih => simp only [List.cons_append, countEvents, ih, bind_assoc_eq]

theorem placeEvents_append (left right : List Event) (state : buckets.Buckets) :
    placeEvents (left ++ right) state = (do
      let next ← placeEvents left state
      placeEvents right next) := by
  induction left generalizing state with
  | nil => simp [placeEvents]
  | cons event rest ih => simp only [List.cons_append, placeEvents, ih, bind_assoc_eq]

theorem countEvents_metadata (events : List Event) (state out : buckets.Buckets)
    (h : countEvents events state = ok out) :
    out.window_bits = state.window_bits ∧ out.windows = state.windows := by
  induction events generalizing state with
  | nil => cases Result.ok.inj h; exact ⟨rfl, rfl⟩
  | cons event rest ih =>
    simp only [countEvents, bind_success] at h
    obtain ⟨next, hstep, hrest⟩ := h
    obtain ⟨hw, hn⟩ := count_metadata state next event.window event.magnitude hstep
    obtain ⟨hw', hn'⟩ := ih next hrest
    exact ⟨hw'.trans hw, hn'.trans hn⟩

theorem placeEvents_metadata (events : List Event) (state out : buckets.Buckets)
    (h : placeEvents events state = ok out) :
    out.window_bits = state.window_bits ∧ out.windows = state.windows := by
  induction events generalizing state with
  | nil => cases Result.ok.inj h; exact ⟨rfl, rfl⟩
  | cons event rest ih =>
    simp only [placeEvents, bind_success] at h
    obtain ⟨next, hstep, hrest⟩ := h
    obtain ⟨hw, hn⟩ := place_metadata state next event.window event.magnitude event.reference hstep
    obtain ⟨hw', hn'⟩ := ih next hrest
    exact ⟨hw'.trans hw, hn'.trans hn⟩

def scalarEvents : ℕ → Slice (Array U64 4#usize) → Usize → Usize → Usize → Result (List Event)
  | 0, _, _, _, _ => ok []
  | n + 1, scalars, width, windows, index => do
    let words ← Slice.index_usize scalars index
    let digits ← signed_digits.SignedDigits.new words width
    let (events, _) ← windowEvents windows.val index 0#usize digits
    let index' ← index + 1#usize
    let rest ← scalarEvents n scalars width windows index'
    ok (events ++ rest)

theorem count_scalars_refines (state out : buckets.Buckets) (scalars : Slice (Array U64 4#usize))
    (width windows index : Usize) (events : List Event) (n : ℕ)
    (hn : index.val + n = scalars.val.length) (hw : state.windows = windows)
    (hevents : scalarEvents n scalars width windows index = ok events)
    (hcount : countEvents events state = ok out) :
    buckets.Buckets.fill_loop0 state.window_bits state.windows state.refs state.starts state.lens
      scalars width index = ok (fields out) := by
  induction n generalizing state index events with
  | zero =>
    simp only [scalarEvents] at hevents
    cases Result.ok.inj hevents
    simp only [countEvents] at hcount
    cases Result.ok.inj hcount
    rw [buckets.Buckets.fill_loop0, loop.eq_1]
    simp [buckets.Buckets.fill_loop0.body, fields,
      show ¬ index < Slice.len scalars from by change ¬ index.val < scalars.val.length; omega]
  | succ n ih =>
    simp only [scalarEvents, bind_success] at hevents
    obtain ⟨words, hwords, digits, hdigits, ⟨first, last⟩, hfirst, hevents⟩ := hevents
    simp only [Function.uncurry_def, bind_success] at hevents
    obtain ⟨index', hindex, rest, hrest, hevents⟩ := hevents
    cases Result.ok.inj hevents
    rw [countEvents_append, bind_success] at hcount
    obtain ⟨next, hstep, hrestcount⟩ := hcount
    have hmeta := countEvents_metadata first state next hstep
    have hindexv : index'.val = index.val + 1 := by
      have hb : index.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
        have hlen := (Slice.len scalars).hBounds
        change scalars.val.length < 2 ^ UScalarTy.Usize.numBits at hlen
        omega
      rw [add_ok index 1#usize hb] at hindex
      cases Result.ok.inj hindex
      rfl
    have hinner := count_windows_refines state next digits last index 0#usize first windows.val
      (by change 0 + windows.val = state.windows.val; rw [hw]; omega) hfirst hstep
    have hlo := ih next index' rest (by omega) (hmeta.2.trans hw) hrest hrestcount
    rw [buckets.Buckets.fill_loop0, loop.eq_1]
    have hbody : buckets.Buckets.fill_loop0.body scalars width state.window_bits state.windows
        state.refs state.starts state.lens index =
        ok (cont (next.window_bits, next.windows, next.refs, next.starts, next.lens, index')) := by
      simp only [buckets.Buckets.fill_loop0.body,
        show index < Slice.len scalars from by change index.val < scalars.val.length; omega,
        if_true, hwords, bind_tc_ok, hdigits]
      change (do
        let (i3, i4, v3, v4, v5) ← buckets.Buckets.fill_loop0_loop0 state digits 0#usize
        let i5 ← index + 1#usize
        ok (cont (i3, i4, v3, v4, v5, i5))) = _
      simp only [hinner, bind_tc_ok, fields, hindex]
    simpa only [hbody] using hlo

theorem place_scalars_refines (state out : buckets.Buckets) (scalars : Slice (Array U64 4#usize))
    (width windows index : Usize) (events : List Event) (n : ℕ)
    (hn : index.val + n = scalars.val.length) (hw : state.windows = windows)
    (hevents : scalarEvents n scalars width windows index = ok events)
    (hplace : placeEvents events state = ok out) :
    buckets.Buckets.fill_loop2 state.window_bits state.windows state.refs state.starts state.lens
      scalars width index = ok (fields out) := by
  induction n generalizing state index events with
  | zero =>
    simp only [scalarEvents] at hevents
    cases Result.ok.inj hevents
    simp only [placeEvents] at hplace
    cases Result.ok.inj hplace
    rw [buckets.Buckets.fill_loop2, loop.eq_1]
    simp [buckets.Buckets.fill_loop2.body, fields,
      show ¬ index < Slice.len scalars from by change ¬ index.val < scalars.val.length; omega]
  | succ n ih =>
    simp only [scalarEvents, bind_success] at hevents
    obtain ⟨words, hwords, digits, hdigits, ⟨first, last⟩, hfirst, hevents⟩ := hevents
    simp only [Function.uncurry_def, bind_success] at hevents
    obtain ⟨index', hindex, rest, hrest, hevents⟩ := hevents
    cases Result.ok.inj hevents
    rw [placeEvents_append, bind_success] at hplace
    obtain ⟨next, hstep, hrestplace⟩ := hplace
    have hmeta := placeEvents_metadata first state next hstep
    have hindexv : index'.val = index.val + 1 := by
      have hb : index.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
        have hlen := (Slice.len scalars).hBounds
        change scalars.val.length < 2 ^ UScalarTy.Usize.numBits at hlen
        omega
      rw [add_ok index 1#usize hb] at hindex
      cases Result.ok.inj hindex
      rfl
    have hinner := place_windows_refines state next digits last index 0#usize first windows.val
      (by change 0 + windows.val = state.windows.val; rw [hw]; omega) hfirst hstep
    have hlo := ih next index' rest (by omega) (hmeta.2.trans hw) hrest hrestplace
    rw [buckets.Buckets.fill_loop2, loop.eq_1]
    have hbody : buckets.Buckets.fill_loop2.body scalars width state.window_bits state.windows
        state.refs state.starts state.lens index =
        ok (cont (next.window_bits, next.windows, next.refs, next.starts, next.lens, index')) := by
      simp only [buckets.Buckets.fill_loop2.body,
        show index < Slice.len scalars from by change index.val < scalars.val.length; omega,
        if_true, hwords, bind_tc_ok, hdigits]
      change (do
        let (i3, i4, v3, v4, v5) ← buckets.Buckets.fill_loop2_loop0 state index digits 0#usize
        let i5 ← index + 1#usize
        ok (cont (i3, i4, v3, v4, v5, i5))) = _
      simp only [hinner, bind_tc_ok, fields, hindex]
    simpa only [hbody] using hlo

end LeanBlsSimd.BucketsRefines
namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8 alloc.vec

theorem windowEvents_succeeds (n : ℕ) (index window windows : Usize) (digits : signed_digits.SignedDigits)
    (hwl : 1 ≤ digits.window_bits.val) (hwh : digits.window_bits.val ≤ 8)
    (hc : digits.carry.val ≤ 1) (hb : digits.bit.val + digits.window_bits.val * n ≤ 256)
    (hw : window.val + n ≤ windows.val) :
    ∃ events last, windowEvents n index window digits = ok (events, last) ∧
      events.length = n ∧ (∀ event ∈ events, Fits digits.window_bits windows event) := by
  induction n generalizing window digits with
  | zero => exact ⟨[], digits, rfl, rfl, by simp⟩
  | succ n ih =>
    obtain ⟨magnitude, negative, digits', hdigit, _, hwidth, hbit, hcarry, _, hmag, _⟩ :=
      SignedDigits.next_digit_refines digits (by nlinarith) hwl hwh hc
    let window' : Usize := UScalar.ofNatCore (window.val + 1) (by
      have := windows.hBounds
      omega)
    have hwindow' : window'.val = window.val + 1 := rfl
    obtain ⟨rest, last, hrest, hlen, hfits⟩ := ih window' digits'
      (hwidth.symm ▸ hwl) (hwidth.symm ▸ hwh) (by rw [hcarry]; cases negative <;> decide)
      (by rw [hbit, hwidth]; nlinarith) (by omega)
    refine ⟨{window, magnitude, reference := signedReference index negative} :: rest, last,
      ?_, by simp only [List.length_cons, hlen], ?_⟩
    · simp only [windowEvents, hdigit, bind_tc_ok, Function.uncurry_def]
      rw [add_ok window 1#usize (by have := windows.hBounds; change window.val + 1 < _; omega)]
      simp only [bind_tc_ok]
      change (do
        let (rest, last) ← windowEvents n index window' digits'
        ok (({window, magnitude, reference := signedReference index negative} : Event) :: rest, last)) = _
      rw [hrest]
      rfl
    · intro event he
      rcases List.mem_cons.mp he with he | he
      · subst event
        exact ⟨by change window.val < windows.val; omega, hmag⟩
      · simpa only [hwidth] using hfits event he

theorem scalarEvents_succeeds (n : ℕ) (scalars : Slice (Array U64 4#usize))
    (width windows index : Usize) (hwl : 1 ≤ width.val) (hwh : width.val ≤ 8)
    (hb : width.val * windows.val ≤ 256) (hi : index.val + n ≤ scalars.val.length) :
    ∃ events, scalarEvents n scalars width windows index = ok events ∧
      events.length = n * windows.val ∧ (∀ event ∈ events, Fits width windows event) := by
  induction n generalizing index with
  | zero => exact ⟨[], rfl, by simp, by simp⟩
  | succ n ih =>
    have hil : index.val < scalars.val.length := by omega
    let words : Array U64 4#usize := scalars.val[index.val]
    have hwords : Slice.index_usize scalars index = ok words := by
      simp [Slice.index_usize, words, List.getElem?_eq_getElem hil]
    let digits := SignedDigits.initial words width
    have hdigits : signed_digits.SignedDigits.new words width = ok digits := rfl
    obtain ⟨first, last, hfirst, hfirstlen, hfits⟩ := windowEvents_succeeds windows.val index
      0#usize windows digits hwl hwh (by change 0 ≤ 1; omega)
      (by change 0 + width.val * windows.val ≤ 256; omega) (by change 0 + windows.val ≤ windows.val; omega)
    let index' : Usize := UScalar.ofNatCore (index.val + 1) (by
      have hlen := (Slice.len scalars).hBounds
      change scalars.val.length < 2 ^ UScalarTy.Usize.numBits at hlen
      omega)
    have hindex' : index'.val = index.val + 1 := rfl
    obtain ⟨rest, hrest, hlen, hrestfits⟩ := ih index' (by omega)
    refine ⟨first ++ rest, ?_, ?_, ?_⟩
    · simp only [scalarEvents, hwords, bind_tc_ok, hdigits, hfirst, Function.uncurry_def]
      rw [add_ok index 1#usize (by
        have hlen := (Slice.len scalars).hBounds
        change scalars.val.length < 2 ^ UScalarTy.Usize.numBits at hlen
        change index.val + 1 < _
        omega)]
      simp only [bind_tc_ok]
      change (do
        let rest ← scalarEvents n scalars width windows index'
        ok (first ++ rest)) = _
      rw [hrest]
      rfl
    · rw [List.length_append, hfirstlen, hlen]
      ring
    · intro event he
      rcases List.mem_append.mp he with he | he
      · exact hfits event he
      · exact hrestfits event he

end LeanBlsSimd.BucketsRefines
namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8 alloc.vec

def windows127 (width : Usize) : Usize :=
  UScalar.ofNatCore (127 / width.val + 1) (lt_of_lt_of_le
    (by have := Nat.div_le_self 127 width.val; omega : 127 / width.val + 1 < 2 ^ 32)
    two_pow_32_le_usize)

def selectedWidth (n : ℕ) : Usize :=
  if n < 128 then 4#usize else if n < 1024 then 6#usize else 8#usize

theorem selectedWidth_bounds (n : ℕ) :
    1 ≤ (selectedWidth n).val ∧ (selectedWidth n).val ≤ 8 := by
  unfold selectedWidth
  split_ifs <;> decide

theorem windows127_bits (width : Usize) (hw : width.val ≤ 8) :
    width.val * (windows127 width).val ≤ 256 := by
  change width.val * (127 / width.val + 1) ≤ 256
  have := Nat.mul_div_le 127 width.val
  nlinarith

theorem listCount127_bound (width : Usize) (hw : width.val ≤ 8) :
    (windows127 width).val * 2 ^ (width.val - 1) < 2 ^ 32 := by
  have hp : 2 ^ (width.val - 1) ≤ 128 := by
    exact Nat.pow_le_pow_right (by decide : 0 < 2) (show width.val - 1 ≤ 7 by omega)
  have hwin : (windows127 width).val ≤ 128 := by
    change 127 / width.val + 1 ≤ 128
    have := Nat.div_le_self 127 width.val
    omega
  nlinarith

theorem vec_resize_zero (size : Usize) :
    ∃ v : Vec U32, Vec.resize core.clone.CloneU32 (Vec.new U32) size 0#u32 = ok v ∧
      v.val = List.replicate size.val 0#u32 := by
  obtain ⟨v, hv, heq⟩ := WP.spec_imp_exists (Vec.resize_spec core.clone.CloneU32 (Vec.new U32) size 0#u32 rfl)
  exact ⟨v, hv, by simpa only [Vec.new, List.resize, List.take_nil, List.length_nil, Nat.sub_zero, List.nil_append] using heq⟩

def fillCore (state : buckets.Buckets) (scalars : Slice (Array U64 4#usize))
    (width windows lists : Usize) : Result buckets.Buckets := do
  let v ← Vec.clear Global state.lens
  let v1 ← Vec.resize core.clone.CloneU32 v lists 0#u32
  let (i4, i5, v2, v3, v4) ←
    buckets.Buckets.fill_loop0 width windows state.refs state.starts v1 scalars width 0#usize
  let v5 ← Vec.clear Global v3
  let (v6, v7, total) ← buckets.Buckets.fill_loop1 v5 v4 lists 0#u32 0#usize
  let v8 ← Vec.clear Global v2
  let i6 ← lift (UScalar.cast .Usize total)
  let v9 ← Vec.resize core.clone.CloneU32 v8 i6 0#u32
  let (i7, i8, v10, v11, v12) ← buckets.Buckets.fill_loop2 i4 i5 v9 v6 v7 scalars width 0#usize
  ok {window_bits := i7, windows := i8, refs := v10, starts := v11, lens := v12}

theorem fill_split (state : buckets.Buckets) (scalars : Slice (Array U64 4#usize)) (bits : Usize) :
    state.fill scalars bits = (do
      massert (bits < 256#usize)
      let width ← (if Slice.len scalars < 128#usize then ok 4#usize
        else if Slice.len scalars < 1024#usize then ok 6#usize else ok 8#usize)
      let q ← bits / width
      let windows ← q + 1#usize
      let shift ← width - 1#usize
      let lists ← windows <<< shift
      fillCore state scalars width windows lists) := by
  unfold buckets.Buckets.fill buckets.NARROWEST_WINDOW_BITS
  rfl

theorem fillCore_refines (state : buckets.Buckets) (scalars : Slice (Array U64 4#usize))
    (width windows lists : Usize) (events : List Event)
    (hwl : 1 ≤ width.val) (hwh : width.val ≤ 8)
    (hlists : lists.val = windows.val * 2 ^ (width.val - 1))
    (hln : lists.val < 2 ^ 32)
    (htrace : scalarEvents scalars.val.length scalars width windows 0#usize = ok events)
    (hfits : ∀ event ∈ events, Fits width windows event) (helen : events.length < 2 ^ 32) :
    ∃ out, fillCore state scalars width windows lists = ok out ∧
      out.window_bits = width ∧ out.windows = windows ∧
      ∀ i < lists.val, bucketSlice out i = eventReferences width events i := by
  obtain ⟨lens, hlens, hlensv⟩ := vec_resize_zero lists
  let counted : buckets.Buckets := {state with window_bits := width, windows, lens}
  have hc0 : Counts counted (windows.val * 2 ^ (width.val - 1)) (fun _ => []) := by
    refine ⟨?_, ?_⟩
    · change lens.val.length = _
      rw [hlensv, List.length_replicate, hlists]
    · intro i hi
      change lens.val[i]!.val = 0
      rw [hlensv, List.getElem!_replicate 0#u32 (by omega)]
      rfl
  obtain ⟨countOut, hcount, hc, hcw, hcn, _, _⟩ := countEvents_empty counted events hwl hwh
    (by change windows.val * 2 ^ (width.val - 1) < 2 ^ 32; rw [← hlists]; exact hln) hfits hc0 helen
  have hcountLoop := count_scalars_refines counted countOut scalars width windows 0#usize events
    scalars.val.length (by change 0 + scalars.val.length = scalars.val.length; omega) rfl htrace hcount
  have hcap : prefixSum (fun i => (eventReferences width events i).length) lists.val < 2 ^ 32 :=
    lt_of_le_of_lt (eventReferences_total_bound width events lists.val) helen
  obtain ⟨starts, lengths, total, hprefix, hp⟩ := prefix_from_counts countOut lists
    (eventReferences width events) (by simpa only [hlists] using hc) hln hcap
  obtain ⟨refs, hrefs, hrefsv⟩ := vec_resize_zero (UScalar.cast .Usize total)
  let placed : buckets.Buckets := {window_bits := width, windows, refs, starts, lens := lengths}
  have hpacked : Packed placed lists.val
      (prefixSum (fun i => (eventReferences width events i).length))
      (fun i => (eventReferences width events i).length) (fun _ => []) := by
    apply prefix_packed_empty placed lists.val _ total hp
    change refs.val.length = total.val
    rw [hrefsv, List.length_replicate, cast_Usize_val]
  obtain ⟨out, hplace, hrecover, how, hon, _⟩ := placeEvents_recovers placed events hwl hwh
    (by change windows.val * 2 ^ (width.val - 1) < 2 ^ 32; rw [← hlists]; exact hln) hfits (by simpa only [hlists] using hpacked)
  have hplaceLoop := place_scalars_refines placed out scalars width windows 0#usize events scalars.val.length
    (by change 0 + scalars.val.length = scalars.val.length; omega) rfl htrace hplace
  refine ⟨out, ?_, how, hon, ?_⟩
  · unfold fillCore
    simp only [Vec.clear, bind_tc_ok]
    rw [hlens]
    simp only [bind_tc_ok]
    change (do
      let (i4, i5, v2, v3, v4) ← buckets.Buckets.fill_loop0 counted.window_bits counted.windows
        counted.refs counted.starts counted.lens scalars width 0#usize
      let (v6, v7, total) ← buckets.Buckets.fill_loop1 (Vec.new U32) v4 lists 0#u32 0#usize
      let v9 ← Vec.resize core.clone.CloneU32 (Vec.new U32) (UScalar.cast .Usize total) 0#u32
      let (i7, i8, v10, v11, v12) ← buckets.Buckets.fill_loop2 i4 i5 v9 v6 v7 scalars width 0#usize
      ok ({window_bits := i7, windows := i8, refs := v10, starts := v11, lens := v12} : buckets.Buckets)) = _
    rw [hcountLoop]
    simp only [bind_tc_ok, fields, hcw, hcn]
    rw [hprefix]
    simp only [bind_tc_ok]
    rw [hrefs]
    simp only [bind_tc_ok]
    change (do
      let (i7, i8, v10, v11, v12) ← buckets.Buckets.fill_loop2 placed.window_bits placed.windows
        placed.refs placed.starts placed.lens scalars width 0#usize
      ok ({window_bits := i7, windows := i8, refs := v10, starts := v11, lens := v12} : buckets.Buckets)) = _
    rw [hplaceLoop]
    rfl
  · simpa only [hlists] using hrecover

theorem shiftLeft_value (x shift : Usize) (hshift : shift.val < UScalarTy.Usize.numBits)
    (hb : x.val * 2 ^ shift.val < 2 ^ 32) :
    x <<< shift = ok (UScalar.ofNatCore (x.val * 2 ^ shift.val)
      (lt_of_lt_of_le hb two_pow_32_le_usize)) := by
  rw [shiftLeft_ok x shift hshift]
  congr 1
  apply UScalar.eq_of_val_eq
  change (x.bv.shiftLeft shift.val).toNat = _
  rw [show (x.bv.shiftLeft shift.val).toNat = x.val <<< shift.val % 2 ^ UScalarTy.Usize.numBits
    from BitVec.toNat_shiftLeft]
  rw [Nat.shiftLeft_eq, Nat.mod_eq_of_lt (lt_of_lt_of_le hb two_pow_32_le_usize)]
  rfl

theorem fill127_setup (state : buckets.Buckets) (scalars : Slice (Array U64 4#usize)) :
    state.fill scalars 127#usize =
      fillCore state scalars (selectedWidth scalars.val.length) (windows127 (selectedWidth scalars.val.length))
        (UScalar.ofNatCore ((windows127 (selectedWidth scalars.val.length)).val *
          2 ^ ((selectedWidth scalars.val.length).val - 1))
          (lt_of_lt_of_le (listCount127_bound _ (selectedWidth_bounds _).2) two_pow_32_le_usize)) := by
  let width := selectedWidth scalars.val.length
  have hwl : 1 ≤ width.val := (selectedWidth_bounds _).1
  have hwh : width.val ≤ 8 := (selectedWidth_bounds _).2
  have hwidth : (if Slice.len scalars < 128#usize then ok 4#usize
      else if Slice.len scalars < 1024#usize then ok 6#usize else ok 8#usize) = ok width := by
    change (if scalars.val.length < 128 then ok 4#usize
      else if scalars.val.length < 1024 then ok 6#usize else ok 8#usize) = _
    unfold width selectedWidth
    split_ifs <;> rfl
  rw [fill_split]
  simp only [show (127#usize < 256#usize) from by decide, massert, if_true, bind_tc_ok, hwidth]
  rw [div_ok 127#usize width (by omega)]
  simp only [bind_tc_ok]
  rw [usize_add_ok (UScalar.ofNatCore ((127#usize).val / width.val)
    (lt_of_le_of_lt (Nat.div_le_self _ _) (127#usize).hBounds)) 1#usize (by
      change 127 / width.val + 1 < 2 ^ 32
      have := Nat.div_le_self 127 width.val
      omega)]
  simp only [bind_tc_ok]
  rw [sub_ok width 1#usize hwl]
  simp only [bind_tc_ok]
  let shift : Usize := UScalar.ofNatCore (width.val - 1)
    (lt_of_le_of_lt (Nat.sub_le _ _) width.hBounds)
  change (do
    let lists ← windows127 width <<< shift
    fillCore state scalars width (windows127 width) lists) = _
  rw [shiftLeft_value (windows127 width) shift (by
    have hu : 32 ≤ UScalarTy.Usize.numBits := by
      rcases System.Platform.numBits_eq with h | h <;> simp [UScalarTy.numBits, h]
    change width.val - 1 < _
    omega) (listCount127_bound width hwh)]
  rfl

theorem fill127_refines (state : buckets.Buckets) (scalars : Slice (Array U64 4#usize))
    (hsize : scalars.val.length * (windows127 (selectedWidth scalars.val.length)).val < 2 ^ 32) :
    ∃ (events : List Event) (out : buckets.Buckets),
      scalarEvents scalars.val.length scalars (selectedWidth scalars.val.length)
        (windows127 (selectedWidth scalars.val.length)) 0#usize = ok events ∧
      state.fill scalars 127#usize = ok out ∧
      events.length = scalars.val.length * (windows127 (selectedWidth scalars.val.length)).val ∧
      out.window_bits = selectedWidth scalars.val.length ∧
      out.windows = windows127 (selectedWidth scalars.val.length) ∧
      ∀ i < out.windows.val * 2 ^ (out.window_bits.val - 1),
        bucketSlice out i = eventReferences (selectedWidth scalars.val.length) events i := by
  let width := selectedWidth scalars.val.length
  obtain ⟨hwl, hwh⟩ := selectedWidth_bounds scalars.val.length
  obtain ⟨events, htrace, hlen, hfits⟩ := scalarEvents_succeeds scalars.val.length scalars width
    (windows127 width) 0#usize hwl hwh (windows127_bits width hwh)
    (by change 0 + scalars.val.length ≤ scalars.val.length; omega)
  let lists : Usize := UScalar.ofNatCore ((windows127 width).val * 2 ^ (width.val - 1))
    (lt_of_lt_of_le (listCount127_bound width hwh) two_pow_32_le_usize)
  obtain ⟨out, hout, how, hon, hrecovery⟩ := fillCore_refines state scalars width (windows127 width)
    lists events hwl hwh rfl (listCount127_bound width hwh) htrace hfits (by rw [hlen]; exact hsize)
  refine ⟨events, out, htrace, ?_, hlen, how, hon, ?_⟩
  · rw [fill127_setup]
    exact hout
  · intro i hi
    apply hrecovery i
    simpa only [how, hon] using hi

end LeanBlsSimd.BucketsRefines
namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8 alloc.vec

theorem digits_run_succ_first (n : ℕ) (digits : signed_digits.SignedDigits) :
    SignedDigits.run (n + 1) digits = (do
      let (digit, next) ← digits.next_digit
      let (rest, last) ← SignedDigits.run n next
      ok (digit :: rest, last)) := by
  induction n generalizing digits with
  | zero => simp only [SignedDigits.run, bind_tc_ok, Function.uncurry_def]; rfl
  | succ n ih =>
    change (do
      let (ds, state) ← SignedDigits.run (n + 1) digits
      let (d, last) ← state.next_digit
      ok (ds ++ [d], last)) = _
    rw [ih digits]
    cases hfirst : digits.next_digit with
    | fail e => simp only [bind_tc_fail]
    | div => simp only [bind_tc_div]
    | ok pair =>
      rcases pair with ⟨d, next⟩
      simp only [bind_tc_ok, Function.uncurry_def, SignedDigits.run]
      cases hrest : SignedDigits.run n next with
      | fail e => simp only [bind_tc_fail]
      | div => simp only [bind_tc_div]
      | ok pair =>
        rcases pair with ⟨rest, last⟩
        simp only [bind_tc_ok]
        cases hlast : last.next_digit with
        | fail e => simp only [bind_tc_fail]
        | div => simp only [bind_tc_div]
        | ok pair =>
          rcases pair with ⟨digit, final⟩
          simp only [bind_tc_ok, List.cons_append]

def eventDigit (event : Event) : Usize × Bool :=
  (event.magnitude, decide (event.reference.val / 2 ^ 31 = 1))

theorem eventDigit_reference (index window magnitude : Usize) (negative : Bool)
    (hi : index.val < 2 ^ 31) :
    eventDigit {window, magnitude, reference := signedReference index negative} = (magnitude, negative) := by
  unfold eventDigit
  rw [signedReference_sign index negative hi]
  cases negative <;> rfl

theorem windowEvents_run (n : ℕ) (index window : Usize) (digits last : signed_digits.SignedDigits)
    (events : List Event) (hi : index.val < 2 ^ 31)
    (hevents : windowEvents n index window digits = ok (events, last)) :
    SignedDigits.run n digits = ok (events.map eventDigit, last) := by
  induction n generalizing digits window events with
  | zero =>
    simp only [windowEvents] at hevents
    cases Result.ok.inj hevents
    rfl
  | succ n ih =>
    simp only [windowEvents] at hevents
    rw [bind_success] at hevents
    obtain ⟨⟨⟨magnitude, negative⟩, digits'⟩, hdigit, hevents⟩ := hevents
    simp only [Function.uncurry_def] at hevents
    rw [bind_success] at hevents
    obtain ⟨window', _, hevents⟩ := hevents
    rw [bind_success] at hevents
    obtain ⟨⟨rest, last'⟩, hrest, hevents⟩ := hevents
    cases Result.ok.inj hevents
    rw [digits_run_succ_first, hdigit]
    simp only [bind_tc_ok, Function.uncurry_def, ih window' digits' rest hrest,
      List.map_cons, eventDigit_reference index window magnitude negative hi]

theorem windowEvents_scalar (words : Array U64 4#usize) (width index : Usize)
    (events : List Event) (last : signed_digits.SignedDigits)
    (hwl : 1 ≤ width.val) (hwh : width.val ≤ 8) (hi : index.val < 2 ^ 31)
    (hscalar : SignedDigits.value words < 2 ^ 127)
    (hevents : windowEvents (windows127 width).val index 0#usize (SignedDigits.initial words width) =
      ok (events, last)) :
    SignedDigits.digitSum width.val (events.map eventDigit) = SignedDigits.value words ∧
      last.carry.val = 0 := by
  obtain ⟨digits, final, hrun, _, hcarry, _, hsum⟩ := SignedDigits.run_complete words width hwl hwh hscalar
  have hrun' := windowEvents_run (windows127 width).val index 0#usize
    (SignedDigits.initial words width) last events hi hevents
  have heq : (digits, final) = (events.map eventDigit, last) := Result.ok.inj (hrun.symm.trans hrun')
  cases heq
  exact ⟨hsum, hcarry⟩

theorem windowEvents_coordinates (n : ℕ) (index window : Usize)
    (digits last : signed_digits.SignedDigits) (events : List Event) (hi : index.val < 2 ^ 31)
    (hb : window.val + n < 2 ^ 32)
    (hevents : windowEvents n index window digits = ok (events, last)) :
    ∀ j (hj : j < events.length),
      (events[j]'hj).window.val = window.val + j ∧
      (events[j]'hj).reference.val % 2 ^ 31 = index.val := by
  induction n generalizing digits window events with
  | zero =>
    simp only [windowEvents] at hevents
    cases Result.ok.inj hevents
    intro j hj
    simp only [List.length_nil] at hj
    omega
  | succ n ih =>
    simp only [windowEvents] at hevents
    rw [bind_success] at hevents
    obtain ⟨⟨⟨magnitude, negative⟩, digits'⟩, hdigit, hevents⟩ := hevents
    simp only [Function.uncurry_def] at hevents
    rw [bind_success] at hevents
    obtain ⟨window', hwindow, hevents⟩ := hevents
    rw [bind_success] at hevents
    obtain ⟨⟨rest, last'⟩, hrest, hevents⟩ := hevents
    cases Result.ok.inj hevents
    have hwindowv : window'.val = window.val + 1 := by
      rw [usize_add_ok window 1#usize (by change window.val + 1 < 2 ^ 32; omega)] at hwindow
      cases Result.ok.inj hwindow
      rfl
    intro j hj
    cases j with
    | zero => exact ⟨rfl, signedReference_index index negative hi⟩
    | succ j =>
      obtain ⟨hpos, href⟩ := ih window' digits' rest (by omega) hrest j (by simp only [List.length_cons] at hj; omega)
      refine ⟨?_, href⟩
      change (rest[j]'_).window.val = window.val + (j + 1)
      exact hpos.trans (by omega)

end LeanBlsSimd.BucketsRefines
