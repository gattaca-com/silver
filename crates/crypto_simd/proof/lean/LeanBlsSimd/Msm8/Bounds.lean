import LeanBlsSimd.Msm8.Fill

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.MsmBounds
open BucketsRefines

/-- The window-width expression copied from generated Buckets.fill. -/
def chooseWidth (scalars : Slice (Array U64 4#usize)) : Result Usize := do
  let i := Slice.len scalars
  if i < 128#usize then ok 4#usize else
    let i1 := Slice.len scalars
    if i1 < 1024#usize then ok 6#usize else ok 8#usize

theorem chooseWidth_refines (scalars : Slice (Array U64 4#usize)) :
    chooseWidth scalars = ok (selectedWidth scalars.val.length) := by
  simp only [chooseWidth,selectedWidth,UScalar.lt_equiv,Slice.len,Usize.ofNatCore_val_eq]
  change (if scalars.val.length < 128 then ok 4#usize else
    if scalars.val.length < 1024 then ok 6#usize else ok 8#usize) = _
  split_ifs <;> rfl

theorem selected_options (n : ℕ) :
    ((selectedWidth n).val = 4 ∧ (windows127 (selectedWidth n)).val = 32) ∨
    ((selectedWidth n).val = 6 ∧ (windows127 (selectedWidth n)).val = 22) ∨
    ((selectedWidth n).val = 8 ∧ (windows127 (selectedWidth n)).val = 16) := by
  unfold selectedWidth
  split_ifs <;> decide

theorem selected_geometry (n : ℕ) :
    4 ≤ (selectedWidth n).val ∧ (selectedWidth n).val ≤ 8 ∧
    1 ≤ (windows127 (selectedWidth n)).val ∧ (windows127 (selectedWidth n)).val ≤ 32 ∧
    (windows127 (selectedWidth n)).val = (127 + (selectedWidth n).val - 1) / (selectedWidth n).val ∧
    127 < (selectedWidth n).val * (windows127 (selectedWidth n)).val ∧
    (selectedWidth n).val * (windows127 (selectedWidth n)).val ≤ 132 ∧
    2 ^ ((selectedWidth n).val - 1) ≤ 128 ∧
    (windows127 (selectedWidth n)).val * 2 ^ ((selectedWidth n).val - 1) ≤ 2048 := by
  rcases selected_options n with ⟨hw,hn⟩ | ⟨hw,hn⟩ | ⟨hw,hn⟩ <;> rw [hw,hn] <;> decide

theorem selected_groups (n : ℕ) :
    1 ≤ ((windows127 (selectedWidth n)).val - 1) / 8 + 1 ∧
    ((windows127 (selectedWidth n)).val - 1) / 8 + 1 ≤ 4 ∧
    8 * (((windows127 (selectedWidth n)).val - 1) / 8 + 1) ≤ 32 := by
  rcases selected_options n with ⟨_,hn⟩ | ⟨_,hn⟩ | ⟨_,hn⟩ <;> rw [hn] <;> decide

end LeanBlsSimd.MsmBounds
namespace LeanBlsSimd.MsmBounds

structure Resources (n windows : ℕ) : Prop where
  originals31 : 2 * n < 2 ^ 31
  references32 : 2 * n * windows < 2 ^ 32
  capacity31 : 2 * n + n * windows < 2 ^ 31
  rows32 : 2 * (2 * n + n * windows) < 2 ^ 32
  independence31 : 2 * n + 2 * n * windows < 2 ^ 31
  bucket32 : 2 * n + 1 < 2 ^ 32
  padded32 : n * windows + 15 < 2 ^ 32

theorem resources (n windows : ℕ) (hn : n ≤ 2 ^ 24) (hw : windows ≤ 32) :
    Resources n windows := by
  have hmul : n * windows ≤ 32 * n := by nlinarith
  have hmul2 : 2 * n * windows = 2 * (n * windows) := by ring
  constructor <;> nlinarith

theorem selected_resources (n : ℕ) (hn : n ≤ 2 ^ 24) :
    Resources n (BucketsRefines.windows127 (BucketsRefines.selectedWidth (2 * n))).val :=
  resources n _ hn (selected_geometry (2 * n)).2.2.2.1

theorem refs_resource_bounds (n windows refs : ℕ) (h : Resources n windows)
    (href : refs ≤ 2 * n * windows) :
    refs < 2 ^ 32 ∧ refs / 2 ≤ n * windows ∧
      2 * n + n * windows + refs / 2 < 2 ^ 31 := by
  have he : 2 * n * windows = 2 * (n * windows) := by ring
  have := h.references32
  constructor
  · omega
  constructor
  · omega
  · have := h.independence31
    omega

theorem bucket_resource_bound (n windows length : ℕ) (h : Resources n windows)
    (hlen : length ≤ 2 * n) : length + 1 < 2 ^ 32 := by
  have := h.bucket32
  omega

theorem sentinel_bound (n : ℕ) (hn : 1 ≤ n) : 0 < 2 * n ∧ 0 < 2 ^ 31 := by omega

theorem padded_groups (jobs : ℕ) (hj : 1 ≤ jobs) :
    let groups := ((jobs - 1) / 16 + 1) * 2
    groups % 2 = 0 ∧ jobs ≤ groups * 8 ∧ groups * 8 ≤ jobs + 15 := by
  dsimp only
  omega

theorem padded_resource_bounds (n windows jobs : ℕ) (h : Resources n windows)
    (hj : 1 ≤ jobs) (hjobs : jobs ≤ n * windows) :
    let groups := ((jobs - 1) / 16 + 1) * 2
    groups % 2 = 0 ∧ jobs ≤ groups * 8 ∧ groups * 8 < 2 ^ 32 := by
  obtain ⟨he,hl,hu⟩ := padded_groups jobs hj
  dsimp only at he hl hu ⊢
  have := h.padded32
  exact ⟨he,hl,by omega⟩

end LeanBlsSimd.MsmBounds
namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8

theorem eventReferences_append (width : Usize) (left right : List Event) (i : ℕ) :
    eventReferences width (left ++ right) i = eventReferences width left i ++ eventReferences width right i := by
  induction left with
  | nil => rfl
  | cons event rest ih => simp only [List.cons_append,eventReferences,ih,List.append_assoc]

private theorem eventReferences_before (width : Usize) (events : List Event) (floor i : ℕ)
    (hfloor : ∀ e ∈ events, floor ≤ e.window.val * 2 ^ (width.val - 1)) (hi : i < floor) :
    eventReferences width events i = [] := by
  induction events with
  | nil => rfl
  | cons e rest ih =>
    have hnot : ¬ (e.magnitude ≠ 0#usize ∧ eventIndex width e = i) := by
      rintro ⟨hm,he⟩
      have hmpos : 0 < e.magnitude.val := by
        have : e.magnitude.val ≠ 0 := by
          intro hz
          apply hm
          apply UScalar.eq_of_val_eq
          exact hz
        omega
      have hlo := hfloor e (by simp)
      simp only [eventIndex,listIndex] at he
      omega
    simp only [eventReferences,hnot,if_false,List.nil_append]
    exact ih (fun e he => hfloor e (List.mem_cons_of_mem _ he))

theorem eventReferences_window_bound (width : Usize) (events : List Event) (start i : ℕ)
    (hcoords : ∀ j (hj : j < events.length), (events[j]'hj).window.val = start + j)
    (hmag : ∀ e ∈ events, e.magnitude.val ≤ 2 ^ (width.val - 1)) :
    (eventReferences width events i).length ≤ 1 := by
  induction events generalizing start with
  | nil => simp [eventReferences]
  | cons e rest ih =>
    have hew : e.window.val = start := by simpa using hcoords 0 (by simp)
    have hrest : ∀ j (hj : j < rest.length), (rest[j]'hj).window.val = start + 1 + j := by
      intro j hj
      have h := hcoords (j + 1) (by simpa using Nat.succ_lt_succ hj)
      simpa only [List.getElem_cons_succ,Nat.add_assoc,Nat.add_comm 1 j] using h
    have hrestmag := fun e he => hmag e (List.mem_cons_of_mem _ he)
    simp only [eventReferences]
    split
    · rename_i hselected
      have htarget : i < (start + 1) * 2 ^ (width.val - 1) := by
        have hm := hmag e (by simp)
        have he := hselected.2
        simp only [eventIndex,listIndex,hew] at he
        have hh : 0 < 2 ^ (width.val - 1) := Nat.two_pow_pos _
        simp only [Nat.add_mul,Nat.one_mul]
        omega
      have hempty := eventReferences_before width rest ((start + 1) * 2 ^ (width.val - 1)) i
        (fun event hm => by
          obtain ⟨j,hj,he⟩ := List.mem_iff_getElem.mp hm
          subst event
          rw [hrest j hj]
          exact Nat.mul_le_mul_right _ (by omega)) htarget
      simp only [hempty,List.append_nil,List.length_singleton,Nat.le_refl]
    · simpa only [List.nil_append] using ih (start + 1) hrest hrestmag

theorem scalarEvents_bucket_bound (n : ℕ) (scalars : Slice (Array U64 4#usize))
    (width windows index : Usize) (events : List Event)
    (hi : index.val + n < 2 ^ 31) (hw : windows.val < 2 ^ 32)
    (htrace : scalarEvents n scalars width windows index = ok events)
    (hfits : ∀ event ∈ events, Fits width windows event) (i : ℕ) :
    (eventReferences width events i).length ≤ n := by
  induction n generalizing index events with
  | zero =>
    simp only [scalarEvents] at htrace
    cases Result.ok.inj htrace
    simp [eventReferences]
  | succ n ih =>
    simp only [scalarEvents,bind_success] at htrace
    obtain ⟨words,_,digits,_,⟨first,last⟩,hfirst,htrace⟩ := htrace
    simp only [Function.uncurry_def,bind_success] at htrace
    obtain ⟨index',hindex,rest,hrest,htrace⟩ := htrace
    cases Result.ok.inj htrace
    have hindexv : index'.val = index.val + 1 := by
      have hsize := two_pow_32_le_usize
      rw [add_ok index 1#usize (by change index.val + 1 < _; omega)] at hindex
      cases Result.ok.inj hindex
      rfl
    have hcoords := windowEvents_coordinates windows.val index 0#usize digits last first
      (by omega) (by simpa using hw) hfirst
    have hbound := eventReferences_window_bound width first 0 i
      (fun j hj => (hcoords j hj).1)
      (fun e he => (hfits e (List.mem_append_left _ he)).2)
    have hrestbound := ih index' rest (by omega) hrest
      (fun e he => hfits e (List.mem_append_right _ he))
    rw [eventReferences_append,List.length_append]
    omega

end LeanBlsSimd.BucketsRefines
namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8 alloc.vec

private theorem mutable_back_length {A : Type} (v : Vec A) (index : Usize)
    (value : A) (back : A → Vec A)
    (h : Vec.index_mut (core.slice.index.SliceIndexUsizeSlice A) v index = ok (value,back))
    (replacement : A) : (back replacement).val.length = v.val.length := by
  rw [Vec.index_mut_slice_index] at h
  unfold Vec.index_mut_usize at h
  split at h
  · cases Result.ok.inj h
    simp [Vec.set]
  · cases h
  · cases h

theorem place_refs_length (state next : buckets.Buckets) (window magnitude : Usize) (reference : U32)
    (h : state.place window magnitude reference = ok next) :
    next.refs.val.length = state.refs.val.length := by
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
    obtain ⟨⟨value, refsBack⟩, hback, h⟩ := h
    simp only [Function.uncurry_def] at h
    rw [bind_success] at h
    obtain ⟨⟨value, lensBack⟩, _, h⟩ := h
    rw [bind_success] at h
    obtain ⟨count, _, h⟩ := h
    cases Result.ok.inj h
    exact mutable_back_length _ _ _ _ hback _
  · cases Result.ok.inj h
    rfl

theorem placeEvents_refs_length (events : List Event) (state out : buckets.Buckets)
    (h : placeEvents events state = ok out) : out.refs.val.length = state.refs.val.length := by
  induction events generalizing state with
  | nil => cases Result.ok.inj h; rfl
  | cons event rest ih =>
    simp only [placeEvents,bind_success] at h
    obtain ⟨next,hnext,hrest⟩ := h
    exact (ih next hrest).trans (place_refs_length _ _ _ _ _ hnext)

theorem fillCore_size (state : buckets.Buckets) (scalars : Slice (Array U64 4#usize))
    (width windows lists : Usize) (events : List Event)
    (hwl : 1 ≤ width.val) (hwh : width.val ≤ 8)
    (hlists : lists.val = windows.val * 2 ^ (width.val - 1))
    (hln : lists.val < 2 ^ 32)
    (htrace : scalarEvents scalars.val.length scalars width windows 0#usize = ok events)
    (hfits : ∀ event ∈ events, Fits width windows event) (helen : events.length < 2 ^ 32) :
    ∃ out, fillCore state scalars width windows lists = ok out ∧
      out.window_bits = width ∧ out.windows = windows ∧
      (∀ i < lists.val, bucketSlice out i = eventReferences width events i) ∧
      out.refs.val.length = prefixSum (fun i => (eventReferences width events i).length) lists.val := by
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
  refine ⟨out, ?_, how, hon, ?_, ?_⟩
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

  · rw [placeEvents_refs_length events placed out hplace]
    change refs.val.length = _
    rw [hrefsv,List.length_replicate,cast_Usize_val,hp.total_value]

end LeanBlsSimd.BucketsRefines
namespace LeanBlsSimd.MsmBounds
open BucketsRefines silver_crypto_simd.bls.msm8 alloc.vec

theorem fill_chunk_bounds (state : buckets.Buckets) (scalars : Slice (Array U64 4#usize))
    (n : ℕ) (hscalars : scalars.val.length = 2 * n) (hn : n ≤ 2 ^ 24) :
    ∃ out, state.fill scalars 127#usize = ok out ∧
      out.window_bits = selectedWidth (2 * n) ∧
      out.windows = windows127 (selectedWidth (2 * n)) ∧
      Resources n out.windows.val ∧
      (∀ i < out.windows.val * 2 ^ (out.window_bits.val - 1),
        (bucketSlice out i).length ≤ 2 * n) ∧
      out.refs.val.length ≤ 2 * n * out.windows.val := by
  let width := selectedWidth scalars.val.length
  have hres : Resources n (windows127 width).val := by
    simpa only [width,hscalars] using selected_resources n hn
  obtain ⟨hwl,hwh⟩ := selectedWidth_bounds scalars.val.length
  obtain ⟨events,htrace,hlen,hfits⟩ := scalarEvents_succeeds scalars.val.length scalars width
    (windows127 width) 0#usize hwl hwh (windows127_bits width hwh)
    (by change 0 + scalars.val.length ≤ scalars.val.length; omega)
  have hsize : events.length < 2 ^ 32 := by
    rw [hlen,hscalars]
    exact hres.references32
  let lists : Usize := UScalar.ofNatCore ((windows127 width).val * 2 ^ (width.val - 1))
    (lt_of_lt_of_le (listCount127_bound width hwh) two_pow_32_le_usize)
  obtain ⟨out,hout,how,hon,hrecover,hrefs⟩ := fillCore_size state scalars width (windows127 width)
    lists events hwl hwh rfl (listCount127_bound width hwh) htrace hfits hsize
  refine ⟨out,?_,by simpa only [width,hscalars] using how,
    by simpa only [width,hscalars] using hon,by simpa only [hon] using hres,?_,?_⟩
  · rw [fill127_setup]
    exact hout
  · intro i hi
    rw [hrecover i (by change i < (windows127 width).val * 2 ^ (width.val - 1); simpa only [how,hon] using hi)]
    have h := scalarEvents_bucket_bound scalars.val.length scalars width (windows127 width) 0#usize events
      (by change 0 + scalars.val.length < 2 ^ 31; rw [hscalars]; simpa only [Nat.zero_add] using hres.originals31)
      (by have hw := (selected_geometry scalars.val.length).2.2.2.1; change (windows127 (selectedWidth scalars.val.length)).val < 2 ^ 32; omega)
      htrace hfits i
    simpa only [hscalars] using h
  · rw [hrefs,hon]
    have hb := eventReferences_total_bound width events lists.val
    rw [hlen,hscalars] at hb
    exact hb

end LeanBlsSimd.MsmBounds
namespace LeanBlsSimd.MsmBounds
open BucketsRefines

theorem original_signed_reference (n windows : ℕ) (h : Resources n windows)
    (index : Usize) (negative : Bool) (hi : index.val < 2 * n) :
    index.val < 2 ^ 31 ∧
      (signedReference index negative).val % 2 ^ 31 = index.val ∧
      (signedReference index negative).val / 2 ^ 31 = (if negative then 1 else 0) := by
  have hb : index.val < 2 ^ 31 := lt_trans hi h.originals31
  exact ⟨hb,signedReference_index index negative hb,signedReference_sign index negative hb⟩

theorem allocated_index31 (n windows capacity index : ℕ) (h : Resources n windows)
    (hcap : capacity ≤ 2 * n + n * windows) (hi : index < capacity) : index < 2 ^ 31 :=
  lt_of_lt_of_le hi (le_trans hcap (Nat.le_of_lt h.capacity31))

end LeanBlsSimd.MsmBounds
