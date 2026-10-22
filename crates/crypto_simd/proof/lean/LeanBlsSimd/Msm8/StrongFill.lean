import LeanBlsSimd.Msm8.Fill

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8 alloc.vec

theorem placeEvents_packed (state : buckets.Buckets) (events : List Event)
    (hwl : 1 ≤ state.window_bits.val) (hwh : state.window_bits.val ≤ 8)
    (hn : state.windows.val * 2 ^ (state.window_bits.val - 1) < 2 ^ 32)
    (hfits : ∀ event ∈ events, Fits state.window_bits state.windows event)
    (h : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1))
      (prefixSum (fun i => (eventReferences state.window_bits events i).length))
      (fun i => (eventReferences state.window_bits events i).length) (fun _ => [])) :
    ∃ next, placeEvents events state = ok next ∧
      Packed next (state.windows.val * 2 ^ (state.window_bits.val - 1))
        (prefixSum (fun i => (eventReferences state.window_bits events i).length))
        (fun i => (eventReferences state.window_bits events i).length)
        (eventReferences state.window_bits events) ∧
      next.window_bits = state.window_bits ∧ next.windows = state.windows ∧ next.starts = state.starts := by
  obtain ⟨next, hs, hp, hw, hn', hst⟩ := placeEvents_refines state _ _ (fun _ => []) events hwl hwh hn hfits h
    (prefix_disjoint _ _) (by intro i hi; simp only [List.length_nil, Nat.zero_add, le_refl])
  have hc : collect state.window_bits (fun _ => []) events = eventReferences state.window_bits events := by
    funext i
    simp only [collect_at, List.nil_append]
  exact ⟨next, hs, by rwa [hc] at hp, hw, hn', hst⟩

theorem fillCore_packed (state : buckets.Buckets) (scalars : Slice (Array U64 4#usize))
    (width windows lists : Usize) (events : List Event)
    (hwl : 1 ≤ width.val) (hwh : width.val ≤ 8)
    (hlists : lists.val = windows.val * 2 ^ (width.val - 1))
    (hln : lists.val < 2 ^ 32)
    (htrace : scalarEvents scalars.val.length scalars width windows 0#usize = ok events)
    (hfits : ∀ event ∈ events, Fits width windows event) (helen : events.length < 2 ^ 32) :
    ∃ out, fillCore state scalars width windows lists = ok out ∧
      out.window_bits = width ∧ out.windows = windows ∧
      Packed out lists.val (prefixSum (fun i => (eventReferences width events i).length))
        (fun i => (eventReferences width events i).length) (eventReferences width events) := by
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
  obtain ⟨out, hplace, hrecover, how, hon, _⟩ := placeEvents_packed placed events hwl hwh
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

theorem fill127_packed (state : buckets.Buckets) (scalars : Slice (Array U64 4#usize))
    (hsize : scalars.val.length * (windows127 (selectedWidth scalars.val.length)).val < 2 ^ 32) :
    ∃ (events : List Event) (out : buckets.Buckets),
      scalarEvents scalars.val.length scalars (selectedWidth scalars.val.length)
        (windows127 (selectedWidth scalars.val.length)) 0#usize = ok events ∧
      state.fill scalars 127#usize = ok out ∧
      events.length = scalars.val.length * (windows127 (selectedWidth scalars.val.length)).val ∧
      out.window_bits = selectedWidth scalars.val.length ∧
      out.windows = windows127 (selectedWidth scalars.val.length) ∧
      Packed out (out.windows.val * 2 ^ (out.window_bits.val - 1))
        (prefixSum (fun i => (eventReferences (selectedWidth scalars.val.length) events i).length))
        (fun i => (eventReferences (selectedWidth scalars.val.length) events i).length)
        (eventReferences (selectedWidth scalars.val.length) events) := by
  let width := selectedWidth scalars.val.length
  obtain ⟨hwl, hwh⟩ := selectedWidth_bounds scalars.val.length
  obtain ⟨events, htrace, hlen, hfits⟩ := scalarEvents_succeeds scalars.val.length scalars width
    (windows127 width) 0#usize hwl hwh (windows127_bits width hwh)
    (by change 0 + scalars.val.length ≤ scalars.val.length; omega)
  let lists : Usize := UScalar.ofNatCore ((windows127 width).val * 2 ^ (width.val - 1))
    (lt_of_lt_of_le (listCount127_bound width hwh) two_pow_32_le_usize)
  obtain ⟨out, hout, how, hon, hrecovery⟩ := fillCore_packed state scalars width (windows127 width)
    lists events hwl hwh rfl (listCount127_bound width hwh) htrace hfits (by rw [hlen]; exact hsize)
  refine ⟨events, out, htrace, ?_, hlen, how, hon, ?_⟩
  · rw [fill127_setup]
    exact hout
  · simpa only [how, hon] using hrecovery

end LeanBlsSimd.BucketsRefines
