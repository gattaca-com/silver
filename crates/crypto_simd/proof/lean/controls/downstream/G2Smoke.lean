import LeanBlsSimd.Refines.UncompressG2

open Aeneas Aeneas.Std Result

/-! The downstream facade uses the generated call spelling and a downstream-owned
externals class. Its adapter fixes an explicit upstream instance and transports
independently extracted blst structs. -/

namespace silver_bls

structure blst.blst_fp where
  l : Array Std.U64 6#usize

structure blst.blst_fp2 where
  fp : Array blst.blst_fp 2#usize

structure blst.blst_p2_affine where
  x : blst.blst_fp2
  y : blst.blst_fp2

end silver_bls

open silver_bls

/-- error: `silver_crypto_simd.bls.uncompress_in_g2` has already been declared -/
#guard_msgs in
axiom silver_crypto_simd.bls.uncompress_in_g2 :
  Slice (Array Std.U8 96#usize) → Slice (Option blst.blst_p2_affine) →
    Result (Slice (Option blst.blst_p2_affine))

namespace silver_bls

namespace Bridge

def toFp2 (p : blst.blst_fp2) : _root_.silver_crypto_simd.blst.blst_fp2 :=
  ⟨⟨p.fp.val.map (fun fp => ⟨fp.l⟩), by simp⟩⟩

def fromFp2 (p : _root_.silver_crypto_simd.blst.blst_fp2) : blst.blst_fp2 :=
  ⟨⟨p.fp.val.map (fun fp => ⟨fp.l⟩), by simp⟩⟩

@[simp] theorem from_to_fp2 (p : blst.blst_fp2) : fromFp2 (toFp2 p) = p := by
  cases p
  simp [fromFp2, toFp2, List.map_map, Function.comp_def]

@[simp] theorem to_from_fp2 (p : _root_.silver_crypto_simd.blst.blst_fp2) :
    toFp2 (fromFp2 p) = p := by
  cases p
  simp [fromFp2, toFp2, List.map_map, Function.comp_def]

def toUpstream (p : blst.blst_p2_affine) : _root_.silver_crypto_simd.blst.blst_p2_affine :=
  ⟨toFp2 p.x, toFp2 p.y⟩

def fromUpstream (p : _root_.silver_crypto_simd.blst.blst_p2_affine) : blst.blst_p2_affine :=
  ⟨fromFp2 p.x, fromFp2 p.y⟩

@[simp] theorem from_to (p : blst.blst_p2_affine) : fromUpstream (toUpstream p) = p := by
  simp [fromUpstream, toUpstream]

@[simp] theorem to_from (p : _root_.silver_crypto_simd.blst.blst_p2_affine) :
    toUpstream (fromUpstream p) = p := by
  simp [fromUpstream, toUpstream]

def toUpstreamSlice (s : Slice (Option blst.blst_p2_affine)) :
    Slice (Option _root_.silver_crypto_simd.blst.blst_p2_affine) :=
  ⟨s.val.map (Option.map toUpstream), by simpa using s.property⟩

def fromUpstreamSlice (s : Slice (Option _root_.silver_crypto_simd.blst.blst_p2_affine)) :
    Slice (Option blst.blst_p2_affine) :=
  ⟨s.val.map (Option.map fromUpstream), by simpa using s.property⟩

def uncompress (upstream : _root_.silver_crypto_simd.bls.BlsExternals)
    (inputs : Slice (Array Std.U8 96#usize)) (out : Slice (Option blst.blst_p2_affine)) :
    Result (Slice (Option blst.blst_p2_affine)) := do
  let result ← @_root_.silver_crypto_simd.bls.uncompress_in_g2 upstream inputs (toUpstreamSlice out)
  ok (fromUpstreamSlice result)

end Bridge

def specVerdict (bytes : Array Std.U8 96#usize) : Option blst.blst_p2_affine :=
  (LeanBlsSimd.UncompressG2.specVerdict bytes).map Bridge.fromUpstream

theorem Bridge.uncompress_eq_spec_list (upstream : _root_.silver_crypto_simd.bls.BlsExternals)
    (hblst : @LeanBlsSimd.UncompressG2.BlstMatchesSpec upstream)
    (inputs : Slice (Array Std.U8 96#usize)) (out : Slice (Option blst.blst_p2_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, Bridge.uncompress upstream inputs out = ok result ∧
      result.val = inputs.val.map specVerdict := by
  obtain ⟨result, hr, hv⟩ := @LeanBlsSimd.UncompressG2.uncompress_in_g2_eq_spec_list
    upstream hblst inputs (Bridge.toUpstreamSlice out) (by simpa [Bridge.toUpstreamSlice] using hlen)
  refine ⟨Bridge.fromUpstreamSlice result, ?_, ?_⟩
  · simp only [Bridge.uncompress, hr, bind_tc_ok]
  · simp [Bridge.fromUpstreamSlice, hv, List.map_map, specVerdict, Function.comp_def]

namespace Fixed

class Externals where
  uncompress : Slice (Array Std.U8 96#usize) → Slice (Option blst.blst_p2_affine) →
    Result (Slice (Option blst.blst_p2_affine))

def UncompressMatchesSpec [Externals] : Prop :=
  ∀ (inputs : Slice (Array Std.U8 96#usize)) (out : Slice (Option blst.blst_p2_affine)),
    out.val.length = inputs.val.length →
      ∃ result, Externals.uncompress inputs out = ok result ∧
        result.val = inputs.val.map specVerdict

@[reducible] def externalsOf (upstream : _root_.silver_crypto_simd.bls.BlsExternals) : Externals :=
  ⟨Bridge.uncompress upstream⟩

theorem externalsOf_matches_spec (upstream : _root_.silver_crypto_simd.bls.BlsExternals)
    (hblst : @LeanBlsSimd.UncompressG2.BlstMatchesSpec upstream) :
    @UncompressMatchesSpec (externalsOf upstream) :=
  Bridge.uncompress_eq_spec_list upstream hblst

@[reducible] def specUpstream : _root_.silver_crypto_simd.bls.BlsExternals :=
  ⟨true, fun _ => none, LeanBlsSimd.UncompressG2.specVerdict⟩

theorem specUpstream_matches : @LeanBlsSimd.UncompressG2.BlstMatchesSpec specUpstream :=
  fun _ => rfl

example : @UncompressMatchesSpec (externalsOf specUpstream) :=
  externalsOf_matches_spec specUpstream specUpstream_matches

end Fixed

def silver_crypto_simd.bls.COMPRESSED_LEN : Result Std.Usize := ok 96#usize

def silver_crypto_simd.bls.uncompress_in_g2 [Fixed.Externals]
    (inputs : Slice (Array Std.U8 96#usize)) (out : Slice (Option blst.blst_p2_affine)) :
    Result (Slice (Option blst.blst_p2_affine)) :=
  Fixed.Externals.uncompress inputs out

/-- The generated call spelling resolves to the downstream facade. -/
def caller [Fixed.Externals] (inputs : Slice (Array Std.U8 96#usize))
    (out : Slice (Option blst.blst_p2_affine)) : Result (Slice (Option blst.blst_p2_affine)) := do
  let _ ← silver_crypto_simd.bls.COMPRESSED_LEN
  silver_crypto_simd.bls.uncompress_in_g2 inputs out

theorem caller_eq_spec_list [Fixed.Externals] (h : Fixed.UncompressMatchesSpec)
    (inputs : Slice (Array Std.U8 96#usize)) (out : Slice (Option blst.blst_p2_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, caller inputs out = ok result ∧ result.val = inputs.val.map specVerdict :=
  h inputs out hlen

example (external : Fixed.Externals) (inputs : Slice (Array Std.U8 96#usize))
    (out : Slice (Option blst.blst_p2_affine)) :
    @caller external inputs out = external.uncompress inputs out := rfl

example (upstream : _root_.silver_crypto_simd.bls.BlsExternals)
    (hblst : @LeanBlsSimd.UncompressG2.BlstMatchesSpec upstream)
    (inputs : Slice (Array Std.U8 96#usize)) (out : Slice (Option blst.blst_p2_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, @caller (Fixed.externalsOf upstream) inputs out = ok result ∧
      result.val = inputs.val.map specVerdict :=
  @caller_eq_spec_list (Fixed.externalsOf upstream)
    (Fixed.externalsOf_matches_spec upstream hblst) inputs out hlen

/-- info: 'silver_bls.Bridge.uncompress_eq_spec_list' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Bridge.uncompress_eq_spec_list

/-- info: 'silver_bls.Fixed.externalsOf_matches_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Fixed.externalsOf_matches_spec

/-- info: 'silver_bls.caller_eq_spec_list' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms caller_eq_spec_list

end silver_bls
