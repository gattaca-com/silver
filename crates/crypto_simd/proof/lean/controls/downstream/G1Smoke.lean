import LeanBlsSimd.Refines.UncompressG1

open Aeneas Aeneas.Std Result

/-! The downstream facade uses the generated call spelling and a downstream-owned
externals class. Its adapter fixes an explicit upstream instance and transports
independently extracted blst structs. -/

namespace silver_kzg

structure blst.blst_fp where
  l : Array Std.U64 6#usize

structure blst.blst_p1_affine where
  x : blst.blst_fp
  y : blst.blst_fp

end silver_kzg

open silver_kzg

/-- error: `silver_crypto_simd.bls.uncompress_in_g1` has already been declared -/
#guard_msgs in
axiom silver_crypto_simd.bls.uncompress_in_g1 :
  Slice (Array Std.U8 48#usize) → Slice (Option blst.blst_p1_affine) →
    Result (Slice (Option blst.blst_p1_affine))

namespace silver_kzg

namespace Bridge

def toUpstream (p : blst.blst_p1_affine) : _root_.silver_crypto_simd.blst.blst_p1_affine :=
  ⟨⟨p.x.l⟩, ⟨p.y.l⟩⟩

def fromUpstream (p : _root_.silver_crypto_simd.blst.blst_p1_affine) : blst.blst_p1_affine :=
  ⟨⟨p.x.l⟩, ⟨p.y.l⟩⟩

@[simp] theorem from_to (p : blst.blst_p1_affine) : fromUpstream (toUpstream p) = p := rfl

@[simp] theorem to_from (p : _root_.silver_crypto_simd.blst.blst_p1_affine) :
    toUpstream (fromUpstream p) = p := rfl

def toUpstreamSlice (s : Slice (Option blst.blst_p1_affine)) :
    Slice (Option _root_.silver_crypto_simd.blst.blst_p1_affine) :=
  ⟨s.val.map (Option.map toUpstream), by simpa using s.property⟩

def fromUpstreamSlice (s : Slice (Option _root_.silver_crypto_simd.blst.blst_p1_affine)) :
    Slice (Option blst.blst_p1_affine) :=
  ⟨s.val.map (Option.map fromUpstream), by simpa using s.property⟩

def uncompress (upstream : _root_.silver_crypto_simd.RuntimeFeatures)
    (external : _root_.silver_crypto_simd.KzgExternals)
    (inputs : Slice (Array Std.U8 48#usize)) (out : Slice (Option blst.blst_p1_affine)) :
    Result (Slice (Option blst.blst_p1_affine)) := do
  let result ← @_root_.silver_crypto_simd.bls.uncompress_in_g1 upstream external inputs (toUpstreamSlice out)
  ok (fromUpstreamSlice result)

end Bridge

def specVerdict (bytes : Array Std.U8 48#usize) : Option blst.blst_p1_affine :=
  (LeanBlsSimd.UncompressG1.specVerdict bytes).map Bridge.fromUpstream

theorem Bridge.uncompress_eq_spec_list (upstream : _root_.silver_crypto_simd.RuntimeFeatures)
    (external : _root_.silver_crypto_simd.KzgExternals)
    (hblst : @LeanBlsSimd.UncompressG1.FallbackCorrect upstream external)
    (inputs : Slice (Array Std.U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, Bridge.uncompress upstream external inputs out = ok result ∧
      result.val = inputs.val.map specVerdict := by
  obtain ⟨result, hr, hv⟩ := @LeanBlsSimd.UncompressG1.uncompress_in_g1_eq_spec_list
    upstream external hblst inputs (Bridge.toUpstreamSlice out) (by simpa [Bridge.toUpstreamSlice] using hlen)
  refine ⟨Bridge.fromUpstreamSlice result, ?_, ?_⟩
  · simp only [Bridge.uncompress, hr, bind_tc_ok]
  · simp [Bridge.fromUpstreamSlice, hv, List.map_map, specVerdict, Function.comp_def]

namespace Fixed

class Externals where
  uncompress : Slice (Array Std.U8 48#usize) → Slice (Option blst.blst_p1_affine) →
    Result (Slice (Option blst.blst_p1_affine))

def UncompressMatchesSpec [Externals] : Prop :=
  ∀ (inputs : Slice (Array Std.U8 48#usize)) (out : Slice (Option blst.blst_p1_affine)),
    out.val.length = inputs.val.length →
      ∃ result, Externals.uncompress inputs out = ok result ∧
        result.val = inputs.val.map specVerdict

@[reducible] def externalsOf (upstream : _root_.silver_crypto_simd.RuntimeFeatures)
    (external : _root_.silver_crypto_simd.KzgExternals) : Externals :=
  ⟨Bridge.uncompress upstream external⟩

theorem externalsOf_matches_spec (upstream : _root_.silver_crypto_simd.RuntimeFeatures)
    (external : _root_.silver_crypto_simd.KzgExternals)
    (hblst : @LeanBlsSimd.UncompressG1.FallbackCorrect upstream external) :
    @UncompressMatchesSpec (externalsOf upstream external) :=
  Bridge.uncompress_eq_spec_list upstream external hblst

@[reducible] def simdFeatures : _root_.silver_crypto_simd.RuntimeFeatures :=
  ⟨true, false, false⟩

example (external : _root_.silver_crypto_simd.KzgExternals) :
    @UncompressMatchesSpec (externalsOf simdFeatures external) :=
  externalsOf_matches_spec simdFeatures external
    (@LeanBlsSimd.UncompressG1.fallbackCorrect_ifma simdFeatures external rfl)

end Fixed

def silver_crypto_simd.bls.COMPRESSED_LEN : Result Std.Usize := ok 48#usize

def silver_crypto_simd.bls.uncompress_in_g1 [Fixed.Externals]
    (inputs : Slice (Array Std.U8 48#usize)) (out : Slice (Option blst.blst_p1_affine)) :
    Result (Slice (Option blst.blst_p1_affine)) :=
  Fixed.Externals.uncompress inputs out

/-- The generated call spelling resolves to the downstream facade. -/
def caller [Fixed.Externals] (inputs : Slice (Array Std.U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) : Result (Slice (Option blst.blst_p1_affine)) := do
  let _ ← silver_crypto_simd.bls.COMPRESSED_LEN
  silver_crypto_simd.bls.uncompress_in_g1 inputs out

theorem caller_eq_spec_list [Fixed.Externals] (h : Fixed.UncompressMatchesSpec)
    (inputs : Slice (Array Std.U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, caller inputs out = ok result ∧ result.val = inputs.val.map specVerdict :=
  h inputs out hlen

example (external : Fixed.Externals) (inputs : Slice (Array Std.U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) :
    @caller external inputs out = external.uncompress inputs out := rfl

example (upstream : _root_.silver_crypto_simd.RuntimeFeatures)
    (external : _root_.silver_crypto_simd.KzgExternals)
    (hblst : @LeanBlsSimd.UncompressG1.FallbackCorrect upstream external)
    (inputs : Slice (Array Std.U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, @caller (Fixed.externalsOf upstream external) inputs out = ok result ∧
      result.val = inputs.val.map specVerdict :=
  @caller_eq_spec_list (Fixed.externalsOf upstream external)
    (Fixed.externalsOf_matches_spec upstream external hblst) inputs out hlen

/-- info: 'silver_kzg.Bridge.uncompress_eq_spec_list' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Bridge.uncompress_eq_spec_list

/-- info: 'silver_kzg.Fixed.externalsOf_matches_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Fixed.externalsOf_matches_spec

/-- info: 'silver_kzg.caller_eq_spec_list' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms caller_eq_spec_list

end silver_kzg
