import LeanBlsSimd.Refines.UncompressG1

open Aeneas Aeneas.Std Result

/-! Two downstream interoperability witnesses, with copied blst structs. One threads
the upstream instance; the other fixes it behind downstream-owned externals.
The unmodified root external fails the permanent negative control below. These
witnesses do not select a downstream extraction strategy. -/

namespace silver_kzg

structure blst.blst_fp where
  l : Array Std.U64 6#usize

structure blst.blst_p1_affine where
  x : blst.blst_fp
  y : blst.blst_fp

end silver_kzg

open silver_kzg

/-- error: `silver_bls_simd.uncompress_in_g1` has already been declared -/
#guard_msgs in
axiom silver_bls_simd.uncompress_in_g1 :
  Slice (Array Std.U8 48#usize) → Slice (Option blst.blst_p1_affine) →
    Result (Slice (Option blst.blst_p1_affine))

namespace silver_kzg

namespace Bridge

def toUpstream (p : blst.blst_p1_affine) : _root_.silver_bls_simd.blst.blst_p1_affine :=
  ⟨⟨p.x.l⟩, ⟨p.y.l⟩⟩

def fromUpstream (p : _root_.silver_bls_simd.blst.blst_p1_affine) : blst.blst_p1_affine :=
  ⟨⟨p.x.l⟩, ⟨p.y.l⟩⟩

@[simp] theorem from_to (p : blst.blst_p1_affine) : fromUpstream (toUpstream p) = p := rfl

@[simp] theorem to_from (p : _root_.silver_bls_simd.blst.blst_p1_affine) :
    toUpstream (fromUpstream p) = p := rfl

def toUpstreamSlice (s : Slice (Option blst.blst_p1_affine)) :
    Slice (Option _root_.silver_bls_simd.blst.blst_p1_affine) :=
  ⟨s.val.map (Option.map toUpstream), by simpa using s.property⟩

def fromUpstreamSlice (s : Slice (Option _root_.silver_bls_simd.blst.blst_p1_affine)) :
    Slice (Option blst.blst_p1_affine) :=
  ⟨s.val.map (Option.map fromUpstream), by simpa using s.property⟩

end Bridge

section Threaded

variable [_root_.silver_bls_simd.G1Externals]

def silver_bls_simd.COMPRESSED_LEN : Result Std.Usize := ok 48#usize

def silver_bls_simd.uncompress_in_g1
    (inputs : Slice (Array Std.U8 48#usize)) (out : Slice (Option blst.blst_p1_affine)) :
    Result (Slice (Option blst.blst_p1_affine)) := do
  let result ← _root_.silver_bls_simd.uncompress_in_g1 inputs (Bridge.toUpstreamSlice out)
  ok (Bridge.fromUpstreamSlice result)

/-- The generated call spelling resolves to the qualified bridge inside `silver_kzg`. -/
def caller (inputs : Slice (Array Std.U8 48#usize)) (out : Slice (Option blst.blst_p1_affine)) :
    Result (Slice (Option blst.blst_p1_affine)) := do
  let _ ← silver_bls_simd.COMPRESSED_LEN
  silver_bls_simd.uncompress_in_g1 inputs out

def specVerdict (bytes : Array Std.U8 48#usize) : Option blst.blst_p1_affine :=
  (LeanBlsSimd.UncompressG1.specVerdict bytes).map Bridge.fromUpstream

theorem caller_eq_spec_list (hblst : LeanBlsSimd.UncompressG1.BlstMatchesSpec)
    (inputs : Slice (Array Std.U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, caller inputs out = ok result ∧ result.val = inputs.val.map specVerdict := by
  obtain ⟨result, hr, hv⟩ := LeanBlsSimd.UncompressG1.uncompress_in_g1_eq_spec_list
    hblst inputs (Bridge.toUpstreamSlice out) (by simpa [Bridge.toUpstreamSlice] using hlen)
  refine ⟨Bridge.fromUpstreamSlice result, ?_, ?_⟩
  · simp only [caller, silver_bls_simd.COMPRESSED_LEN, bind_tc_ok,
      silver_bls_simd.uncompress_in_g1, hr]
  · simp [Bridge.fromUpstreamSlice, hv, List.map_map, specVerdict, Function.comp_def]

end Threaded

/-! An alternative keeps the upstream instance fixed behind a downstream-owned
external function. The downstream caller requires only its own externals class. -/

namespace Fixed

class Externals where
  uncompress : Slice (Array Std.U8 48#usize) → Slice (Option blst.blst_p1_affine) →
    Result (Slice (Option blst.blst_p1_affine))

def caller [Externals] (inputs : Slice (Array Std.U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) : Result (Slice (Option blst.blst_p1_affine)) :=
  Externals.uncompress inputs out

def UncompressMatchesSpec [Externals] : Prop :=
  ∀ (inputs : Slice (Array Std.U8 48#usize)) (out : Slice (Option blst.blst_p1_affine)),
    out.val.length = inputs.val.length →
      ∃ result, Externals.uncompress inputs out = ok result ∧
        result.val = inputs.val.map specVerdict

@[reducible] def externalsOf (upstream : _root_.silver_bls_simd.G1Externals) : Externals :=
  ⟨@silver_kzg.silver_bls_simd.uncompress_in_g1 upstream⟩

theorem externalsOf_matches_spec (upstream : _root_.silver_bls_simd.G1Externals)
    (hblst : @LeanBlsSimd.UncompressG1.BlstMatchesSpec upstream) :
    @UncompressMatchesSpec (externalsOf upstream) := by
  intro inputs out hlen
  exact @silver_kzg.caller_eq_spec_list upstream hblst inputs out hlen

theorem caller_eq_spec_list [Externals] (h : UncompressMatchesSpec)
    (inputs : Slice (Array Std.U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, caller inputs out = ok result ∧ result.val = inputs.val.map specVerdict :=
  h inputs out hlen

@[reducible] def specUpstream : _root_.silver_bls_simd.G1Externals :=
  ⟨true, LeanBlsSimd.UncompressG1.specVerdict⟩

theorem specUpstream_matches : @LeanBlsSimd.UncompressG1.BlstMatchesSpec specUpstream :=
  fun _ => rfl

example : @UncompressMatchesSpec (externalsOf specUpstream) :=
  externalsOf_matches_spec specUpstream specUpstream_matches

example (external : Externals) (inputs : Slice (Array Std.U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) :
    @caller external inputs out = external.uncompress inputs out := rfl

end Fixed

#print axioms caller_eq_spec_list
#print axioms Fixed.externalsOf_matches_spec
#print axioms Fixed.caller_eq_spec_list

end silver_kzg
