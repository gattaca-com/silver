import Aeneas
import LeanBlsSimd.Extracted.Types
import LeanBlsSimd.Model.Intrinsics
open Aeneas Aeneas.Std Result ControlFlow Error
open silver_bls_simd

/-- Total external observations, supplied by the caller of the generated G1 API. -/
class silver_bls_simd.G1Externals where
  simdAvailable : Bool
  uncompress : Array Std.U8 48#usize → Option blst.blst_p1_affine

def silver_bls_simd.simd_available [G1Externals] : Result Bool :=
  ok G1Externals.simdAvailable

def silver_bls_simd.uncompress_in_g1_blst [G1Externals]
    (bytes : Array Std.U8 48#usize) : Result (Option blst.blst_p1_affine) :=
  ok (G1Externals.uncompress bytes)

def blst.blst_p1_affine.Insts.CoreDefaultDefault.default : Result blst.blst_p1_affine :=
  let fp : blst.blst_fp := { l := Array.repeat 6#usize 0#u64 }
  ok { x := fp, y := fp }

/-!
Handwritten definitions for functions that Aeneas leaves external. The starting template is
`FunsExternal_Template.lean`, generated beside `Funs.lean`; `extract.sh` preserves this file.

Each intrinsic wraps the corresponding `Model/Intrinsics.lean` operation in `ok`. Conversions
between Aeneas integers and Lean's fixed-width integers preserve their bit vectors.
-/

/-- [core::core_arch::x86::avx512f::_mm512_add_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 779:0-779:64
    Name pattern: [core::core_arch::x86::avx512f::_mm512_add_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_add_epi64"]
def core.core_arch.x86.avx512f._mm512_add_epi64 (a b : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_add_epi64 a b)

/-- [core::core_arch::x86::avx512f::_mm512_sub_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 1187:0-1187:64
    Name pattern: [core::core_arch::x86::avx512f::_mm512_sub_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_sub_epi64"]
def core.core_arch.x86.avx512f._mm512_sub_epi64 (a b : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_sub_epi64 a b)

/-- [core::core_arch::x86::avx512f::_mm512_setzero_si512]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 16684:0-16684:46
    Name pattern: [core::core_arch::x86::avx512f::_mm512_setzero_si512]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_setzero_si512"]
def core.core_arch.x86.avx512f._mm512_setzero_si512 : Result core.core_arch.x86.__m512i :=
  ok LeanBlsSimd._mm512_setzero_si512

/-- [core::core_arch::x86::avx512f::_mm512_set_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 16943:0-16952:12
    Name pattern: [core::core_arch::x86::avx512f::_mm512_set_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_set_epi64"]
def core.core_arch.x86.avx512f._mm512_set_epi64 (e7 e6 e5 e4 e3 e2 e1 e0 : Std.I64) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_set_epi64 (Int64.ofBitVec e7.bv) (Int64.ofBitVec e6.bv)
    (Int64.ofBitVec e5.bv) (Int64.ofBitVec e4.bv) (Int64.ofBitVec e3.bv) (Int64.ofBitVec e2.bv)
    (Int64.ofBitVec e1.bv) (Int64.ofBitVec e0.bv))

/-- [core::core_arch::x86::avx512f::_mm512_srli_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 20499:0-20499:70
    Name pattern: [core::core_arch::x86::avx512f::_mm512_srli_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_srli_epi64"]
def core.core_arch.x86.avx512f._mm512_srli_epi64 (IMM8 : Std.U32) (a : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_srli_epi64 IMM8.bv.toNat a)

/-- [core::core_arch::x86::avx512f::_mm512_srai_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 21375:0-21375:70
    Name pattern: [core::core_arch::x86::avx512f::_mm512_srai_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_srai_epi64"]
def core.core_arch.x86.avx512f._mm512_srai_epi64 (IMM8 : Std.U32) (a : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_srai_epi64 IMM8.bv.toNat a)

/-- [core::core_arch::x86::avx512f::_mm512_mask_blend_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 28757:0-28757:84
    Name pattern: [core::core_arch::x86::avx512f::_mm512_mask_blend_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_mask_blend_epi64"]
def core.core_arch.x86.avx512f._mm512_mask_blend_epi64 (k : Std.U8)
    (a b : core.core_arch.x86.__m512i) : Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_mask_blend_epi64 (UInt8.ofBitVec k.bv) a b)

/-- [core::core_arch::x86::avx512f::_mm512_and_si512]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 29551:0-29551:64
    Name pattern: [core::core_arch::x86::avx512f::_mm512_and_si512]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_and_si512"]
def core.core_arch.x86.avx512f._mm512_and_si512 (a b : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_and_si512 a b)

/-- [core::core_arch::x86::avx512f::_mm512_set1_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 31330:0-31330:49
    Name pattern: [core::core_arch::x86::avx512f::_mm512_set1_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_set1_epi64"]
def core.core_arch.x86.avx512f._mm512_set1_epi64 (a : Std.I64) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_set1_epi64 (Int64.ofBitVec a.bv))

/-- [core::core_arch::x86::avx512f::_mm512_cmpeq_epi64_mask]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 34423:0-34423:72
    Name pattern: [core::core_arch::x86::avx512f::_mm512_cmpeq_epi64_mask]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_cmpeq_epi64_mask"]
def core.core_arch.x86.avx512f._mm512_cmpeq_epi64_mask (a b : core.core_arch.x86.__m512i) :
    Result Std.U8 :=
  ok ⟨(LeanBlsSimd._mm512_cmpeq_epi64_mask a b).toBitVec⟩

/-- [core::core_arch::x86::avx512ifma::_mm512_madd52hi_epu64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512ifma.rs', lines 18:0-18:75
    Name pattern: [core::core_arch::x86::avx512ifma::_mm512_madd52hi_epu64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512ifma::_mm512_madd52hi_epu64"]
def core.core_arch.x86.avx512ifma._mm512_madd52hi_epu64 (a b c : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_madd52hi_epu64 a b c)

/-- [core::core_arch::x86::avx512ifma::_mm512_madd52lo_epu64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512ifma.rs', lines 65:0-65:75
    Name pattern: [core::core_arch::x86::avx512ifma::_mm512_madd52lo_epu64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512ifma::_mm512_madd52lo_epu64"]
def core.core_arch.x86.avx512ifma._mm512_madd52lo_epu64 (a b c : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_madd52lo_epu64 a b c)

/-- [blst::{core::default::Default for blst::blst_p2_affine}::default]:
    Source: '/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/blst-0.3.16/src/bindings.rs', lines 634:16-634:23
    Name pattern: [blst::{core::default::Default<blst::blst_p2_affine>}::default]
    Visibility: public -/
@[rust_fun "blst::{core::default::Default<blst::blst_p2_affine>}::default"]
def blst.blst_p2_affine.Insts.CoreDefaultDefault.default : Result blst.blst_p2_affine :=
  -- `#[derive(Default)]` on `blst_p2_affine`, `blst_fp2` and `blst_fp`: every limb is 0.
  let fp2 : blst.blst_fp2 := { fp := Array.repeat 2#usize { l := Array.repeat 6#usize 0#u64 } }
  ok { x := fp2, y := fp2 }

/-- [silver_bls_simd::fp8::lanes]:
    Source: 'crates/bls_simd/src/fp8.rs', lines 50:0-54:1 -/
def fp8.lanes (v : core.core_arch.x86.__m512i) : Result (Array Std.U64 8#usize) :=
  -- A `transmute`: element `l` of the array is lane `l` of `v`.
  ok ⟨v.toList.map fun x => ⟨x.toBitVec⟩, by simp⟩
