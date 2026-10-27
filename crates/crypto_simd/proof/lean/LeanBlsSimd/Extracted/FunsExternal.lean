import Aeneas
import LeanBlsSimd.Extracted.Types
import LeanBlsSimd.Model.Intrinsics
open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls

def Aeneas.Std.alloc.vec.Vec.clear (_Allocator : Type) {α : Type} (_ : alloc.vec.Vec α) :
    Result (alloc.vec.Vec α) :=
  ok ⟨[], by simp⟩

def Aeneas.Std.alloc.vec.Vec.is_empty (_Allocator : Type) {α : Type}
    (v : alloc.vec.Vec α) : Result Bool :=
  ok v.val.isEmpty

/-- CPU observations supplied independently of the opaque blst operations. -/
class silver_crypto_simd.RuntimeFeatures where
  simdAvailable : Bool
  shaAvailable : Bool
  bmi2Available : Bool

/-- Signature decoding has a separate boundary from KZG. -/
class silver_crypto_simd.bls.BlsExternals where
  uncompressG2 : Array Std.U8 96#usize → Option blst.blst_p2_affine

class silver_crypto_simd.KzgExternals where
  uncompressG1 : Array Std.U8 48#usize → Option blst.blst_p1_affine
  pairingCheck : blst.blst_p1 → blst.blst_p2_affine → blst.blst_p1 → blst.blst_p2_affine → Bool

def silver_crypto_simd.bls.uncompress_in_g1_blst [KzgExternals]
    (bytes : Array Std.U8 48#usize) : Result (Option blst.blst_p1_affine) :=
  ok (KzgExternals.uncompressG1 bytes)

def silver_crypto_simd.kzg.blst_pairing.pairing_check [KzgExternals]
    (p1 : blst.blst_p1) (q1 : blst.blst_p2_affine)
    (p2 : blst.blst_p1) (q2 : blst.blst_p2_affine) : Result Bool :=
  ok (KzgExternals.pairingCheck p1 q1 p2 q2)

def silver_crypto_simd.ifma_available [RuntimeFeatures] : Result Bool :=
  ok RuntimeFeatures.simdAvailable

def silver_crypto_simd.sha_available [RuntimeFeatures] : Result Bool :=
  ok RuntimeFeatures.shaAvailable

def silver_crypto_simd.bmi2_available [RuntimeFeatures] : Result Bool :=
  ok RuntimeFeatures.bmi2Available

def silver_crypto_simd.bls.uncompress_in_g2_blst [BlsExternals]
    (bytes : Array Std.U8 96#usize) : Result (Option blst.blst_p2_affine) :=
  ok (BlsExternals.uncompressG2 bytes)

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

/-- [core::core_arch::x86::avx512f::_mm512_slli_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 19969:0-19969:70
    Name pattern: [core::core_arch::x86::avx512f::_mm512_slli_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_slli_epi64"]
def core.core_arch.x86.avx512f._mm512_slli_epi64 (IMM8 : Std.U32) (a : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_slli_epi64 IMM8.bv.toNat a)

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

/-- [core::core_arch::x86::avx512f::_mm512_permutex2var_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 24132:0-24132:81
    Name pattern: [core::core_arch::x86::avx512f::_mm512_permutex2var_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_permutex2var_epi64"]
def core.core_arch.x86.avx512f._mm512_permutex2var_epi64
    (a index b : core.core_arch.x86.__m512i) : Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_permutex2var_epi64 a index b)

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

/-- [silver_crypto_simd::bls::fp8::lanes]:
    Source: 'crates/crypto_simd/src/bls/fp8.rs', lines 50:0-54:1 -/
def silver_crypto_simd.bls.fp8.lanes (v : core.core_arch.x86.__m512i) : Result (Array Std.U64 8#usize) :=
  -- A `transmute`: element `l` of the array is lane `l` of `v`.
  ok ⟨v.toList.map fun x => ⟨x.toBitVec⟩, by simp⟩

namespace silver_crypto_simd

def U32.Insts.CoreIterRangeStep.backward_checked (a : Std.U32) (n : Usize) :
    Result (Option Std.U32) :=
  ok (if n.val ≤ a.val then some ⟨BitVec.ofNat 32 (a.val - n.val)⟩ else none)

def U32.Insts.CoreIterRangeStep.forward_checked (a : Std.U32) (n : Usize) :
    Result (Option Std.U32) :=
  ok (if a.val + n.val < 2^32 then some ⟨BitVec.ofNat 32 (a.val + n.val)⟩ else none)

def U32.Insts.CoreIterRangeStep.steps_between (a b : Std.U32) :
    Result (Usize × Option Usize) :=
  ok (if a.val ≤ b.val then
    (⟨BitVec.ofNat _ (b.val - a.val)⟩, some ⟨BitVec.ofNat _ (b.val - a.val)⟩)
    else (0#usize, none))

def core.option.Option.Insts.CoreCloneClone.clone {T : Type} (inst : core.clone.Clone T)
    (x : Option T) : Result (Option T) :=
  match x with
  | none => ok none
  | some a => inst.clone a >>= fun b => ok (some b)

def alloc.vec.Vec.Insts.CoreDefaultDefault.default (T : Type) : Result (alloc.vec.Vec T) :=
  ok (alloc.vec.Vec.new T)

def blst.blst_fr.Insts.CoreCloneClone.clone (x : blst.blst_fr) : Result blst.blst_fr := ok x
def blst.blst_p1_affine.Insts.CoreCloneClone.clone (x : blst.blst_p1_affine) :
    Result blst.blst_p1_affine := ok x

def core.option.Option.Insts.CoreOpsTry_traitTryTOptionInfallible.branch {T : Type}
    (x : Option T) :
    Result (core.ops.control_flow.ControlFlow (Option core.convert.Infallible) T) :=
  match x with
  | none => ok (.Break none)
  | some a => ok (.Continue a)

def core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionInfallible.from_residual
    (T : Type) (residual : Option core.convert.Infallible) : Result (Option T) :=
  match residual with
  | none => ok none
  | some impossible => nomatch impossible

def blst.blst_p1.Insts.CoreDefaultDefault.default : Result blst.blst_p1 :=
  let fp : blst.blst_fp := { l := Array.repeat 6#usize 0#u64 }
  ok { x := fp, y := fp, z := fp }

end silver_crypto_simd

@[rust_fun "core::core_arch::x86::sha::_mm_sha256msg1_epu32"]
def core.core_arch.x86.sha._mm_sha256msg1_epu32 (a b : core.core_arch.x86.__m128i) :
    Result core.core_arch.x86.__m128i := ok (LeanBlsSimd._mm_sha256msg1_epu32 a b)

@[rust_fun "core::core_arch::x86::sha::_mm_sha256msg2_epu32"]
def core.core_arch.x86.sha._mm_sha256msg2_epu32 (a b : core.core_arch.x86.__m128i) :
    Result core.core_arch.x86.__m128i := ok (LeanBlsSimd._mm_sha256msg2_epu32 a b)

@[rust_fun "core::core_arch::x86::sha::_mm_sha256rnds2_epu32"]
def core.core_arch.x86.sha._mm_sha256rnds2_epu32 (a b wk : core.core_arch.x86.__m128i) :
    Result core.core_arch.x86.__m128i := ok (LeanBlsSimd._mm_sha256rnds2_epu32 a b wk)

@[rust_fun "core::core_arch::x86::sse2::_mm_add_epi32"]
def core.core_arch.x86.sse2._mm_add_epi32 (a b : core.core_arch.x86.__m128i) :
    Result core.core_arch.x86.__m128i := ok (LeanBlsSimd._mm_add_epi32 a b)

@[rust_fun "core::core_arch::x86::sse2::_mm_set_epi64x"]
def core.core_arch.x86.sse2._mm_set_epi64x (hi lo : Std.I64) :
    Result core.core_arch.x86.__m128i :=
  ok (LeanBlsSimd._mm_set_epi64x (Int64.ofBitVec hi.bv) (Int64.ofBitVec lo.bv))

@[rust_fun "core::core_arch::x86::sse2::_mm_shuffle_epi32"]
def core.core_arch.x86.sse2._mm_shuffle_epi32 (IMM8 : Std.I32)
    (a : core.core_arch.x86.__m128i) : Result core.core_arch.x86.__m128i :=
  ok (LeanBlsSimd._mm_shuffle_epi32 IMM8.bv.toNat a)

@[rust_fun "core::core_arch::x86::sse41::_mm_blend_epi16"]
def core.core_arch.x86.sse41._mm_blend_epi16 (IMM8 : Std.I32)
    (a b : core.core_arch.x86.__m128i) : Result core.core_arch.x86.__m128i :=
  ok (LeanBlsSimd._mm_blend_epi16 IMM8.bv.toNat a b)

@[rust_fun "core::core_arch::x86::ssse3::_mm_shuffle_epi8"]
def core.core_arch.x86.ssse3._mm_shuffle_epi8 (a b : core.core_arch.x86.__m128i) :
    Result core.core_arch.x86.__m128i := ok (LeanBlsSimd._mm_shuffle_epi8 a b)

@[rust_fun "core::core_arch::x86::ssse3::_mm_alignr_epi8"]
def core.core_arch.x86.ssse3._mm_alignr_epi8 (IMM8 : Std.I32)
    (a b : core.core_arch.x86.__m128i) : Result core.core_arch.x86.__m128i :=
  ok (LeanBlsSimd._mm_alignr_epi8 IMM8.bv.toNat a b)

@[rust_fun "core::core_arch::x86_64::adx::_addcarry_u64"]
def core.core_arch.x86_64.adx._addcarry_u64 (carry : Std.U8) (a b _out : Std.U64) :
    Result (Std.U8 × Std.U64) :=
  let (c, s) := LeanBlsSimd._addcarry_u64 (UInt8.ofBitVec carry.bv)
    (UInt64.ofBitVec a.bv) (UInt64.ofBitVec b.bv)
  ok (⟨c.toBitVec⟩, ⟨s.toBitVec⟩)

/-- The pointer load reads the 16 array bytes in x86 little-endian order. -/
def silver_crypto_simd.sha256.extensions.load_bytes (bytes : Array Std.U8 16#usize) :
    Result core.core_arch.x86.__m128i :=
  ok (LeanBlsSimd.ShaIntrinsics.loadBytes (.ofFn fun i =>
    UInt8.ofBitVec (bytes.val[i.val]'(by rw [bytes.property]; exact i.isLt)).bv))

/-- A `[u32; 4]` has four consecutive native little-endian words on x86-64. -/
def silver_crypto_simd.sha256.extensions.load_words (words : Array Std.U32 4#usize) :
    Result core.core_arch.x86.__m128i :=
  ok (.ofFn fun i => UInt32.ofBitVec (words.val[i.val]'(by
    rw [words.property]; exact i.isLt)).bv)

def silver_crypto_simd.sha256.extensions.store_words (v : core.core_arch.x86.__m128i) :
    Result (Array Std.U32 4#usize) :=
  ok ⟨v.toList.map fun x => ⟨x.toBitVec⟩, by simp⟩
