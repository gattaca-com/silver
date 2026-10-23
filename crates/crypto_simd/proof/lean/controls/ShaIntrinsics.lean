import LeanBlsSimd.Extracted.FunsExternal

open LeanBlsSimd

namespace ShaControls

/- The three SHA fixtures are Rust 1.95 stdarch's published tests, independent
of this model. They detect wrong state lane order and missing message chaining. -/
def a : M128 := #v[0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5]
def b : M128 := #v[0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5]

theorem msg1_fixture : _mm_sha256msg1_epu32 a b =
    #v[0x406b09ee, 0x2857b88f, 0xd5cda67d, 0xeb84973f] := by decide
theorem msg2_fixture : _mm_sha256msg2_epu32 a b =
    #v[0x73ac8450, 0x15d1ec8b, 0x887fd851, 0xb58777ce] := by decide
theorem rnds2_fixture : _mm_sha256rnds2_epu32 a b #v[0xd807aa98, 0x12835b01, 0, 0] =
    #v[0x0d6d1d19, 0x187ee3db, 0xeffb15ea, 0xd3063037] := by decide
theorem rnds2_ignores_upper_wk :
    _mm_sha256rnds2_epu32 a b #v[0xd807aa98, 0x12835b01, 123, 456] =
    _mm_sha256rnds2_epu32 a b #v[0xd807aa98, 0x12835b01, 0, 0] := by decide
theorem rnds2_wrong_operand_order :
    _mm_sha256rnds2_epu32 b a #v[0xd807aa98, 0x12835b01, 0, 0] ≠
    #v[0x0d6d1d19, 0x187ee3db, 0xeffb15ea, 0xd3063037] := by decide

theorem msg2_requires_new_words :
    _mm_sha256msg2_epu32 a b ≠
      (#v[(0x73ac8450 : UInt32), 0x15d1ec8b,
        a[2] + ShaIntrinsics.smallSigma1 b[0],
        a[3] + ShaIntrinsics.smallSigma1 b[1]] : M128) := by decide

theorem add_wraps : _mm_add_epi32 #v[0xffffffff, 2, 3, 4] #v[1, 5, 6, 7] =
    #v[0, 7, 9, 11] := by decide
theorem constructor_bits : _mm_set_epi64x (-1) 0x0123456789abcdef =
    #v[0x89abcdef, 0x01234567, 0xffffffff, 0xffffffff] := by decide
theorem shuffle_lanes : _mm_shuffle_epi32 0x1b #v[1, 2, 3, 4] = #v[4, 3, 2, 1] := by decide
theorem align_order : _mm_alignr_epi8 4 #v[5, 6, 7, 8] #v[1, 2, 3, 4] =
    #v[2, 3, 4, 5] := by decide
theorem align_zero_fill : _mm_alignr_epi8 28 #v[5, 6, 7, 8] #v[1, 2, 3, 4] =
    #v[8, 0, 0, 0] := by decide
theorem align_overshift : _mm_alignr_epi8 32 a b = #v[0, 0, 0, 0] := by decide
theorem blend_halfwords : _mm_blend_epi16 0x55
    #v[0x11223344, 0x11223344, 0x11223344, 0x11223344]
    #v[0xaabbccdd, 0xaabbccdd, 0xaabbccdd, 0xaabbccdd] =
    #v[0x1122ccdd, 0x1122ccdd, 0x1122ccdd, 0x1122ccdd] := by decide

def bytes : Vector UInt8 16 := #v[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
theorem byte_load_little_endian : ShaIntrinsics.loadBytes bytes =
    #v[0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c] := by decide
theorem byte_shuffle_mask_bits : _mm_shuffle_epi8 (ShaIntrinsics.loadBytes bytes)
    #v[0xff807f10, 0xff807f10, 0xff807f10, 0xff807f10] =
    #v[0x00000f00, 0x00000f00, 0x00000f00, 0x00000f00] := by decide
theorem byte_swap : _mm_shuffle_epi8 (ShaIntrinsics.loadBytes bytes)
    (_mm_set_epi64x 0x0c0d0e0f08090a0b 0x0405060700010203) =
    #v[0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f] := by decide

theorem carry_zero : _addcarry_u64 0 3 4 = (0, 7) := by decide
theorem carry_overflow : _addcarry_u64 1 0xffffffffffffffff 0 = (1, 0) := by decide
theorem carry_nonzero : _addcarry_u64 2 3 4 = (0, 8) := by decide
theorem carry_not_low_bit : _addcarry_u64 2 3 4 ≠ (0, 7) := by decide
theorem carry_maximum : _addcarry_u64 255 0xffffffffffffffff 0xffffffffffffffff =
    (1, 0xffffffffffffffff) := by decide

open Aeneas Aeneas.Std Result in
theorem load_store_words :
    (silver_crypto_simd.sha256.extensions.load_words
      (Array.make 4#usize [1#u32, 2#u32, 3#u32, 4#u32]) >>=
      silver_crypto_simd.sha256.extensions.store_words) =
    ok (Array.make 4#usize [1#u32, 2#u32, 3#u32, 4#u32]) := by rfl

open Aeneas Aeneas.Std Result in
theorem byte_binding :
    silver_crypto_simd.sha256.extensions.load_bytes
      (Array.make 16#usize (bytes.toList.map fun x => (⟨x.toBitVec⟩ : Std.U8)) (by simp)) =
    ok #v[0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c] := by rfl

open Aeneas Aeneas.Std Result in
theorem carry_overwrites_out :
    core.core_arch.x86_64.adx._addcarry_u64 2#u8 3#u64 4#u64 123#u64 =
    ok (0#u8, 8#u64) := by rfl

end ShaControls

#print axioms ShaControls.msg1_fixture
#print axioms ShaControls.msg2_fixture
#print axioms ShaControls.rnds2_fixture
#print axioms ShaControls.carry_nonzero
#print axioms ShaControls.load_store_words
