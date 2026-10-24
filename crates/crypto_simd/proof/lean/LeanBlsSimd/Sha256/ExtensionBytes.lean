import LeanBlsSimd.Sha256.Words

namespace LeanBlsSimd.Sha256.Extensions

theorem join_bytes (x : UInt32) :
    UInt32.ofNat ((UInt8.ofNat x.toNat).toNat +
      256*(UInt8.ofNat (x.toNat/256)).toNat +
      65536*(UInt8.ofNat (x.toNat/65536)).toNat +
      16777216*(UInt8.ofNat (x.toNat/16777216)).toNat) = x := by
  apply UInt32.toNat_inj.mp
  have hx := x.toBitVec.isLt
  change x.toNat < 4294967296 at hx
  simp only [UInt32.toNat_ofNat',UInt8.toNat_ofNat']
  norm_num only [Nat.reducePow]
  omega

theorem alignr_four (a b : M128) :
    _mm_alignr_epi8 4 a b = #v[b[1],b[2],b[3],a[0]] := by
  apply Vector.ext
  intro i hi
  interval_cases i <;>
    norm_num only [_mm_alignr_epi8,ShaIntrinsics.fromBytes,ShaIntrinsics.byte,
      Vector.getElem_ofFn,Vector.getElem_mk,List.getElem_toArray,
      List.getElem_cons_zero,List.getElem_cons_succ,Nat.div_one]
  all_goals exact join_bytes _

theorem alignr_eight (a b : M128) :
    _mm_alignr_epi8 8 a b = #v[b[2],b[3],a[0],a[1]] := by
  apply Vector.ext
  intro i hi
  interval_cases i <;>
    norm_num only [_mm_alignr_epi8,ShaIntrinsics.fromBytes,ShaIntrinsics.byte,
      Vector.getElem_ofFn,Vector.getElem_mk,List.getElem_toArray,
      List.getElem_cons_zero,List.getElem_cons_succ,Nat.div_one]
  all_goals exact join_bytes _

theorem blend_f0 (a b : M128) :
    _mm_blend_epi16 0xf0 a b = #v[a[0],a[1],b[2],b[3]] := by
  apply Vector.ext
  intro i hi
  interval_cases i <;>
    norm_num only [_mm_blend_epi16,ShaIntrinsics.fromBytes,ShaIntrinsics.byte,
      Vector.getElem_ofFn,Vector.getElem_mk,List.getElem_toArray,
      List.getElem_cons_zero,List.getElem_cons_succ,Nat.div_one]
  all_goals exact join_bytes _


def littleWord (a b c d : UInt8) : UInt32 :=
  UInt32.ofNat (a.toNat + 256*b.toNat + 65536*c.toNat + 16777216*d.toNat)

theorem littleWord_byte (a b c d : UInt8) (j : Nat) (hj : j < 4) :
    UInt8.ofNat ((littleWord a b c d).toNat / 2^(8*j)) = (#v[a,b,c,d])[j] := by
  have ha := a.toBitVec.isLt
  have hb := b.toBitVec.isLt
  have hc := c.toBitVec.isLt
  have hd := d.toBitVec.isLt
  change a.toNat < 256 at ha
  change b.toNat < 256 at hb
  change c.toNat < 256 at hc
  change d.toNat < 256 at hd
  apply UInt8.toNat_inj.mp
  interval_cases j <;>
    norm_num only [littleWord,UInt8.toNat_ofNat',UInt32.toNat_ofNat',
      Vector.getElem_mk,List.getElem_toArray,List.getElem_cons_zero,List.getElem_cons_succ] <;> omega

theorem byte_load_get (x : Vector UInt8 16) (i : Nat) (hi : i < 16) :
    ShaIntrinsics.byte (ShaIntrinsics.loadBytes x) i = x[i] := by
  interval_cases i <;>
    norm_num only [ShaIntrinsics.byte,ShaIntrinsics.loadBytes,ShaIntrinsics.fromBytes,Vector.getElem_ofFn]
  all_goals first
    | exact littleWord_byte _ _ _ _ 0 (by decide)
    | exact littleWord_byte _ _ _ _ 1 (by decide)
    | exact littleWord_byte _ _ _ _ 2 (by decide)
    | exact littleWord_byte _ _ _ _ 3 (by decide)

end LeanBlsSimd.Sha256.Extensions
