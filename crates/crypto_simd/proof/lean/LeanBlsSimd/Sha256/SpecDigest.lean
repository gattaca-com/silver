import LeanBlsSimd.Sha256.GeneratedBytes

open private LeanBlsSimd.Sha256.Spec.set_size LeanBlsSimd.Sha256.Spec.set_get
  from LeanBlsSimd.Sha256.Padding

namespace LeanBlsSimd.Sha256.Spec

set_option maxRecDepth 2048

def digestPartial (state : Array UInt32) (n : Nat) : ByteArray :=
  (List.range' 0 n).foldl (fun out i =>
    let h := state[i]!
    (((out.set! (4*i) (UInt8.ofNat ((h >>> 24).toNat))).set!
      (4*i+1) (UInt8.ofNat ((h >>> 16).toNat &&& 0xff))).set!
      (4*i+2) (UInt8.ofNat ((h >>> 8).toNat &&& 0xff))).set!
      (4*i+3) (UInt8.ofNat (h.toNat &&& 0xff)))
    (ByteArray.mk (Array.replicate 32 0))

theorem digestPartial_succ (state : Array UInt32) (n : Nat) :
    digestPartial state (n+1) =
      ((((digestPartial state n).set! (4*n) (UInt8.ofNat ((state[n]! >>> 24).toNat))).set!
        (4*n+1) (UInt8.ofNat ((state[n]! >>> 16).toNat &&& 0xff))).set!
        (4*n+2) (UInt8.ofNat ((state[n]! >>> 8).toNat &&& 0xff))).set!
        (4*n+3) (UInt8.ofNat (state[n]!.toNat &&& 0xff)) := by
  simp only [digestPartial,List.range'_1_concat,List.foldl_append,List.foldl_cons,List.foldl_nil,
    Nat.zero_add]

theorem digestPartial_size (state : Array UInt32) (n : Nat) : (digestPartial state n).size = 32 := by
  induction n with
  | zero => rfl
  | succ n ih => simp only [digestPartial_succ,LeanBlsSimd.Sha256.Spec.set_size,ih]

private theorem byte_mask (x : UInt8) : x &&& 255 = x := by
  apply UInt8.toBitVec_inj.mp
  exact BitVec.and_allOnes

theorem digestPartial_get (state : Array UInt32) (n : Nat) (hn : n ≤ 8)
    (w b : Nat) (hw : w < n) (hb : b < 4) :
    (digestPartial state n)[4*w+b]! = UInt8.ofNat (state[w]!.toNat >>> (8*(3-b))) := by
  induction n with
  | zero => omega
  | succ n ih =>
    rw [digestPartial_succ]
    simp (disch := (simp only [LeanBlsSimd.Sha256.Spec.set_size,digestPartial_size]; omega)) only
      [LeanBlsSimd.Sha256.Spec.set_get]
    by_cases he : w=n
    · subst w
      interval_cases b <;>
        simp [UInt32.toNat_shiftRight,byte_mask]
    · have hw' : w < n := by omega
      rw [if_neg (by omega),if_neg (by omega),if_neg (by omega),if_neg (by omega)]
      exact ih (by omega) hw'

theorem digest_size (state : Array UInt32) : (digest state).size = 32 := by
  simpa only [digestPartial,digest] using digestPartial_size state 8

theorem digest_get (state : Array UInt32) (w b : Nat) (hw : w < 8) (hb : b < 4) :
    (digest state)[4*w+b]! = UInt8.ofNat (state[w]!.toNat >>> (8*(3-b))) :=
by
  simpa only [digestPartial,digest] using digestPartial_get state 8 (by omega) w b hw hb

end LeanBlsSimd.Sha256.Spec
