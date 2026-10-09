import LeanBlsSimd.Model.DecompressG2
import LeanBlsSimd.Proofs.Fp2x8
import EthCryptographySpecs.Proofs.IdLoops

/-!
# Byte decoding

`bytesVal` reads a list of bytes as a big-endian integer, as the spec's `Fp.bytesBEToNat` does
(`bytesBEToNat_eq`). `fp_words` keeps that value in six little-endian words
(`val64_fp_words`), clearing the three flag bits of word 5 is clearing them in byte 0
(`fp_words_clear_flags`), and `less_than_p` compares that value with p (`less_than_p_iff`).

`decodeLane` states what `decode` records for one lane's bytes, in the spec's terms: the flags of
byte 0 and the two coordinates as integers. Each lane of `decode` holds exactly that
(`decode_holds`), whatever the other lanes hold. `toBytes` gives the lane's bytes as the
`ByteArray` that `G2.uncompress` reads, and `bytesBEToNat_c1` and `bytesBEToNat_c0` read its two
coordinates as `decodeLane` does.
-/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls DecompressG2

/-- A big-endian byte string as an integer. -/
def bytesVal (bs : List UInt8) : ℕ := bs.foldl (fun acc u => acc * 256 + u.toNat) 0

theorem foldl_bytesVal (bs : List UInt8) (a : ℕ) :
    bs.foldl (fun acc u => acc * 256 + u.toNat) a = a * 256 ^ bs.length + bytesVal bs := by
  induction bs generalizing a with
  | nil => simp [bytesVal]
  | cons u bs ih =>
    have h0 : bytesVal (u :: bs) = u.toNat * 256 ^ bs.length + bytesVal bs := by
      show List.foldl _ 0 (u :: bs) = _
      rw [List.foldl_cons, ih]
      simp
    rw [List.foldl_cons, ih, h0, List.length_cons, pow_succ]
    ring

theorem bytesVal_append (as bs : List UInt8) :
    bytesVal (as ++ bs) = bytesVal as * 256 ^ bs.length + bytesVal bs := by
  rw [bytesVal, List.foldl_append, foldl_bytesVal]
  rfl

theorem bytesVal_cons (u : UInt8) (bs : List UInt8) :
    bytesVal (u :: bs) = u.toNat * 256 ^ bs.length + bytesVal bs := by
  rw [show u :: bs = [u] ++ bs from rfl, bytesVal_append]
  simp [bytesVal]

theorem bytesVal_lt (bs : List UInt8) : bytesVal bs < 256 ^ bs.length := by
  induction bs with
  | nil => simp [bytesVal]
  | cons u bs ih =>
    rw [bytesVal_cons, List.length_cons, pow_succ]
    have := u.toNat_lt
    nlinarith

/-! ## The spec's decoder -/

theorem shiftLeft_or_byte (acc : ℕ) (u : UInt8) : (acc <<< 8) ||| u.toNat = acc * 256 + u.toNat := by
  rw [Nat.shiftLeft_eq, Nat.or_comm, or_mul_two_pow u.toNat_lt, add_comm]
  rfl

open EthCryptographySpecs.IdLoops in
theorem bytesBEToNat_eq (b : ByteArray) : Fp.bytesBEToNat b = bytesVal b.data.toList := by
  unfold Fp.bytesBEToNat
  dsimp only [Id.run, id_pure, id_bind]
  rw [forIn_range_yield]
  rw [show (fun (acc : Nat) (i : Nat) => (acc <<< 8) ||| b[i]!.toNat)
      = fun acc i => (acc <<< 8) ||| b.data[i]!.toNat from
      funext fun acc => funext fun i => by
        congr 2
        by_cases h : i < b.size
        · rw [getElem!_pos b i h, getElem!_pos b.data i h]
          rfl
        · rw [getElem!_neg b i h, getElem!_neg b.data i h]]
  show (List.range' 0 b.data.size).foldl
      (fun acc i => (acc <<< 8) ||| b.data[i]!.toNat) 0 = _
  rw [foldl_range'_getElem! b.data (fun acc u => (acc <<< 8) ||| u.toNat) 0, bytesVal]
  congr
  funext acc u
  exact shiftLeft_or_byte acc u

/-! ## The kernel's words -/

theorem vector_foldl_eq {α β : Type} {n : ℕ} (f : β → α → β) (b : β) (v : Vector α n) :
    v.foldl f b = v.toList.foldl f b := by
  rcases v with ⟨xs, h⟩
  simp [Vector.toList]

theorem toNat_foldl_shift (bs : List UInt8) (a : UInt64) (hn : bs.length ≤ 8)
    (ha : a.toNat < 256 ^ (8 - bs.length)) :
    (bs.foldl (fun (acc : UInt64) (b : UInt8) => (acc <<< 8) ||| b.toUInt64) a).toNat =
      a.toNat * 256 ^ bs.length + bytesVal bs := by
  induction bs generalizing a with
  | nil => simp [bytesVal]
  | cons u bs ih =>
    simp only [List.length_cons] at hn ha
    have h8 : a.toNat * 256 < 2 ^ 64 := by
      have : (256 : ℕ) ^ (8 - (bs.length + 1)) * 256 ≤ 2 ^ 64 := by
        rw [← pow_succ, show (2 : ℕ) ^ 64 = 256 ^ 8 by norm_num]
        exact Nat.pow_le_pow_right (by norm_num) (by omega)
      nlinarith
    have hstep : ((a <<< 8) ||| u.toUInt64).toNat = a.toNat * 256 + u.toNat := by
      rw [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt8.toNat_toUInt64,
        show (8 : UInt64).toNat % 64 = 8 by decide, Nat.mod_eq_of_lt (by rw [Nat.shiftLeft_eq]; omega),
        shiftLeft_or_byte]
    rw [List.foldl_cons, ih _ (by omega), hstep, bytesVal_cons, List.length_cons, pow_succ]
    · ring
    · rw [hstep]
      have hu := u.toNat_lt
      have : (256 : ℕ) ^ (8 - bs.length) = 256 ^ (8 - (bs.length + 1)) * 256 := by
        rw [← pow_succ]; congr 1; omega
      rw [this]
      nlinarith

theorem toNat_u64_from_be_bytes (v : Vector UInt8 8) :
    (u64_from_be_bytes v).toNat = bytesVal v.toList := by
  rw [u64_from_be_bytes, vector_foldl_eq, toNat_foldl_shift _ _ (by simp) (by simp)]
  simp

theorem bytesVal_drop (l : List UInt8) (k : ℕ) :
    bytesVal (l.drop k) =
      bytesVal ((l.drop k).take 8) * 256 ^ (l.length - (k + 8)) + bytesVal (l.drop (k + 8)) := by
  conv_lhs => rw [← List.take_append_drop 8 (l.drop k)]
  rw [bytesVal_append, List.drop_drop, List.length_drop]

theorem toList_fp_words_chunk (be : Vector UInt8 FP_BYTES) (w : Fin 6) :
    (Vector.ofFn fun i : Fin 8 => be[FP_BYTES - 8 * (w.val + 1) + i.val]'(by
        have := w.isLt; have := i.isLt; simp only [FP_BYTES, G2_COMPRESSED_LEN] at *; omega)).toList =
      (be.toList.drop (40 - 8 * w.val)).take 8 := by
  have hw := w.isLt
  apply List.ext_getElem
  · simp [FP_BYTES, G2_COMPRESSED_LEN]
    omega
  · intro i h1 h2
    simp only [Vector.toList_ofFn, List.getElem_ofFn, List.getElem_take, List.getElem_drop,
      Vector.getElem_toList]
    congr 1
    simp only [FP_BYTES, G2_COMPRESSED_LEN]
    omega

set_option exponentiation.threshold 400 in
theorem val64_fp_words (be : Vector UInt8 FP_BYTES) : val64 (fp_words be) = bytesVal be.toList := by
  have hl : be.toList.length = 48 := by simp [FP_BYTES, G2_COMPRESSED_LEN]
  have hw (w : ℕ) (hw : w < 6) :
      ((fp_words be)[w]).toNat = bytesVal ((be.toList.drop (40 - 8 * w)).take 8) := by
    rw [← toList_fp_words_chunk be ⟨w, hw⟩, ← toNat_u64_from_be_bytes]
    simp [fp_words]
  rw [val64_eq, hw 0 (by decide), hw 1 (by decide), hw 2 (by decide), hw 3 (by decide),
    hw 4 (by decide), hw 5 (by decide)]
  have e0 := bytesVal_drop be.toList 0
  have e8 := bytesVal_drop be.toList 8
  have e16 := bytesVal_drop be.toList 16
  have e24 := bytesVal_drop be.toList 24
  have e32 := bytesVal_drop be.toList 32
  have e40 := bytesVal_drop be.toList 40
  rw [hl] at e0 e8 e16 e24 e32 e40
  rw [List.drop_zero] at e0
  have e48 : bytesVal (be.toList.drop 48) = 0 := by
    rw [List.drop_eq_nil_of_le (by omega)]
    rfl
  norm_num at e0 e8 e16 e24 e32 e40 ⊢
  rw [e0, e8, e16, e24, e32, e40, e48]
  ring

theorem zero_lt_FP_BYTES : 0 < FP_BYTES := by decide

/-- Byte 0 of a coordinate with its three flag bits cleared, as `G2.uncompress` clears them. -/
def clearFlags (h : Vector UInt8 FP_BYTES) : Vector UInt8 FP_BYTES :=
  h.set 0 (h[0]'zero_lt_FP_BYTES &&& 0x1f) zero_lt_FP_BYTES

theorem toList_take_eight (h : Vector UInt8 FP_BYTES) :
    h.toList.take 8 = h[0]'zero_lt_FP_BYTES :: (h.toList.drop 1).take 7 := by
  have hl : h.toList.length = 48 := by simp [FP_BYTES, G2_COMPRESSED_LEN]
  apply List.ext_getElem
  · simp [hl]
  · intro i h1 h2
    cases i with
    | zero => simp
    | succ i => simp

/-- Clearing the top three bits of word 5 is clearing them in byte 0. -/
theorem fp_words_clear_flags (h : Vector UInt8 FP_BYTES) :
    (fp_words h).set 5 ((fp_words h)[5] &&& 0x1fffffffffffffff) = fp_words (clearFlags h) := by
  have hchunk (g : Vector UInt8 FP_BYTES) : (u64_from_be_bytes (Vector.ofFn fun i : Fin 8 =>
      g[FP_BYTES - 8 * (5 + 1) + i.val]'(by
        have := i.isLt; simp only [FP_BYTES, G2_COMPRESSED_LEN] at *; omega))).toNat =
      bytesVal (g.toList.take 8) := by
    rw [toNat_u64_from_be_bytes]
    exact congrArg bytesVal (toList_fp_words_chunk g 5)
  ext j hj
  by_cases h5 : j = 5
  · subst h5
    rw [Vector.getElem_set_self, UInt64.toNat_and,
      show (0x1fffffffffffffff : UInt64).toNat = 2 ^ 61 - 1 by decide,
      Nat.and_two_pow_sub_one_eq_mod]
    simp only [fp_words, Vector.getElem_ofFn]
    rw [hchunk, hchunk, toList_take_eight, toList_take_eight, bytesVal_cons, bytesVal_cons]
    have hrest : ((clearFlags h).toList.drop 1).take 7 = (h.toList.drop 1).take 7 := by
      simp only [clearFlags, Vector.toList_set]
      generalize h.toList = l
      cases l <;> rfl
    have hlen : ((h.toList.drop 1).take 7).length = 7 := by
      simp [FP_BYTES, G2_COMPRESSED_LEN]
    have h0 : ((clearFlags h)[0]'zero_lt_FP_BYTES).toNat = (h[0]'zero_lt_FP_BYTES).toNat % 32 := by
      rw [clearFlags, Vector.getElem_set_self, UInt8.toNat_and,
        show (0x1f : UInt8).toNat = 2 ^ 5 - 1 by decide, Nat.and_two_pow_sub_one_eq_mod]
    rw [hrest, hlen, h0]
    have hr := bytesVal_lt ((h.toList.drop 1).take 7)
    rw [hlen] at hr
    have hu := (h[0]'zero_lt_FP_BYTES).toNat_lt
    omega
  · rw [Vector.getElem_set_ne _ _ (Ne.symm h5)]
    unfold fp_words
    rw [Vector.getElem_ofFn, Vector.getElem_ofFn]
    apply congrArg UInt64.toNat
    apply congrArg u64_from_be_bytes
    ext i hi
    rw [Vector.getElem_ofFn, Vector.getElem_ofFn, clearFlags, Vector.getElem_set_ne]
    simp only [FP_BYTES, G2_COMPRESSED_LEN]
    omega

/-! ## `less_than_p` -/

/-- The loop body of `less_than_p`. -/
def ltStep (x : Vector UInt64 6) (r : Option Bool) (w : ℕ) : Option Bool :=
  match r with
  | some b => some b
  | none => if x[w]! ≠ P_U64v[w]! then some (x[w]! < P_U64v[w]!) else none

theorem less_than_p_eq (x : Vector UInt64 6) :
    less_than_p x = ((List.range 6).reverse.foldl (ltStep x) none).getD false := rfl

theorem foldl_ltStep_some (x : Vector UInt64 6) :
    ∀ (ws : List ℕ) (b : Bool), ws.foldl (ltStep x) (some b) = some b
  | [], _ => rfl
  | _ :: ws, b => foldl_ltStep_some x ws b

/-- The low `k` words as an integer. -/
def lowVal (x : Vector UInt64 6) : ℕ → ℕ
  | 0 => 0
  | k + 1 => x[k]!.toNat * 2 ^ (64 * k) + lowVal x k

theorem lowVal_lt (x : Vector UInt64 6) : ∀ k, lowVal x k < 2 ^ (64 * k)
  | 0 => by simp [lowVal]
  | k + 1 => by
    have ih := lowVal_lt x k
    have hk := (x[k]!).toNat_lt
    rw [lowVal, show 64 * (k + 1) = 64 + 64 * k by ring, pow_add]
    have : (x[k]!.toNat + 1) * 2 ^ (64 * k) ≤ 2 ^ 64 * 2 ^ (64 * k) :=
      Nat.mul_le_mul_right _ hk
    nlinarith

theorem lex_lt {a b A B C : ℕ} (hab : a ≠ b) (hA : A < C) (hB : B < C) :
    a * C + A ≠ b * C + B ∧ (a * C + A < b * C + B ↔ a < b) := by
  rcases Nat.lt_or_gt_of_ne hab with h | h
  · have : (a + 1) * C ≤ b * C := Nat.mul_le_mul_right _ h
    refine ⟨by nlinarith, iff_of_true (by nlinarith) h⟩
  · have : (b + 1) * C ≤ a * C := Nat.mul_le_mul_right _ h
    refine ⟨by nlinarith, iff_of_false (by nlinarith) (by omega)⟩

theorem foldl_ltStep (x : Vector UInt64 6) : ∀ k : ℕ,
    (List.range k).reverse.foldl (ltStep x) none =
      if lowVal x k = lowVal P_U64v k then none
      else some (decide (lowVal x k < lowVal P_U64v k))
  | 0 => by simp [lowVal]
  | k + 1 => by
    rw [List.range_succ, List.reverse_append, List.reverse_singleton, List.singleton_append,
      List.foldl_cons]
    have hA := lowVal_lt x k
    have hB := lowVal_lt P_U64v k
    by_cases hk : x[k]! = P_U64v[k]!
    · have hstep : ltStep x none k = none := by simp [ltStep, hk]
      rw [hstep, foldl_ltStep x k, lowVal, lowVal, hk]
      simp only [Nat.add_left_cancel_iff, Nat.add_lt_add_iff_left]
    · have hstep : ltStep x none k = some (decide (x[k]! < P_U64v[k]!)) := by
        simp [ltStep, hk]
      have hne : x[k]!.toNat ≠ P_U64v[k]!.toNat := fun h => hk (UInt64.toNat_inj.mp h)
      obtain ⟨h1, h2⟩ := lex_lt hne hA hB
      rw [hstep, foldl_ltStep_some, lowVal, lowVal, if_neg h1, decide_eq_decide.mpr h2]
      rfl

set_option exponentiation.threshold 400 in
theorem lowVal_six (x : Vector UInt64 6) : lowVal x 6 = val64 x := by
  simp only [lowVal, val64_eq]
  have h (k : ℕ) (hk : k < 6) : x[k]! = x[k] := getElem!_pos x k hk
  rw [h 0 (by decide), h 1 (by decide), h 2 (by decide), h 3 (by decide), h 4 (by decide),
    h 5 (by decide)]
  norm_num
  ring

theorem lowVal_P : lowVal P_U64v 6 = Fp.modulus := by decide +kernel

theorem less_than_p_iff (x : Vector UInt64 6) : less_than_p x = decide (val64 x < Fp.modulus) := by
  rw [less_than_p_eq, foldl_ltStep, lowVal_six, lowVal_P]
  by_cases h : val64 x = Fp.modulus
  · rw [if_pos h, h]
    exact (decide_eq_false (lt_irrefl _)).symm
  · rw [if_neg h, Option.getD_some]

/-! ## `decode`, lane by lane -/

namespace DecompressG2

theorem zero_lt_G2_COMPRESSED_LEN : 0 < G2_COMPRESSED_LEN := by decide

/-- What `decode` records for one lane's bytes, with its coordinates as integers. -/
structure LaneDecode where
  x0 : ℕ
  x1 : ℕ
  largerRoot : Bool
  invalid : Bool
  undecided : Bool

/-- `decode` on one lane's bytes, in the spec's terms: the flags of byte 0, and the two
coordinates as big-endian integers, x1 with its flag bits cleared. -/
def decodeLane (bytes : Vector UInt8 G2_COMPRESSED_LEN) : LaneDecode :=
  let head := bytes[0]'zero_lt_G2_COMPRESSED_LEN
  let v1 := bytesVal (clearFlags (split_at bytes).1).toList
  let v0 := bytesVal (split_at bytes).2.toList
  if head &&& 0x80 = 0 then ⟨0, 0, false, true, false⟩
  else if head &&& 0x40 ≠ 0 then ⟨0, 0, false, false, true⟩
  else if v1 < Fp.modulus ∧ v0 < Fp.modulus then ⟨v0, v1, decide (head &&& 0x20 ≠ 0), false, false⟩
  else ⟨0, 0, decide (head &&& 0x20 ≠ 0), true, false⟩

/-- Lane `l` of `d` holds `r`: limbs that meet `Fp8Inv` with `r`'s values, and `r`'s mask bits. -/
structure LaneDecode.Holds (r : LaneDecode) (d : Decoded) (l : Fin 8) : Prop where
  inv0 : Fp8Inv d.x0[l]
  val0 : val d.x0[l] = r.x0
  inv1 : Fp8Inv d.x1[l]
  val1 : val d.x1[l] = r.x1
  largerRoot : d.larger_root.toNat.testBit l = r.largerRoot
  invalid : d.invalid.toNat.testBit l = r.invalid
  undecided : d.undecided.toNat.testBit l = r.undecided

/-- Lane `l` of a `Decoded`: its limbs and its three mask bits. -/
def Decoded.lane (d : Decoded) (l : Fin 8) : Limbs × Limbs × Bool × Bool × Bool :=
  (d.x0[l], d.x1[l], d.larger_root.toNat.testBit l, d.invalid.toNat.testBit l,
    d.undecided.toNat.testBit l)

theorem LaneDecode.Holds.of_lane {r : LaneDecode} {d d' : Decoded} {l : Fin 8} (h : r.Holds d l)
    (he : d'.lane l = d.lane l) : r.Holds d' l := by
  simp only [Decoded.lane, Prod.mk.injEq] at he
  obtain ⟨h0, h1, h2, h3, h4⟩ := he
  exact ⟨h0 ▸ h.inv0, h0 ▸ h.val0, h1 ▸ h.inv1, h1 ▸ h.val1, h2 ▸ h.largerRoot,
    h3 ▸ h.invalid, h4 ▸ h.undecided⟩

def decodeInit : Decoded := {
  x0 := .replicate 8 (.replicate 8 0),
  x1 := .replicate 8 (.replicate 8 0),
  larger_root := 0,
  invalid := 0,
  undecided := 0 }

/-- The loop body of `decode`. -/
def decodeStep (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (d : Decoded) (lane : Fin 8) :
    Decoded :=
  let bytes := inputs[lane]
  let bit : Mmask8 := 1 <<< lane.val.toUInt8
  let flags := bytes[0]'(by simp [G2_COMPRESSED_LEN]) &&& 0xe0
  if flags &&& FLAG_COMPRESSED = 0 then { d with invalid := d.invalid ||| bit }
  else if flags &&& FLAG_INFINITY ≠ 0 then { d with undecided := d.undecided ||| bit }
  else
    let d := if flags &&& FLAG_LARGER_ROOT ≠ 0 then
      { d with larger_root := d.larger_root ||| bit } else d
    let (x1_bytes, x0_bytes) := split_at bytes
    let x1 := fp_words x1_bytes
    let x1 := x1.set 5 (x1[5] &&& 0x1fffffffffffffff)
    let x0 := fp_words x0_bytes
    if !less_than_p x1 || !less_than_p x0 then { d with invalid := d.invalid ||| bit }
    else { d with x0 := d.x0.set lane (unpack52 x0), x1 := d.x1.set lane (unpack52 x1) }

theorem decode_eq (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) :
    decode inputs = (List.finRange 8).foldl (decodeStep inputs) decodeInit := rfl

theorem decodeStep_lane_ne (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (d : Decoded)
    {i l : Fin 8} (hl : l ≠ i) : (decodeStep inputs d i).lane l = d.lane l := by
  have hb (k : Mmask8) : (k ||| (1 <<< i.val.toUInt8)).toNat.testBit l = k.toNat.testBit l := by
    rw [Mmask8.testBit_or, Mmask8.testBit_one_shiftLeft, decide_eq_false hl, Bool.or_false]
  have hs (v : Vector Limbs 8) (x : Limbs) : (v.set i x)[l] = v[l] :=
    Vector.getElem_set_ne _ _ (fun h => hl (Fin.ext h).symm)
  unfold decodeStep
  dsimp only
  split_ifs <;> simp only [Decoded.lane, hb, hs]

def initLane : Limbs × Limbs × Bool × Bool × Bool :=
  (.replicate 8 0, .replicate 8 0, false, false, false)

theorem inv_replicate_zero : Fp8Inv (.replicate 8 0) := ⟨by decide, by decide +kernel⟩

theorem flag_compressed (b : UInt8) : (b &&& 0xe0) &&& FLAG_COMPRESSED = b &&& 0x80 := by
  rw [UInt8.and_assoc]
  rfl

theorem flag_infinity (b : UInt8) : (b &&& 0xe0) &&& FLAG_INFINITY = b &&& 0x40 := by
  rw [UInt8.and_assoc]
  rfl

theorem flag_larger_root (b : UInt8) : (b &&& 0xe0) &&& FLAG_LARGER_ROOT = b &&& 0x20 := by
  rw [UInt8.and_assoc]
  rfl

theorem decodeStep_lane_self (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (d : Decoded)
    (i : Fin 8) (h0 : d.lane i = initLane) :
    (decodeLane inputs[i]).Holds (decodeStep inputs d i) i := by
  simp only [Decoded.lane, initLane, Prod.mk.injEq] at h0
  obtain ⟨hx0, hx1, hlr, hinv, hund⟩ := h0
  have hb (k : Mmask8) : (k ||| (1 <<< i.val.toUInt8)).toNat.testBit i = true := by
    rw [Mmask8.testBit_or, Mmask8.testBit_one_shiftLeft, decide_eq_true rfl, Bool.or_true]
  unfold decodeStep decodeLane
  dsimp only
  simp only [flag_compressed, flag_infinity, flag_larger_root]
  generalize split_at inputs[i] = sp
  obtain ⟨x1b, x0b⟩ := sp
  dsimp only
  rw [fp_words_clear_flags, less_than_p_iff, less_than_p_iff, val64_fp_words, val64_fp_words]
  have hz0 : Fp8Inv d.x0[i] ∧ val d.x0[i] = 0 := ⟨hx0 ▸ inv_replicate_zero, by rw [hx0]; exact val_replicate_zero⟩
  have hz1 : Fp8Inv d.x1[i] ∧ val d.x1[i] = 0 := ⟨hx1 ▸ inv_replicate_zero, by rw [hx1]; exact val_replicate_zero⟩
  have hcond : ∀ a b : Prop, [Decidable a] → [Decidable b] →
      ((!decide a || !decide b) = true) = ¬(a ∧ b) := by
    intro a b _ _
    by_cases ha : a <;> by_cases hb : b <;> simp [ha, hb]
  simp only [hcond, ite_not]
  generalize inputs[i][0]'zero_lt_G2_COMPRESSED_LEN = head
  have hok {v : Vector UInt8 FP_BYTES} (h : bytesVal v.toList < Fp.modulus) :
      Fp8Inv (unpack52 (fp_words v)) ∧ val (unpack52 (fp_words v)) = bytesVal v.toList := by
    rw [← val64_fp_words] at h ⊢
    exact ⟨inv_unpack52 h, (unpack52_spec _).2⟩
  have hs (v : Vector Limbs 8) (x : Limbs) : (v.set i x)[i] = x := Vector.getElem_set_self ..
  split_ifs with h1 h2 h3 h4
  · exact ⟨hz0.1, hz0.2, hz1.1, hz1.2, hlr, hb _, hund⟩
  · refine ⟨?_, ?_, ?_, ?_, ?_, hinv, hund⟩
    · rw [hs]; exact (hok h3.2).1
    · rw [hs]; exact (hok h3.2).2
    · rw [hs]; exact (hok h3.1).1
    · rw [hs]; exact (hok h3.1).2
    · rw [hlr, decide_eq_false (not_not.mpr h4)]
  · refine ⟨?_, ?_, ?_, ?_, ?_, hinv, hund⟩
    · rw [hs]; exact (hok h3.2).1
    · rw [hs]; exact (hok h3.2).2
    · rw [hs]; exact (hok h3.1).1
    · rw [hs]; exact (hok h3.1).2
    · rw [hb, decide_eq_true h4]
  · exact ⟨hz0.1, hz0.2, hz1.1, hz1.2, by rw [hlr, decide_eq_false (not_not.mpr ‹_›)], hb _, hund⟩
  · exact ⟨hz0.1, hz0.2, hz1.1, hz1.2, by rw [hb, decide_eq_true ‹_›], hb _, hund⟩
  · exact ⟨hz0.1, hz0.2, hz1.1, hz1.2, hlr, hinv, hb _⟩

theorem foldl_decodeStep (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) :
    ∀ (ls : List (Fin 8)) (d : Decoded) (l : Fin 8), ls.Nodup →
      (l ∉ ls → (ls.foldl (decodeStep inputs) d).lane l = d.lane l) ∧
      (l ∈ ls → d.lane l = initLane →
        (decodeLane inputs[l]).Holds (ls.foldl (decodeStep inputs) d) l)
  | [], d, l, _ => ⟨fun _ => rfl, fun h => absurd h List.not_mem_nil⟩
  | i :: ls, d, l, hnd => by
    have hi : i ∉ ls := (List.nodup_cons.mp hnd).1
    have hnd' := (List.nodup_cons.mp hnd).2
    rw [List.foldl_cons]
    refine ⟨fun hl => ?_, fun hl h0 => ?_⟩
    · have hli : l ≠ i := fun h => hl (h ▸ List.mem_cons_self ..)
      have hlr : l ∉ ls := fun h => hl (List.mem_cons_of_mem _ h)
      rw [(foldl_decodeStep inputs ls _ l hnd').1 hlr, decodeStep_lane_ne inputs d hli]
    · by_cases hli : l = i
      · subst hli
        exact (decodeStep_lane_self inputs d l h0).of_lane
          ((foldl_decodeStep inputs ls _ l hnd').1 hi)
      · have hlr : l ∈ ls := (List.mem_cons.mp hl).resolve_left hli
        exact (foldl_decodeStep inputs ls _ l hnd').2 hlr
          (by rw [decodeStep_lane_ne inputs d hli, h0])

/-- Each lane of `decode` records what its own bytes decode to. -/
theorem decode_holds (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8) :
    (decodeLane inputs[l]).Holds (decode inputs) l := by
  rw [decode_eq]
  refine (foldl_decodeStep inputs _ decodeInit l (List.nodup_finRange 8)).2
    (List.mem_finRange l) ?_
  simp [Decoded.lane, decodeInit, initLane]

/-! ## The spec's bytes -/

/-- A lane's 96 bytes as the `ByteArray` that `G2.uncompress` reads. -/
def toBytes (bytes : Vector UInt8 G2_COMPRESSED_LEN) : ByteArray := ⟨bytes.toArray⟩

theorem size_toBytes (bytes : Vector UInt8 G2_COMPRESSED_LEN) : (toBytes bytes).size = 96 := by
  simp [toBytes, ByteArray.size, G2_COMPRESSED_LEN]

theorem get!_toBytes_zero (bytes : Vector UInt8 G2_COMPRESSED_LEN) :
    (toBytes bytes).get! 0 = bytes[0]'zero_lt_G2_COMPRESSED_LEN := by
  show bytes.toArray[0]! = _
  rw [getElem!_pos bytes.toArray 0 (by simp [G2_COMPRESSED_LEN])]
  simp

theorem toList_clearFlags_split (bytes : Vector UInt8 G2_COMPRESSED_LEN) :
    (clearFlags (split_at bytes).1).toList =
      ((bytes.toList.set 0 (bytes[0]'zero_lt_G2_COMPRESSED_LEN &&& 0x1f)).drop 0).take 48 := by
  apply List.ext_getElem
  · simp [FP_BYTES, G2_COMPRESSED_LEN]
  · intro i h1 h2
    simp only [clearFlags, Vector.toList_set, List.getElem_set, List.getElem_take, List.getElem_drop,
      Vector.getElem_toList, split_at, Vector.toList_ofFn, List.getElem_ofFn, Vector.getElem_ofFn]
    by_cases hi : 0 = i
    · subst hi
      simp only [if_true]
    · simp only [Nat.zero_add]

theorem toList_split_snd (bytes : Vector UInt8 G2_COMPRESSED_LEN) (v : UInt8) :
    (split_at bytes).2.toList = ((bytes.toList.set 0 v).drop 48).take (96 - 48) := by
  apply List.ext_getElem
  · simp [FP_BYTES, G2_COMPRESSED_LEN]
  · intro i h1 h2
    simp only [List.getElem_set, List.getElem_take, List.getElem_drop, Vector.getElem_toList,
      split_at, Vector.toList_ofFn, List.getElem_ofFn]
    rw [if_neg (by omega)]
    rfl

theorem bytesBEToNat_c1 (bytes : Vector UInt8 G2_COMPRESSED_LEN) :
    Fp.bytesBEToNat (((toBytes bytes).set! 0 ((toBytes bytes).get! 0 &&& 0x1f)).extract 0 48) =
      bytesVal (clearFlags (split_at bytes).1).toList := by
  rw [bytesBEToNat_eq, ByteArray.data_extract, get!_toBytes_zero, toList_clearFlags_split]
  simp [toBytes, ByteArray.set!]
  rfl

theorem bytesBEToNat_c0 (bytes : Vector UInt8 G2_COMPRESSED_LEN) :
    Fp.bytesBEToNat (((toBytes bytes).set! 0 ((toBytes bytes).get! 0 &&& 0x1f)).extract 48 96) =
      bytesVal (split_at bytes).2.toList := by
  rw [bytesBEToNat_eq, ByteArray.data_extract, toList_split_snd bytes ((toBytes bytes).get! 0 &&& 0x1f)]
  simp [toBytes, ByteArray.set!]
  rfl

end DecompressG2

end LeanBlsSimd
