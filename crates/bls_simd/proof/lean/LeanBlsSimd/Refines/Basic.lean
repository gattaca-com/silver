import LeanBlsSimd.Extracted.Funs
import LeanBlsSimd.Model.DecompressG2

/-!
# Conversions between Aeneas values and model values

A refinement theorem has the form `gen args = ok (toX (model (ofX args)))`. The `of*` functions
read Aeneas values as model values, and the `to*` functions convert back. In this form a theorem
rewrites a generated call on any arguments. The roundtrip lemmas then cancel nested conversions.

The other lemmas evaluate Aeneas primitives to `ok` when their arguments are in bounds.
-/

open Aeneas Aeneas.Std Result

namespace LeanBlsSimd

abbrev ofU64 (x : U64) : UInt64 := .ofBitVec x.bv
abbrev toU64 (x : UInt64) : U64 := ⟨x.toBitVec⟩
abbrev ofU8 (x : U8) : UInt8 := .ofBitVec x.bv
abbrev toU8 (x : UInt8) : U8 := ⟨x.toBitVec⟩

@[simp] theorem ofU64_toU64 (x : UInt64) : ofU64 (toU64 x) = x := rfl
@[simp] theorem toU64_ofU64 (x : U64) : toU64 (ofU64 x) = x := rfl
@[simp] theorem ofU8_toU8 (x : UInt8) : ofU8 (toU8 x) = x := rfl
@[simp] theorem toU8_ofU8 (x : U8) : toU8 (ofU8 x) = x := rfl

@[simp] theorem ofU64_and (a b : U64) : ofU64 (a &&& b) = ofU64 a &&& ofU64 b := rfl
@[simp] theorem ofU64_or (a b : U64) : ofU64 (a ||| b) = ofU64 a ||| ofU64 b := rfl
@[simp] theorem ofU64_mk (b : BitVec 64) : ofU64 ⟨b⟩ = UInt64.ofBitVec b := rfl

@[simp] theorem val_toU64 (x : UInt64) : (toU64 x).val = x.toNat := rfl

@[simp] theorem toNat_ofU64 (a : U64) : (ofU64 a).toNat = a.val := rfl

@[simp] theorem toU8_and (a b : UInt8) : toU8 a &&& toU8 b = toU8 (a &&& b) := rfl
@[simp] theorem toU8_or (a b : UInt8) : toU8 a ||| toU8 b = toU8 (a ||| b) := rfl
@[simp] theorem toU8_inj (a b : UInt8) : toU8 a = toU8 b ↔ a = b :=
  ⟨fun h => by simpa using congrArg ofU8 h, fun h => h ▸ rfl⟩
@[simp] theorem toU64_and (a b : UInt64) : toU64 a &&& toU64 b = toU64 (a &&& b) := rfl

theorem eq_toU64_iff (y : U64) (x : UInt64) : y = toU64 x ↔ ofU64 y = x := by
  constructor
  · rintro rfl; rfl
  · rintro rfl; rfl

@[simp] theorem ofBitVec_hcast_I64 (x : U64) :
    Int64.ofBitVec (UScalar.hcast .I64 x).bv = (ofU64 x).toInt64 := rfl

def ofArray {α β : Type} {n : Usize} {m : ℕ} (f : α → β) (a : Array α n)
    (h : n.val = m := by rfl) : Vector β m :=
  ⟨(a.val.map f).toArray, by simp [a.property, h]⟩

def toArray {α β : Type} {n : Usize} {m : ℕ} (f : β → α) (v : Vector β m)
    (h : n.val = m := by rfl) : Array α n :=
  ⟨v.toList.map f, by simp [h]⟩

def ofSlice {α β : Type} {m : ℕ} (f : α → β) (s : Slice α) (h : s.val.length = m) :
    Vector β m :=
  ⟨(s.val.map f).toArray, by simp [h]⟩

section Arrays

variable {α β : Type} {n : Usize} {m : ℕ}

@[simp] theorem toArray_val (f : β → α) (v : Vector β m) (h : n.val = m) :
    (toArray f v h).val = v.toList.map f := rfl

@[simp] theorem toList_ofArray (f : α → β) (a : Array α n) (h : n.val = m) :
    (ofArray f a h).toList = a.val.map f := by
  simp [ofArray, Vector.toList]

@[simp] theorem getElem_ofArray (f : α → β) (a : Array α n) (h : n.val = m) (i : ℕ)
    (hi : i < m) :
    (ofArray f a h)[i] = f (a.val[i]'(by rw [a.property, h]; exact hi)) := by
  simp [ofArray]

@[simp] theorem ofArray_toArray {f : α → β} {g : β → α} (hfg : ∀ x, f (g x) = x)
    (v : Vector β m) (h : n.val = m) (h' : n.val = m) : ofArray f (toArray g v h) h' = v := by
  apply Vector.toList_inj.mp
  simp [Function.comp_def, hfg]

@[simp] theorem toArray_ofArray {f : α → β} {g : β → α} (hgf : ∀ x, g (f x) = x)
    (a : Array α n) (h : n.val = m) (h' : n.val = m) : toArray g (ofArray f a h) h' = a := by
  apply Subtype.ext
  simp [Function.comp_def, hgf]

@[simp] theorem ofArray_toArray_id (v : Vector α m) (h : n.val = m) (h' : n.val = m) :
    ofArray id (toArray id v h) h' = v :=
  ofArray_toArray (fun _ => rfl) v h h'

@[simp] theorem ofArray_toArray_ofU64 (v : Vector UInt64 m) (h : n.val = m) (h' : n.val = m) :
    ofArray ofU64 (toArray toU64 v h) h' = v :=
  ofArray_toArray (fun _ => rfl) v h h'

theorem index_usize_eq (a : Array α n) (j : Usize) (hj : j.val < n.val) :
    Array.index_usize a j = ok (a.val[j.val]'(by rw [a.property]; exact hj)) := by
  simp [Array.index_usize, a.property, hj]

theorem update_eq (a : Array α n) (j : Usize) (x : α) (hj : j.val < n.val) :
    Array.update a j x = ok (a.set j x) := by
  simp [Array.update, a.property, hj]; rfl

theorem toArray_replicate (f : β → α) (x : β) (h : n.val = m) :
    toArray f (Vector.replicate m x) h = Array.repeat n (f x) := by
  apply Subtype.ext
  simp [h]

end Arrays

@[simp] theorem set_toArray {α β : Type} {n : Usize} {m : ℕ} (f : β → α) (v : Vector β m)
    (h : n.val = m) (i : Usize) (x : β) (hi : i.val < m) :
    (toArray f v h).set i (f x) = toArray f (v.set i.val x hi) h := by
  apply Subtype.ext
  simp [List.map_set, Vector.toList_set]

theorem toArray_set_of_eq {α β : Type} {n : Usize} {m : ℕ} (f : β → α) (v : Vector β m)
    (h : n.val = m) (i : Usize) (j : ℕ) (hj : j < m) (x : β) (y : α) (hij : i.val = j)
    (hy : y = f x) : (toArray f v h).set i y = toArray f (v.set j x hj) h := by
  subst hy hij; exact set_toArray f v h i x hj

theorem index_usize_toArray {α β : Type} {n : Usize} {m : ℕ} (f : β → α) (v : Vector β m)
    (h : n.val = m) (j : Usize) (hj : j.val < m) :
    Array.index_usize (toArray f v h) j = ok (f v[j.val]) := by
  rw [index_usize_eq _ _ (by rw [h]; exact hj)]
  simp

@[simp] theorem getElem_ofSlice {α β : Type} {m : ℕ} (f : α → β) (s : Slice α)
    (h : s.val.length = m) (i : ℕ) (hi : i < m) :
    (ofSlice f s h)[i] = f (s.val[i]'(by rw [h]; exact hi)) := by
  simp [ofSlice]

@[simp] theorem toList_ofSlice {α β : Type} {m : ℕ} (f : α → β) (s : Slice α)
    (h : s.val.length = m) : (ofSlice f s h).toList = s.val.map f := by
  simp [ofSlice, Vector.toList]

theorem foldl_set_ofFn {α : Type} {n : ℕ} (F : Fin n → α) (v : Vector α n) :
    (List.finRange n).foldl (fun v j => v.set j (F j)) v = Vector.ofFn F := by
  have key : ∀ (l : List (Fin n)) (v : Vector α n) (i : ℕ) (hi : i < n),
      (l.foldl (fun v j => v.set j (F j)) v)[i] =
        if ⟨i, hi⟩ ∈ l then F ⟨i, hi⟩ else v[i] := by
    intro l
    induction l with
    | nil => simp
    | cons j l ih =>
      intro v i hi
      rw [List.foldl_cons, ih]
      by_cases h : (⟨i, hi⟩ : Fin n) ∈ l
      · simp [h]
      · by_cases hj : j.val = i
        · have : j = ⟨i, hi⟩ := Fin.ext hj
          subst this; simp [h]
        · have : j ≠ ⟨i, hi⟩ := fun e => hj (by rw [e])
          simp [h, hj, Ne.symm this]
  ext i hi
  rw [key]
  simp

theorem vector_set!_eq {α : Type} {m : ℕ} (v : Vector α m) (k : ℕ) (hk : k < m) (x : α) :
    v.set! k x = v.set k x hk := by
  apply Vector.toArray_inj.mp
  simp [Vector.set!, Vector.set, Array.set!, Array.setIfInBounds, hk]

section Arith

variable {ty : UScalarTy}

theorem tryMk_ok (v : ℕ) (h : v < 2 ^ ty.numBits) :
    UScalar.tryMk ty v = ok (UScalar.ofNatCore v h) := by
  simp [UScalar.tryMk, UScalar.tryMkOpt, h, Result.ofOption]

theorem add_ok (x y : UScalar ty) (h : x.val + y.val < 2 ^ ty.numBits) :
    x + y = ok (UScalar.ofNatCore (x.val + y.val) h) :=
  tryMk_ok _ h

theorem sub_ok (x y : UScalar ty) (h : y.val ≤ x.val) :
    x - y = ok (UScalar.ofNatCore (x.val - y.val) (by have := x.hBounds; omega)) := by
  show UScalar.sub x y = _
  simp only [UScalar.sub, Nat.not_lt.mpr h, if_false]
  congr 1; apply UScalar.eq_of_val_eq
  simp only [UScalar.ofNatCore_val_eq]
  simp only [UScalar.val, BitVec.toNat_ofNat]
  have := x.hBounds
  exact Nat.mod_eq_of_lt (by simp only [UScalar.val] at *; omega)

theorem mul_ok (x y : UScalar ty) (h : x.val * y.val < 2 ^ ty.numBits) :
    x * y = ok (UScalar.ofNatCore (x.val * y.val) h) :=
  tryMk_ok _ h

theorem div_ok (x y : UScalar ty) (h : y.val ≠ 0) :
    x / y = ok (UScalar.ofNatCore (x.val / y.val)
      (lt_of_le_of_lt (Nat.div_le_self _ _) x.hBounds)) := by
  show UScalar.div x y = _
  have hy : y.bv ≠ 0 := by intro e; apply h; simp [UScalar.val, e]
  simp only [UScalar.div, bne_iff_ne, ne_eq, hy, not_false_eq_true, if_true]
  congr 1

theorem rem_ok (x y : UScalar ty) (h : y.val ≠ 0) :
    x % y = ok (UScalar.ofNatCore (x.val % y.val)
      (lt_of_le_of_lt (Nat.mod_le _ _) x.hBounds)) := by
  show UScalar.rem x y = _
  simp only [UScalar.rem, bne_iff_ne, ne_eq, h, not_false_eq_true, if_true]
  congr 1

theorem shiftRight_ok {tys : UScalarTy} (x : UScalar ty) (s : UScalar tys)
    (h : s.val < ty.numBits) :
    x >>> s = ok ⟨x.bv.ushiftRight s.val⟩ := by
  show UScalar.shiftRight_UScalar x s = _
  simp [UScalar.shiftRight_UScalar, UScalar.shiftRight, h]

theorem shiftLeft_ok {tys : UScalarTy} (x : UScalar ty) (s : UScalar tys)
    (h : s.val < ty.numBits) :
    x <<< s = ok ⟨x.bv.shiftLeft s.val⟩ := by
  show UScalar.shiftLeft_UScalar x s = _
  simp [UScalar.shiftLeft_UScalar, UScalar.shiftLeft, h]

end Arith

theorem shiftRight_64_i32 (x : U128) : x >>> 64#i32 = ok ⟨x.bv.ushiftRight 64⟩ := rfl

theorem toNat_shift_amount (s : ℕ) (hs : s < 64) : (s.toUInt64.toBitVec % 64).toNat = s := by
  rw [BitVec.toNat_umod]
  simp only [Nat.toUInt64]
  show s % 2 ^ 64 % (64 % 2 ^ 64) = s
  rw [Nat.mod_eq_of_lt (show s < 2 ^ 64 by omega)]
  exact Nat.mod_eq_of_lt hs

@[simp] theorem ofU64_ushiftRight (a : U64) (s : ℕ) (hs : s < 64) :
    ofU64 ⟨a.bv.ushiftRight s⟩ = ofU64 a >>> s.toUInt64 := by
  apply UInt64.toBitVec_inj.mp
  show a.bv.ushiftRight s = (UInt64.ofBitVec a.bv >>> s.toUInt64).toBitVec
  rw [UInt64.toBitVec_shiftRight, BitVec.ushiftRight_eq', UInt64.toBitVec_ofBitVec,
    toNat_shift_amount s hs]
  rfl

@[simp] theorem ofU64_shiftLeft (a : U64) (s : ℕ) (hs : s < 64) :
    ofU64 ⟨a.bv.shiftLeft s⟩ = ofU64 a <<< s.toUInt64 := by
  apply UInt64.toBitVec_inj.mp
  show a.bv.shiftLeft s = (UInt64.ofBitVec a.bv <<< s.toUInt64).toBitVec
  rw [UInt64.toBitVec_shiftLeft, BitVec.shiftLeft_eq', UInt64.toBitVec_ofBitVec,
    toNat_shift_amount s hs]
  rfl

theorem toU8_shiftLeft_one (s : Usize) (hs : s.val < 8) :
    (1#u8 <<< s : Result U8) = ok (toU8 (1 <<< s.val.toUInt8)) := by
  rw [shiftLeft_ok _ _ (by simp; omega)]
  congr 1
  show (⟨(1#u8).bv.shiftLeft s.val⟩ : U8) = ⟨(1 <<< s.val.toUInt8 : UInt8).toBitVec⟩
  congr 1
  rw [UInt8.toBitVec_shiftLeft, BitVec.shiftLeft_eq']
  congr 1
  rw [BitVec.toNat_umod]
  simp only [Nat.toUInt8]
  show s.val = s.val % 2 ^ 8 % (8 % 2 ^ 8)
  rw [Nat.mod_eq_of_lt (show s.val < 2 ^ 8 by omega), show (8 : ℕ) % 2 ^ 8 = 8 from rfl,
    Nat.mod_eq_of_lt hs]

theorem two_pow_32_le_usize : 2 ^ 32 ≤ 2 ^ UScalarTy.Usize.numBits := by
  rcases System.Platform.numBits_eq with h | h <;> simp [UScalarTy.numBits, h]

@[simp] theorem cast_Usize_val (x : U32) : (UScalar.cast .Usize x).val = x.val := by
  rw [UScalar.cast_val_eq]
  exact Nat.mod_eq_of_lt (lt_of_lt_of_le x.hBounds two_pow_32_le_usize)

theorem usize_add_ok (x y : Usize) (h : x.val + y.val < 2 ^ 32) :
    x + y = ok (UScalar.ofNatCore (x.val + y.val) (lt_of_lt_of_le h two_pow_32_le_usize)) :=
  add_ok x y _

theorem usize_mul_ok (x y : Usize) (h : x.val * y.val < 2 ^ 32) :
    x * y = ok (UScalar.ofNatCore (x.val * y.val) (lt_of_lt_of_le h two_pow_32_le_usize)) :=
  mul_ok x y _

@[simp] theorem usize_ofNat_val (k : ℕ) (hk : k < 2 ^ 32) :
    (⟨BitVec.ofNat System.Platform.numBits k⟩ : Usize).val = k := by
  simp only [UScalar.val]
  exact Nat.mod_eq_of_lt (lt_of_lt_of_le hk two_pow_32_le_usize)

@[simp] theorem u32_ofNat_val (k : ℕ) (hk : k < 2 ^ 32) :
    (⟨BitVec.ofNat 32 k⟩ : U32).val = k := by
  simp only [UScalar.val]
  exact Nat.mod_eq_of_lt hk

theorem usize_ofNat_add_ok (k : ℕ) (y : Usize) (h : k + y.val < 2 ^ 32) :
    (⟨BitVec.ofNat System.Platform.numBits k⟩ : Usize) + y =
      ok (UScalar.ofNatCore (k + y.val) (lt_of_lt_of_le h two_pow_32_le_usize)) := by
  rw [usize_add_ok _ _ (by rw [usize_ofNat_val k (by omega)]; exact h)]
  congr 2
  rw [usize_ofNat_val k (by omega)]

theorem update_ofNat {α : Type} {n : Usize} (a : Array α n) (k : ℕ) (x : α) (hk : k < n.val)
    (hk32 : k < 2 ^ 32) :
    a.update ⟨BitVec.ofNat System.Platform.numBits k⟩ x =
      ok (a.set ⟨BitVec.ofNat System.Platform.numBits k⟩ x) :=
  update_eq a _ x (by rw [usize_ofNat_val k hk32]; exact hk)

theorem usize_lt_8 (x : Usize) (h : x.val < 8) :
    x = 0#usize ∨ x = 1#usize ∨ x = 2#usize ∨ x = 3#usize ∨ x = 4#usize ∨ x = 5#usize ∨
      x = 6#usize ∨ x = 7#usize := by
  have : x.val = 0 ∨ x.val = 1 ∨ x.val = 2 ∨ x.val = 3 ∨ x.val = 4 ∨ x.val = 5 ∨ x.val = 6 ∨
      x.val = 7 := by omega
  have e : ∀ k : ℕ, (hk : k ≤ UScalar.cMax .Usize) → x.val = k → x = UScalar.ofNat k hk :=
    fun k hk hx => UScalar.eq_of_val_eq (by simp [hx])
  rcases this with h | h | h | h | h | h | h | h
  · exact Or.inl (e 0 (by decide) h)
  · exact Or.inr (Or.inl (e 1 (by decide) h))
  · exact Or.inr (Or.inr (Or.inl (e 2 (by decide) h)))
  · exact Or.inr (Or.inr (Or.inr (Or.inl (e 3 (by decide) h))))
  · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl (e 4 (by decide) h)))))
  · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl (e 5 (by decide) h))))))
  · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl (e 6 (by decide) h)))))))
  · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (e 7 (by decide) h)))))))

theorem slice_index_ok {α : Type} (s : Slice α) (a b : Usize) (hab : a.val ≤ b.val)
    (hb : b.val ≤ s.val.length) :
    core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice α) s
        { start := a, «end» := b } =
      ok ⟨s.val.slice a.val b.val, le_trans (List.slice_length_le _ _ _) s.property⟩ := by
  simp [core.slice.index.Slice.index, core.slice.index.SliceIndexRangeUsizeSlice.index, hab, hb]

theorem copy_from_slice_ok {α : Type} (inst : core.marker.Copy α) (s src : Slice α)
    (h : s.val.length = src.val.length) : core.slice.Slice.copy_from_slice inst s src = ok src := by
  simp [core.slice.Slice.copy_from_slice, h]

theorem split_at_ok {α : Type} (s : Slice α) (n : Usize) (h : n.val ≤ s.val.length) :
    core.slice.Slice.split_at s n =
      ok (⟨s.val.take n.val, by have := s.property; simp; omega⟩,
        ⟨s.val.drop n.val, by have := s.property; simp; omega⟩) := by
  simp [core.slice.Slice.split_at, h]

@[simp] theorem bind_ok_eq {α : Type} (x : Result α) : (do let v ← x; ok v) = x := by
  cases x <;> rfl

end LeanBlsSimd
