import LeanBlsSimd.Kzg.Extender.Kernel.FftPairIndex
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8AddSub
import LeanBlsSimd.Refines.Fr8

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

structure WideStage where
  dit : Bool
  table : fft8.Fft8
  input : Slice fr8.Fr8
  half : Usize
  offset : fr8.Fr8

namespace WideStage

def x (s : WideStage) (n : Nat) : fr8.Fr8 :=
  s.input.val[pairFirst s.half.val n]!

def y (s : WideStage) (n : Nat) : fr8.Fr8 :=
  s.input.val[pairFirst s.half.val n + s.half.val]!

def factor (s : WideStage) (n : Nat) : fr8.Fr8 :=
  s.table.wide.val[s.half.val - 1 + n % s.half.val]!

def normal (s : WideStage) (n : Nat) : fr8.Fr8 :=
  FrModel.toFr8 (if s.dit then (FrModel.ofFr8 (s.y n)).normalise
    else ((FrModel.ofFr8 (s.x n)).subRaw
      (FrModel.ofFr8 (s.y n)) (FrModel.ofFr8 s.offset)).normalise)

def pending (s : WideStage) (n : Nat) : Array M512 11#usize :=
  FrModel.Fr8.productValue (s.normal n) (s.factor n)

def product (s : WideStage) (n : Nat) : fr8.Fr8 :=
  FrModel.Fr8.reduceValue (s.pending n)

def left (s : WideStage) (n : Nat) : fr8.Fr8 :=
  if s.dit then FrModel.toFr8 ((FrModel.ofFr8 (s.x n)).addRaw (FrModel.ofFr8 (s.product n)))
  else FrModel.toFr8 (((FrModel.ofFr8 (s.x n)).addRaw (FrModel.ofFr8 (s.y n))).normalise.reduced)

def right (s : WideStage) (n : Nat) : fr8.Fr8 :=
  if s.dit then FrModel.toFr8 ((FrModel.ofFr8 (s.x n)).subRaw
    (FrModel.ofFr8 (s.product n)) (FrModel.ofFr8 s.offset))
  else s.product n

def state (s : WideStage) (count : Nat) (prepared : Bool) : Slice fr8.Fr8 :=
  ⟨s.input.val.mapIdx (fun v original =>
    let n := pairNumber s.half.val v
    if n < count then
      if v % (2*s.half.val) < s.half.val then s.left n else s.right n
    else if prepared ∧ n = count ∧ v % (2*s.half.val) < s.half.val then s.left n
    else original), by simpa using s.input.property⟩

@[simp] theorem state_length (s : WideStage) (count : Nat) (prepared : Bool) :
    (s.state count prepared).val.length = s.input.val.length := by simp [state]

theorem state_get (s : WideStage) (count : Nat) (prepared : Bool) (v : Nat)
    (hv : v < s.input.val.length) :
    (s.state count prepared).val[v]! =
      (let n := pairNumber s.half.val v
       if n < count then
         if v % (2*s.half.val) < s.half.val then s.left n else s.right n
       else if prepared ∧ n = count ∧ v % (2*s.half.val) < s.half.val then s.left n
       else s.input.val[v]!) := by
  simp [state, hv]

@[simp] theorem state_zero (s : WideStage) : s.state 0 false = s.input := by
  apply Subtype.ext
  apply List.ext_getElem (by simp)
  intro i hi hi'
  simp [state]

theorem slice_update (data : Slice fr8.Fr8) (i : Usize) (value : fr8.Fr8)
    (hi : i.val < data.val.length) : Slice.update data i value = ok (data.set i value) := by
  simp [Slice.update, Slice.set, Slice.setAtNat, List.getElem?_eq_getElem hi]

theorem slice_read (data : Slice fr8.Fr8) (i : Usize)
    (hi : i.val < data.val.length) : Slice.index_usize data i = ok data.val[i.val]! := by
  simp [Slice.index_usize, List.getElem?_eq_getElem hi]

theorem set_comm (data : Slice fr8.Fr8) (i j : Usize) (a b : fr8.Fr8) (hne : i ≠ j) :
    (data.set i a).set j b = (data.set j b).set i a := by
  apply Subtype.ext
  simp only [Slice.set, Slice.setAtNat]
  exact List.set_comm a b (fun h => hne (UScalar.eq_of_val_eq h))

theorem state_first (s : WideStage) (count n : Nat) (prepared : Bool)
    (hhalf : 0 < s.half.val) (hn : count ≤ n)
    (hprepared : prepared = false ∨ count < n)
    (hbound : pairFirst s.half.val n < s.input.val.length) :
    (s.state count prepared).val[pairFirst s.half.val n]! = s.x n := by
  rw [state_get _ _ _ _ hbound]
  simp only [pairNumber_first _ _ hhalf, pairFirst_lower _ _ hhalf, x]
  rcases hprepared with rfl | hn'
  · simp [Nat.not_lt.mpr hn]
  · simp [Nat.not_lt.mpr hn, show n ≠ count by omega]

theorem state_second (s : WideStage) (count n : Nat) (prepared : Bool)
    (hhalf : 0 < s.half.val) (hn : count ≤ n)
    (hbound : pairFirst s.half.val n + s.half.val < s.input.val.length) :
    (s.state count prepared).val[pairFirst s.half.val n + s.half.val]! = s.y n := by
  rw [state_get _ _ _ _ hbound]
  simp [pairNumber_second _ _ hhalf, Nat.not_lt.mpr hn,
    Nat.not_lt.mpr (pairSecond_upper _ _ hhalf), y]

private theorem first_iff (half n v : Nat) (hhalf : 0 < half) :
    (pairNumber half v = n ∧ v % (2 * half) < half) ↔ v = pairFirst half n := by
  constructor
  · rintro ⟨hn, hlo⟩
    simpa [hn] using pair_partition_lower half v hhalf hlo
  · rintro rfl
    exact ⟨pairNumber_first _ _ hhalf, pairFirst_lower _ _ hhalf⟩

private theorem second_iff (half n v : Nat) (hhalf : 0 < half) :
    (pairNumber half v = n ∧ ¬v % (2 * half) < half) ↔
      v = pairFirst half n + half := by
  constructor
  · rintro ⟨hn, hhi⟩
    simpa [hn] using pair_partition_upper half v hhalf (by omega)
  · rintro rfl
    exact ⟨pairNumber_second _ _ hhalf, Nat.not_lt.mpr (pairSecond_upper _ _ hhalf)⟩

theorem state_prepare (s : WideStage) (n : Nat) (i : Usize)
    (hhalf : 0 < s.half.val) (hi : i.val = pairFirst s.half.val n) :
    (s.state n false).set i (s.left n) = s.state n true := by
  apply Subtype.ext
  apply List.ext_getElem (by simp [Slice.set, Slice.setAtNat])
  intro v hv hv'
  simp only [Slice.set, Slice.setAtNat, state, List.getElem_set, List.getElem_mapIdx]
  have he := first_iff s.half.val n v hhalf
  by_cases hnum : pairNumber s.half.val v = n
  · by_cases hlo : v % (2 * s.half.val) < s.half.val
    · have hv : v = i.val := by rw [hi]; exact he.mp ⟨hnum, hlo⟩
      simp [← hv, hnum, hlo]
    · have hv : v ≠ i.val := by intro h; apply hlo; exact (he.mpr (h.trans hi)).2
      simp [hnum, hlo, Ne.symm hv]
  · have hv : v ≠ i.val := by intro h; apply hnum; exact (he.mpr (h.trans hi)).1
    simp [hnum, Ne.symm hv]

theorem state_finish_prepared (s : WideStage) (n : Nat) (i : Usize)
    (hhalf : 0 < s.half.val) (hi : i.val = pairFirst s.half.val n + s.half.val) :
    (s.state n true).set i (s.right n) = s.state (n + 1) false := by
  apply Subtype.ext
  apply List.ext_getElem (by simp [Slice.set, Slice.setAtNat])
  intro v hv hv'
  simp only [Slice.set, Slice.setAtNat, state, List.getElem_set, List.getElem_mapIdx]
  have he := second_iff s.half.val n v hhalf
  by_cases hnum : pairNumber s.half.val v = n
  · by_cases hlo : v % (2 * s.half.val) < s.half.val
    · have hv : v ≠ i.val := by intro h; exact (he.mpr (h.trans hi)).2 hlo
      simp [hnum, hlo, Ne.symm hv]
    · have hv : v = i.val := by rw [hi]; exact he.mp ⟨hnum, hlo⟩
      simp [← hv, hnum, hlo]
  · have hv : v ≠ i.val := by intro h; apply hnum; exact (he.mpr (h.trans hi)).1
    have hlt : pairNumber s.half.val v < n + 1 ↔ pairNumber s.half.val v < n := by omega
    simp [hnum, Ne.symm hv, hlt]

theorem state_complete (s : WideStage) (n : Nat) (i j : Usize)
    (hhalf : 0 < s.half.val) (hi : i.val = pairFirst s.half.val n)
    (hj : j.val = pairFirst s.half.val n + s.half.val) :
    ((s.state n false).set i (s.left n)).set j (s.right n) = s.state (n + 1) false := by
  rw [state_prepare s n i hhalf hi, state_finish_prepared s n j hhalf hj]

end WideStage
end LeanBlsSimd.Kzg.Extender.Kernel
