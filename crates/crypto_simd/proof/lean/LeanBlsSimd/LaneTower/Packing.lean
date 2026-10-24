import LeanBlsSimd.LaneTower.Pairs

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.LaneTower

/-- Fill the two spare lanes with a pair from a second six-lane block. -/
def packPair {α : Type} (i : Fin 3) (a b : V α) : V α :=
  ![a 0, a 1, a 2, a 3, a 4, a 5,
    b ⟨2 * i.val, by omega⟩, b ⟨2 * i.val + 1, by omega⟩]

def packIndex (i : Fin 3) : Array I64 8#usize :=
  ![Array.make (α := I64) 8#usize [0#i64, 1#i64, 2#i64, 3#i64, 4#i64, 5#i64, 8#i64, 9#i64] (by rfl),
    Array.make (α := I64) 8#usize [0#i64, 1#i64, 2#i64, 3#i64, 4#i64, 5#i64, 10#i64, 11#i64] (by rfl),
    Array.make (α := I64) 8#usize [0#i64, 1#i64, 2#i64, 3#i64, 4#i64, 5#i64, 12#i64, 13#i64] (by rfl)] i

theorem shuffle_pack {α : Type} (i : Fin 3) (a b : V α) :
    shuffle (packIndex i) a b = packPair i a b := by
  funext l
  fin_cases i <;> fin_cases l <;> rfl

theorem packPair_const {α : Type} (i : Fin 3) (a : α) :
    packPair i (fun _ => a) (fun _ => a) = (fun _ => a) := by
  funext l
  fin_cases l <;> rfl

def pack9 {α : Type} (a : Fin 9 → V α) : Fin 7 → V α :=
  ![packPair 0 (a 0) (a 7), packPair 1 (a 1) (a 7), packPair 2 (a 2) (a 7),
    packPair 0 (a 3) (a 8), packPair 1 (a 4) (a 8), packPair 2 (a 5) (a 8), a 6]

def pack6 {α : Type} (a : Fin 6 → V α) : Fin 5 → V α :=
  ![packPair 0 (a 0) (a 5), packPair 1 (a 1) (a 5), packPair 2 (a 2) (a 5), a 3, a 4]

def RowsRaw {n : Usize} {N : ℕ} (k m : ℕ) (xs : Array fp8.Fp8 n)
    (a : Fin N → V F) (hn : n.val = N := by rfl) : Prop :=
  ∀ j, Raw (fun _ => k) m (ofArray id xs hn)[j.val] (a j)

def RowsNormal {n : Usize} {N : ℕ} (k : ℕ) (xs : Array fp8.Fp8 n)
    (a : Fin N → V F) (hn : n.val = N := by rfl) : Prop :=
  ∀ j, Normal (fun _ => k) (ofArray id xs hn)[j.val] (a j)

private theorem pack_pair {k m : ℕ} {x y : fp8.Fp8} {a b : V F}
    (i : Fin 3) (hx : Raw (fun _ => k) m x a) (hy : Raw (fun _ => k) m y b)
    (hk : k ≤ 5120) (hm : m ≤ 1024) :
    ∃ p out, fp8.Fp8.permute2 x y (packIndex i) = ok p ∧
      fp8.Fp8.normalise p = ok out ∧ Normal (fun _ => k) out (packPair i a b) := by
  obtain ⟨p, hp, rp⟩ := raw_permute2 (packIndex i) hx hy
  have hr : Raw (fun _ => k) m p (packPair i a b) := by
    simpa only [shuffle_pack, packPair_const, max_self] using rp
  obtain ⟨out, hout, rout⟩ := raw_normalise hr (fun _ => hk) hm
  exact ⟨p, out, hp, hout, rout⟩

theorem pack_nine {k m : ℕ} {xs : Array fp8.Fp8 9#usize} {a : Fin 9 → V F}
    (hx : RowsRaw k m xs a) (hk : k ≤ 5120) (hm : m ≤ 1024) :
    ∃ out, fp12.pack_nine xs = ok out ∧ RowsNormal k out (pack9 a) := by
  obtain ⟨p0, o0, hp0, ho0, ro0⟩ := pack_pair 0 (hx ⟨0, by decide⟩) (hx ⟨7, by decide⟩) hk hm
  obtain ⟨p1, o1, hp1, ho1, ro1⟩ := pack_pair 1 (hx ⟨1, by decide⟩) (hx ⟨7, by decide⟩) hk hm
  obtain ⟨p2, o2, hp2, ho2, ro2⟩ := pack_pair 2 (hx ⟨2, by decide⟩) (hx ⟨7, by decide⟩) hk hm
  obtain ⟨p3, o3, hp3, ho3, ro3⟩ := pack_pair 0 (hx ⟨3, by decide⟩) (hx ⟨8, by decide⟩) hk hm
  obtain ⟨p4, o4, hp4, ho4, ro4⟩ := pack_pair 1 (hx ⟨4, by decide⟩) (hx ⟨8, by decide⟩) hk hm
  obtain ⟨p5, o5, hp5, ho5, ro5⟩ := pack_pair 2 (hx ⟨5, by decide⟩) (hx ⟨8, by decide⟩) hk hm
  obtain ⟨o6, ho6, ro6⟩ := raw_normalise (hx ⟨6, by decide⟩) (fun _ => hk) hm
  refine ⟨Array.make 7#usize [o0, o1, o2, o3, o4, o5, o6] (by rfl), ?_, ?_⟩
  · simp only [getElem_ofArray, id_eq] at hp0 hp1 hp2 hp3 hp4 hp5 ho6
    simp only [packIndex, Matrix.cons_val_zero, Matrix.cons_val_one, Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons] at hp0 hp1 hp2 hp3 hp4 hp5
    simp only [fp12.pack_nine, UScalar.ofNatCore_val_eq,
      index_usize_eq xs 0#usize (by decide),
      index_usize_eq xs 1#usize (by decide),
      index_usize_eq xs 2#usize (by decide),
      index_usize_eq xs 3#usize (by decide),
      index_usize_eq xs 4#usize (by decide),
      index_usize_eq xs 5#usize (by decide),
      index_usize_eq xs 6#usize (by decide),
      index_usize_eq xs 7#usize (by decide),
      index_usize_eq xs 8#usize (by decide),
      bind_tc_ok]
    simp only [hp0, bind_tc_ok, ho0, hp1, ho1, hp2, ho2, hp3, ho3, hp4, ho4, hp5, ho5, ho6]
  · intro j
    fin_cases j
    · exact ro0
    · exact ro1
    · exact ro2
    · exact ro3
    · exact ro4
    · exact ro5
    · exact ro6

theorem pack_six {k m : ℕ} {xs : Array fp8.Fp8 6#usize} {a : Fin 6 → V F}
    (hx : RowsRaw k m xs a) (hk : k ≤ 5120) (hm : m ≤ 1024) :
    ∃ out, fp12.pack_six xs = ok out ∧ RowsNormal k out (pack6 a) := by
  obtain ⟨p0, o0, hp0, ho0, ro0⟩ := pack_pair 0 (hx ⟨0, by decide⟩) (hx ⟨5, by decide⟩) hk hm
  obtain ⟨p1, o1, hp1, ho1, ro1⟩ := pack_pair 1 (hx ⟨1, by decide⟩) (hx ⟨5, by decide⟩) hk hm
  obtain ⟨p2, o2, hp2, ho2, ro2⟩ := pack_pair 2 (hx ⟨2, by decide⟩) (hx ⟨5, by decide⟩) hk hm
  obtain ⟨o3, ho3, ro3⟩ := raw_normalise (hx ⟨3, by decide⟩) (fun _ => hk) hm
  obtain ⟨o4, ho4, ro4⟩ := raw_normalise (hx ⟨4, by decide⟩) (fun _ => hk) hm
  refine ⟨Array.make 5#usize [o0, o1, o2, o3, o4] (by rfl), ?_, ?_⟩
  · simp only [getElem_ofArray, id_eq] at hp0 hp1 hp2 ho3 ho4
    simp only [packIndex, Matrix.cons_val_zero, Matrix.cons_val_one, Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons] at hp0 hp1 hp2
    simp only [fp12.pack_six, UScalar.ofNatCore_val_eq,
      index_usize_eq xs 0#usize (by decide),
      index_usize_eq xs 1#usize (by decide),
      index_usize_eq xs 2#usize (by decide),
      index_usize_eq xs 3#usize (by decide),
      index_usize_eq xs 4#usize (by decide),
      index_usize_eq xs 5#usize (by decide),
      bind_tc_ok]
    simp only [hp0, bind_tc_ok, ho0, hp1, ho1, hp2, ho2, ho3, ho4]
  · intro j
    fin_cases j
    · exact ro0
    · exact ro1
    · exact ro2
    · exact ro3
    · exact ro4

def lowIndex : Array I64 8#usize :=
  Array.make (α := I64) 8#usize [6#i64, 7#i64, 14#i64, 15#i64, 6#i64, 7#i64, 14#i64, 15#i64] (by rfl)

def tailIndex : Array I64 8#usize :=
  Array.make (α := I64) 8#usize [0#i64, 1#i64, 2#i64, 3#i64, 14#i64, 15#i64, 14#i64, 15#i64] (by rfl)

def unpackTail {α : Type} (a b c : V α) : V α :=
  ![a 6, a 7, b 6, b 7, c 6, c 7, c 6, c 7]

def unpack9 {α : Type} (a : Fin 7 → V α) : Fin 9 → V α :=
  ![a 0, a 1, a 2, a 3, a 4, a 5, a 6,
    unpackTail (a 0) (a 1) (a 2), unpackTail (a 3) (a 4) (a 5)]

def unpack6 {α : Type} (a : Fin 5 → V α) : Fin 6 → V α :=
  ![a 0, a 1, a 2, a 3, a 4, unpackTail (a 0) (a 1) (a 2)]

theorem shuffle_unpack {α : Type} (a b c : V α) :
    shuffle tailIndex (shuffle lowIndex a b) c = unpackTail a b c := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_const {α : Type} (is : Array I64 8#usize) (a : α) :
    shuffle is (fun _ => a) (fun _ => a) = (fun _ => a) := by
  funext l
  unfold shuffle
  split_ifs <;> rfl

private theorem unpack_tail {k : ℕ} {x y z : fp8.Fp8} {a b c : V F}
    (hx : Normal (fun _ => k) x a) (hy : Normal (fun _ => k) y b)
    (hz : Normal (fun _ => k) z c) :
    ∃ p out, fp8.Fp8.permute2 x y lowIndex = ok p ∧
      fp8.Fp8.permute2 p z tailIndex = ok out ∧
      Normal (fun _ => k) out (unpackTail a b c) := by
  obtain ⟨p, hp, rp⟩ := normal_permute2 lowIndex hx hy
  have hr : Normal (fun _ => k) p (shuffle lowIndex a b) := by
    simpa only [shuffle_const] using rp
  obtain ⟨out, hout, rout⟩ := normal_permute2 tailIndex hr hz
  refine ⟨p, out, hp, hout, ?_⟩
  rw [shuffle_unpack] at rout
  simpa only [shuffle_const] using rout

theorem unpack_nine {k : ℕ} {xs : Array fp8.Fp8 7#usize} {a : Fin 7 → V F}
    (hx : RowsNormal k xs a) :
    ∃ out, fp12.unpack_nine xs = ok out ∧ RowsNormal k out (unpack9 a) := by
  obtain ⟨p7, o7, hp7, ho7, ro7⟩ := unpack_tail (hx ⟨0, by decide⟩) (hx ⟨1, by decide⟩) (hx ⟨2, by decide⟩)
  obtain ⟨p8, o8, hp8, ho8, ro8⟩ := unpack_tail (hx ⟨3, by decide⟩) (hx ⟨4, by decide⟩) (hx ⟨5, by decide⟩)
  refine ⟨Array.make 9#usize [(ofArray id xs)[0], (ofArray id xs)[1], (ofArray id xs)[2], (ofArray id xs)[3], (ofArray id xs)[4], (ofArray id xs)[5], (ofArray id xs)[6], o7, o8] (by rfl), ?_, ?_⟩
  · simp only [getElem_ofArray, id_eq] at hp7 hp8 ho7 ho8
    simp only [lowIndex, tailIndex] at hp7 hp8 ho7 ho8
    simp only [fp12.unpack_nine, UScalar.ofNatCore_val_eq,
      index_usize_eq xs 0#usize (by decide),
      index_usize_eq xs 1#usize (by decide),
      index_usize_eq xs 2#usize (by decide),
      index_usize_eq xs 3#usize (by decide),
      index_usize_eq xs 4#usize (by decide),
      index_usize_eq xs 5#usize (by decide),
      index_usize_eq xs 6#usize (by decide),
      bind_tc_ok]
    simp only [hp7, bind_tc_ok, hp8, ho7, ho8]
    simp only [getElem_ofArray, id_eq]
  · intro j
    fin_cases j
    · exact hx ⟨0, by decide⟩
    · exact hx ⟨1, by decide⟩
    · exact hx ⟨2, by decide⟩
    · exact hx ⟨3, by decide⟩
    · exact hx ⟨4, by decide⟩
    · exact hx ⟨5, by decide⟩
    · exact hx ⟨6, by decide⟩
    · exact ro7
    · exact ro8

theorem unpack_six {k : ℕ} {xs : Array fp8.Fp8 5#usize} {a : Fin 5 → V F}
    (hx : RowsNormal k xs a) :
    ∃ out, fp12.unpack_six xs = ok out ∧ RowsNormal k out (unpack6 a) := by
  obtain ⟨p5, o5, hp5, ho5, ro5⟩ := unpack_tail (hx ⟨0, by decide⟩) (hx ⟨1, by decide⟩) (hx ⟨2, by decide⟩)
  refine ⟨Array.make 6#usize [(ofArray id xs)[0], (ofArray id xs)[1], (ofArray id xs)[2], (ofArray id xs)[3], (ofArray id xs)[4], o5] (by rfl), ?_, ?_⟩
  · simp only [getElem_ofArray, id_eq] at hp5 ho5
    simp only [lowIndex, tailIndex] at hp5 ho5
    simp only [fp12.unpack_six, UScalar.ofNatCore_val_eq,
      index_usize_eq xs 0#usize (by decide),
      index_usize_eq xs 1#usize (by decide),
      index_usize_eq xs 2#usize (by decide),
      index_usize_eq xs 3#usize (by decide),
      index_usize_eq xs 4#usize (by decide),
      bind_tc_ok]
    simp only [hp5, bind_tc_ok, ho5]
    simp only [getElem_ofArray, id_eq]
  · intro j
    fin_cases j
    · exact hx ⟨0, by decide⟩
    · exact hx ⟨1, by decide⟩
    · exact hx ⟨2, by decide⟩
    · exact hx ⟨3, by decide⟩
    · exact hx ⟨4, by decide⟩
    · exact ro5

/-- Packing ignores the two unused input lanes; unpacking restores every active lane. -/
theorem unpack9_pack9 {α : Type} (a : Fin 9 → V α) (j : Fin 9) (l : Fin 8) (hl : l.val < 6) :
    unpack9 (pack9 a) j l = a j l := by
  fin_cases j <;> fin_cases l <;> first | rfl | norm_num at hl

theorem unpack6_pack6 {α : Type} (a : Fin 6 → V α) (j : Fin 6) (l : Fin 8) (hl : l.val < 6) :
    unpack6 (pack6 a) j l = a j l := by
  fin_cases j <;> fin_cases l <;> first | rfl | norm_num at hl

theorem unpack9_products (a b : Fin 9 → V F) (j : Fin 9) (l : Fin 8) (hl : l.val < 6) :
    unpack9 (fun j l => pack9 a j l * pack9 b j l) j l = a j l * b j l := by
  fin_cases j <;> fin_cases l <;> first | rfl | norm_num at hl

theorem unpack6_products (a b : Fin 6 → V F) (j : Fin 6) (l : Fin 8) (hl : l.val < 6) :
    unpack6 (fun j l => pack6 a j l * pack6 b j l) j l = a j l * b j l := by
  fin_cases j <;> fin_cases l <;> first | rfl | norm_num at hl

end LeanBlsSimd.LaneTower
