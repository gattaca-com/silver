import LeanBlsSimd.LaneTower.Packing

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.LaneTower

noncomputable def productBody (n : Usize) (left right q : Array fp8.Fp8 n) (i : Usize) :
    Result (ControlFlow (Array fp8.Fp8 n × Usize) (Array fp8.Fp8 n)) := do
  if i < n then
    let x ← Array.index_usize left i
    let y ← Array.index_usize right i
    let z ← fp8.Fp8.mul x y
    let q1 ← Array.update q i z
    let i1 ← i + 1#usize
    ok (cont (q1, i1))
  else ok (done q)

noncomputable def productLoop (n : Usize) (left right q : Array fp8.Fp8 n) (i : Usize) :
    Result (Array fp8.Fp8 n) :=
  loop (fun (q, i) => productBody n left right q i) (q, i)

theorem product_loop {n : Usize} {k k' : ℕ} {left right : Array fp8.Fp8 n}
    {a b : Fin n.val → V F} (hx : RowsNormal k left a) (hy : RowsNormal k' right b)
    (hk : k * k' ≤ 80 * 256 ^ 2)
    (q : Array fp8.Fp8 n) (i : Usize) (hi : i.val ≤ n.val)
    (hq : ∀ j : Fin n.val, j.val < i.val →
      Normal (fun _ => 2) (ofArray id q)[j.val] (fun l => a j l * b j l)) :
    ∃ out, productLoop n left right q i = ok out ∧
      RowsNormal 2 out (fun j l => a j l * b j l) := by
  unfold productLoop
  induction hh : n.val - i.val generalizing q i with
  | zero =>
    have hi' : i.val = n.val := by omega
    have hb : productBody n left right q i = ok (done q) := by
      simp only [productBody, UScalar.lt_equiv, hi', Nat.lt_irrefl, ↓reduceIte]
    refine ⟨q, ?_, fun j => hq j (by omega)⟩
    rw [loop.eq_1]
    simp only [hb]
  | succ t ih =>
    have hlt : i.val < n.val := by omega
    let j : Fin n.val := ⟨i.val, hlt⟩
    obtain ⟨z, hz, rz⟩ := raw_mul (hx j) (hy j) (fun _ => hk)
    let q' := q.set i z
    let i' : Usize := UScalar.ofNatCore (i.val + 1) (by scalar_tac)
    have hi' : i'.val = i.val + 1 := rfl
    have hget (v : Fin n.val) : (ofArray id q')[v.val] =
        if v.val = i.val then z else (ofArray id q)[v.val] := by
      simp [q', getElem_ofArray, Array.set_val_eq, List.getElem_set, eq_comm]
    have hq' (v : Fin n.val) (hv : v.val < i'.val) :
        Normal (fun _ => 2) (ofArray id q')[v.val] (fun l => a v l * b v l) := by
      rw [hget]
      split_ifs with h
      · have he : v = j := Fin.ext h
        simpa only [he] using rz
      · exact hq v (by omega)
    have hb : productBody n left right q i = ok (cont (q', i')) := by
      simp only [getElem_ofArray, id_eq, j] at hz
      simp only [productBody, UScalar.lt_equiv, hlt, ↓reduceIte,
        index_usize_eq left i hlt, index_usize_eq right i hlt, hz, bind_tc_ok,
        update_eq q i z hlt]
      rw [add_ok _ _ (by scalar_tac)]
      rfl
    obtain ⟨out, hout, rout⟩ := ih q' i' (by omega) hq' (by omega)
    refine ⟨out, ?_, rout⟩
    rw [loop.eq_1]
    simpa only [hb] using hout

theorem mul_loop_eq (left right q : Array fp8.Fp8 7#usize) (i : Usize) :
    fp12.Fp12.mul_loop left right q i = productLoop 7#usize left right q i := by
  unfold fp12.Fp12.mul_loop productLoop fp12.Fp12.mul_loop.body productBody
  with_reducible rfl

theorem square_loop_eq (left right q : Array fp8.Fp8 5#usize) (i : Usize) :
    fp12.Fp12.square_loop left right q i = productLoop 5#usize left right q i := by
  unfold fp12.Fp12.square_loop productLoop fp12.Fp12.square_loop.body productBody
  with_reducible rfl

theorem line_loop_eq (left right q : Array fp8.Fp8 5#usize) (i : Usize) :
    fp12.Fp12.mul_by_line_loop left right q i = productLoop 5#usize left right q i := by
  unfold fp12.Fp12.mul_by_line_loop productLoop fp12.Fp12.mul_by_line_loop.body productBody
  with_reducible rfl

theorem product_loop_start {n : Usize} {k k' : ℕ} {left right : Array fp8.Fp8 n}
    {a b : Fin n.val → V F} (hx : RowsNormal k left a) (hy : RowsNormal k' right b)
    (hk : k * k' ≤ 80 * 256 ^ 2) (q : Array fp8.Fp8 n) :
    ∃ out, productLoop n left right q 0#usize = ok out ∧
      RowsNormal 2 out (fun j l => a j l * b j l) :=
  product_loop hx hy hk q 0#usize (by scalar_tac) (by intro j hj; scalar_tac)

end LeanBlsSimd.LaneTower
