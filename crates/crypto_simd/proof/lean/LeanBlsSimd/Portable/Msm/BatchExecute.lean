import LeanBlsSimd.Portable.Msm.BatchUnwind
import LeanBlsSimd.Portable.Msm.BatchPrepareLoop

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Msm.Batch
open QueueRefines

def signedPair (coords : ℕ → ChainField × ChainField) (r : U32) : ChainField × ChainField :=
  let p := coords (r.val % 2^31)
  (p.1,if 2^31 ≤ r.val then -p.2 else p.2)

def differences (jobs : ℕ → Job) (coords : ℕ → ChainField × ChainField) (i : ℕ) : ChainField :=
  (signedPair coords (jobs i).second).1 - (signedPair coords (jobs i).first).1

def jobResult (jobs : ℕ → Job) (coords : ℕ → ChainField × ChainField) (i : ℕ) :
    ChainField × ChainField :=
  let a := signedPair coords (jobs i).first
  let b := signedPair coords (jobs i).second
  finishValues a.1 a.2 b.1 b.2 (differences jobs coords i)⁻¹

def execute (jobs : ℕ → Job) (coords : ℕ → ChainField × ChainField) :
    ℕ → portable.msm.store.PointStore → portable.msm.store.PointStore
  | 0,store => store
  | n+1,store =>
    let p := jobResult jobs coords n
    execute jobs coords n (Store.write store (jobs n).output.val p.1 p.2)

def ExecutionState (store : portable.msm.store.PointStore) (jobs : ℕ → Job)
    (coords : ℕ → ChainField × ChainField) (remaining : ℕ) : Prop :=
  ∀ j < remaining,
    Store.Holds store ((jobs j).first.val % 2^31)
      (coords ((jobs j).first.val % 2^31)).1 (coords ((jobs j).first.val % 2^31)).2 ∧
    Store.Holds store ((jobs j).second.val % 2^31)
      (coords ((jobs j).second.val % 2^31)).1 (coords ((jobs j).second.val % 2^31)).2 ∧
    (jobs j).output.val < store.points.val.length

/-- An output may replace its own input, but cannot replace an earlier job's input. -/
def ReverseIndependent (jobs : ℕ → Job) (n : ℕ) : Prop :=
  ∀ j < n, ∀ k < j,
    (jobs j).output.val ≠ (jobs k).first.val % 2^31 ∧
    (jobs j).output.val ≠ (jobs k).second.val % 2^31

theorem ExecutionState.step (store : portable.msm.store.PointStore) (jobs : ℕ → Job)
    (coords : ℕ → ChainField × ChainField) (n : ℕ)
    (h : ExecutionState store jobs coords (n+1)) (hind : ReverseIndependent jobs (n+1)) :
    ExecutionState (Store.write store (jobs n).output.val
      (jobResult jobs coords n).1 (jobResult jobs coords n).2) jobs coords n := by
  intro k hk
  obtain ⟨ha,hb,ho⟩ := h k (by omega)
  obtain ⟨hna,hnb⟩ := hind n (by omega) k hk
  refine ⟨?_,?_,?_⟩
  · unfold Store.Holds at *
    rw [Store.write_other _ _ _ _ _ hna]
    exact ha
  · unfold Store.Holds at *
    rw [Store.write_other _ _ _ _ _ hnb]
    exact hb
  · simpa [Store.write] using ho

theorem execute_loop [RuntimeFeatures]
    (a b out : alloc.vec.Vec U32) (dx prefixes : alloc.vec.Vec portable.fp.Fp)
    (jobs : ℕ → Job) (coords : ℕ → ChainField × ChainField)
    (n : ℕ) (store : portable.msm.store.PointStore) (i : Usize)
    (hi : i.val = n)
    (ha : ∀ j < n, a.val[j]? = some (jobs j).first)
    (hb : ∀ j < n, b.val[j]? = some (jobs j).second)
    (ho : ∀ j < n, out.val[j]? = some (jobs j).output)
    (hstate : ExecutionState store jobs coords n) (hind : ReverseIndependent jobs n)
    (hprep : Prepared dx prefixes (differences jobs coords) n)
    (hnz : ∀ j < n, differences jobs coords j ≠ 0) :
    portable.msm.pairs.BatchedAdds.run_loop0_loop0 a b out dx prefixes store i
      (inverseArray (differences jobs coords) n) = ok (execute jobs coords n store) := by
  induction n generalizing store i with
  | zero =>
    have hz : ¬ i > 0#usize := by simpa only [UScalar.lt_equiv] using Nat.not_lt_of_ge (by change i.val ≤ 0; omega)
    rw [portable.msm.pairs.BatchedAdds.run_loop0_loop0,loop.eq_1]
    simp only [portable.msm.pairs.BatchedAdds.run_loop0_loop0.body,hz,if_false,execute]
  | succ n ih =>
    let j : Usize := UScalar.ofNatCore n (by have := i.hBounds; omega)
    have hj : j.val = n := rfl
    obtain ⟨hsa,hsb,hbound⟩ := hstate n (by omega)
    have hsigneda := Store.signed_refines store (jobs n).first _ _ hsa
    have hsignedb := Store.signed_refines store (jobs n).second _ _ hsb
    have hstep := unwind_step a b out dx prefixes store i j (differences jobs coords)
      (by omega) (by simpa only [hj] using hnz)
      (by simpa only [hj] using (hprep n (by omega)).1)
      (by intro hge; exact (hprep (j.val-4) (by omega)).2)
      (jobs n).first (jobs n).second (jobs n).output
      (signedPair coords (jobs n).first).1 (signedPair coords (jobs n).first).2
      (signedPair coords (jobs n).second).1 (signedPair coords (jobs n).second).2
      (by simpa only [hj] using ha n (by omega))
      (by simpa only [hj] using hb n (by omega))
      (by simpa only [hj] using ho n (by omega)) hsigneda hsignedb hbound
    have hnext := ih (Store.write store (jobs n).output.val
        (jobResult jobs coords n).1 (jobResult jobs coords n).2) j hj
      (fun k hk => ha k (by omega)) (fun k hk => hb k (by omega)) (fun k hk => ho k (by omega))
      (ExecutionState.step store jobs coords n hstate hind)
      (fun k hk l hl => hind k (by omega) l hl)
      (fun k hk => hprep k (by omega)) (fun k hk => hnz k (by omega))
    simp only [hj] at hstep
    rw [portable.msm.pairs.BatchedAdds.run_loop0_loop0,loop.eq_1]
    simp only [hstep]
    exact hnext

theorem execute_length (jobs : ℕ → Job) (coords : ℕ → ChainField × ChainField)
    (n : ℕ) (store : portable.msm.store.PointStore) :
    (execute jobs coords n store).points.val.length = store.points.val.length := by
  induction n generalizing store with
  | zero => rfl
  | succ n ih => simp only [execute,ih,Store.write,List.length_set]

theorem execute_len (jobs : ℕ → Job) (coords : ℕ → ChainField × ChainField)
    (n : ℕ) (store : portable.msm.store.PointStore) :
    (execute jobs coords n store).len = store.len := by
  induction n generalizing store with
  | zero => rfl
  | succ n ih => simp only [execute,ih,Store.write]

theorem execute_frame (jobs : ℕ → Job) (coords : ℕ → ChainField × ChainField)
    (n : ℕ) (store : portable.msm.store.PointStore) (p : ℕ)
    (hne : ∀ j < n, (jobs j).output.val ≠ p) :
    (execute jobs coords n store).points.val[p]? = store.points.val[p]? := by
  induction n generalizing store with
  | zero => rfl
  | succ n ih =>
    rw [execute,ih _ (fun j hj => hne j (by omega)),Store.write_other _ _ _ _ _ (hne n (by omega))]

theorem execute_output (jobs : ℕ → Job) (coords : ℕ → ChainField × ChainField)
    (n : ℕ) (store : portable.msm.store.PointStore) (j : ℕ) (hj : j < n)
    (hb : (jobs j).output.val < store.points.val.length)
    (hunique : ∀ k < n, k ≠ j → (jobs k).output.val ≠ (jobs j).output.val) :
    Store.Holds (execute jobs coords n store) (jobs j).output.val
      (jobResult jobs coords j).1 (jobResult jobs coords j).2 := by
  induction n generalizing store with
  | zero => omega
  | succ n ih =>
    by_cases he : j = n
    · subst j
      unfold Store.Holds
      rw [execute,execute_frame jobs coords n _ _ (fun k hk => hunique k (by omega) (by omega))]
      exact Store.write_holds store _ _ _ hb
    · rw [execute]
      exact ih _ (by omega) (by simpa [Store.write] using hb)
        (fun k hk hkj => hunique k (by omega) hkj)

end LeanBlsSimd.Portable.Msm.Batch
