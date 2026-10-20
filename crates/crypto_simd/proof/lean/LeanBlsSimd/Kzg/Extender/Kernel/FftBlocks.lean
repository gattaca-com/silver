import LeanBlsSimd.Kzg.Extender.Kernel.FftShort

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

open FftMath

def shortStages (dit : Bool) (values roots : _root_.Array Fr) : _root_.Array Fr :=
  if dit then
    butterflyStage true (butterflyStage true (butterflyStage true values roots 1) roots 2) roots 4
  else
    butterflyStage false (butterflyStage false (butterflyStage false values roots 4) roots 2) roots 1

@[simp] theorem size_shortStages (dit : Bool) (values roots : _root_.Array Fr) :
    (shortStages dit values roots).size = values.size := by
  cases dit <;> simp [shortStages]

private def BlockPrefix (data : Slice fr8.Fr8) (values output : _root_.Array Fr)
    (n count : Nat) : Prop :=
  data.val.length = n ∧ ∀ v : Fin n, Represents data.val[v.val]!
    (fun lane => if v.val < count then output[8*v.val+lane.val]! else values[8*v.val+lane.val]!)

private theorem prefix_set (data : Slice fr8.Fr8) (values output : _root_.Array Fr)
    (n : Nat) (i : Usize) (hi : i.val < n) (value : fr8.Fr8)
    (hvalue : Represents value (fun lane => output[8*i.val+lane.val]!))
    (hp : BlockPrefix data values output n i.val) :
    BlockPrefix (data.set i value) values output n (i.val+1) := by
  refine ⟨by simpa [Slice.set, Slice.setAtNat] using hp.1, ?_⟩
  intro j
  by_cases hj : j.val = i.val
  · have hib : i.val < data.val.length := by rw [hp.1]; exact hi
    simpa [Slice.set, Slice.setAtNat, hj, hib] using hvalue
  · have hiff : (j.val < i.val+1) = (j.val < i.val) := propext (by omega)
    simpa only [Slice.set, Slice.setAtNat,
      List.getElem!_set_ne data.val i.val j.val value (by omega), hiff] using hp.2 j

private theorem set_block_loop_prefix
    (block : Array fr8.Fr8 8#usize) (values output : _root_.Array Fr) (n : Nat)
    (offset : Usize) (hat : offset.val+8 ≤ n) (hn : n ≤ 512)
    (hb : ∀ row : Fin 8, Represents block.val[row.val]!
      (fun lane => output[8*(offset.val+row.val)+lane.val]!))
    (remaining : Nat) :
    ∀ (data : Slice fr8.Fr8) (k : Usize), k.val+remaining = 8 →
      BlockPrefix data values output n (offset.val+k.val) →
      ∃ out, fft8.set_block_loop data offset block k = ok out ∧
        BlockPrefix out values output n (offset.val+8) := by
  induction remaining with
  | zero =>
    intro data k hk hp
    have hk8 : k.val = 8 := by omega
    refine ⟨data, ?_, by simpa [hk8] using hp⟩
    rw [fft8.set_block_loop, loop.eq_1]
    simp [fft8.set_block_loop.body, fr8.LANES, UScalar.lt_equiv, hk8]
  | succ remaining ih =>
    intro data k hk hp
    have hk8 : k.val < 8 := by omega
    let i : Usize := UScalar.ofNatCore (offset.val+k.val) (by scalar_tac)
    let next : Usize := UScalar.ofNatCore (k.val+1) (by scalar_tac)
    have hi : i.val = offset.val+k.val := UScalar.ofNatCore_val_eq _
    have hnext : next.val = k.val+1 := UScalar.ofNatCore_val_eq _
    have hadd : offset+k = ok i := scalar_add_ok offset k (by scalar_tac)
    have hinc : k+1#usize = ok next := by
      simpa only [next] using scalar_add_ok k 1#usize (by scalar_tac)
    have hindex : Array.index_usize block k = ok block.val[k.val]! := by
      simp [Array.index_usize, hk8, block.property]
    have hiData : i.val < data.val.length := by rw [hp.1, hi]; omega
    have hupdate : Slice.update data i block.val[k.val]! = ok (data.set i block.val[k.val]!) := by
      simp [Slice.update, Slice.set, Slice.setAtNat, hiData]
    have hnew : BlockPrefix (data.set i block.val[k.val]!) values output n (offset.val+next.val) := by
      rw [hnext, show offset.val+(k.val+1) = i.val+1 by omega]
      apply prefix_set data values output n i (by omega) _
      · simpa only [hi] using hb ⟨k.val,hk8⟩
      · simpa only [hi] using hp
    obtain ⟨out, hout, ho⟩ := ih (data.set i block.val[k.val]!) next (by omega) hnew
    refine ⟨out, ?_, ho⟩
    have hbody : fft8.set_block_loop.body offset block data k =
        ok (cont (data.set i block.val[k.val]!, next)) := by
      simp only [fft8.set_block_loop.body, fr8.LANES, UScalar.lt_equiv,
        UScalar.ofNatCore_val_eq, hk8, if_true, hindex, hadd, hupdate, hinc, bind_tc_ok]
    rw [fft8.set_block_loop, loop.eq_1]
    simpa only [hbody] using hout

private theorem set_block_prefix
    (data : Slice fr8.Fr8) (block : Array fr8.Fr8 8#usize)
    (values output : _root_.Array Fr) (n : Nat) (offset : Usize)
    (hat : offset.val+8 ≤ n) (hn : n ≤ 512)
    (hb : ∀ row : Fin 8, Represents block.val[row.val]!
      (fun lane => output[8*(offset.val+row.val)+lane.val]!))
    (hp : BlockPrefix data values output n offset.val) :
    ∃ out, fft8.set_block data offset block = ok out ∧
      BlockPrefix out values output n (offset.val+8) := by
  exact set_block_loop_prefix block values output n offset hat hn hb 8 data 0#usize
    (by decide) (by simpa using hp)

def blockRun (dit : Bool) (table : fft8.Fft8) (data : Slice fr8.Fr8) (offset : Usize) :
    Result (Array fr8.Fr8 8#usize) := do
  let t ← fr8.Fr8.transpose data offset
  let t' ← if dit then do
      let t1 ← fft8.Fft8.dit_short table t 1#usize
      let t2 ← fft8.Fft8.dit_short table t1 2#usize
      fft8.Fft8.dit_short table t2 4#usize
    else do
      let t1 ← fft8.Fft8.dif_short table t 4#usize
      let t2 ← fft8.Fft8.dif_short table t1 2#usize
      fft8.Fft8.dif_short table t2 1#usize
  fr8.Fr8.transpose (Array.to_slice t') 0#usize

private theorem transpose_back (t : Array fr8.Fr8 8#usize)
    (values : _root_.Array Fr) (offset : Nat) (ht : TransposedRep t values offset) :
    ∃ out, fr8.Fr8.transpose (Array.to_slice t) 0#usize = ok out ∧
      ∀ row : Fin 8, Represents out.val[row.val]!
        (fun lane => values[8*(offset+row.val)+lane.val]!) := by
  apply transpose_representation (Array.to_slice t) 0#usize
    (fun row lane => values[8*(offset+lane.val)+row.val]!)
  · simp [Array.to_slice, t.property]
  · intro row
    simpa [Array.to_slice, getElem!_pos, row.isLt, t.property] using ht row

theorem block_run_representation
    (dit : Bool) (table : fft8.Fft8) (data : Slice fr8.Fr8) (offset : Usize)
    (values roots : _root_.Array Fr) (htable : FftInvariant table roots)
    (hsize : values.size = roots.size) (hunit : roots[0]! = 1)
    (hat : offset.val+8 ≤ data.val.length) (hblock : 8*(offset.val+8) ≤ values.size)
    (hdata : ∀ row : Fin 8, Represents data.val[offset.val+row.val]!
      (fun lane => values[8*(offset.val+row.val)+lane.val]!)) :
    ∃ out, blockRun dit table data offset = ok out ∧
      ∀ row : Fin 8, Represents out.val[row.val]!
        (fun lane => (shortStages dit values roots)[8*(offset.val+row.val)+lane.val]!) := by
  obtain ⟨t, htranspose, ht⟩ := transpose_representation data offset
    (fun row lane => values[8*(offset.val+row.val)+lane.val]!) hat hdata
  have htr : TransposedRep t values offset.val := ht
  cases dit
  · obtain ⟨t1, h1, ht1⟩ := short_refinement false table t values roots offset.val 4#usize
      (by simp) htable hsize hblock hunit htr
    obtain ⟨t2, h2, ht2⟩ := short_refinement false table t1
      (butterflyStage false values roots 4) roots offset.val 2#usize
      (by simp) htable (by simpa using hsize) (by simpa using hblock) hunit ht1
    obtain ⟨t3, h3, ht3⟩ := short_refinement false table t2
      (butterflyStage false (butterflyStage false values roots 4) roots 2) roots offset.val 1#usize
      (by simp) htable (by simpa using hsize) (by simpa using hblock) hunit ht2
    obtain ⟨out, hout, ho⟩ := transpose_back t3 _ offset.val ht3
    refine ⟨out, ?_, ho⟩
    simp only [blockRun, Bool.false_eq_true, if_false, htranspose, bind_tc_ok] at *
    simp only [h1, h2, h3, hout, bind_tc_ok]
  · obtain ⟨t1, h1, ht1⟩ := short_refinement true table t values roots offset.val 1#usize
      (by simp) htable hsize hblock hunit htr
    obtain ⟨t2, h2, ht2⟩ := short_refinement true table t1
      (butterflyStage true values roots 1) roots offset.val 2#usize
      (by simp) htable (by simpa using hsize) (by simpa using hblock) hunit ht1
    obtain ⟨t3, h3, ht3⟩ := short_refinement true table t2
      (butterflyStage true (butterflyStage true values roots 1) roots 2) roots offset.val 4#usize
      (by simp) htable (by simpa using hsize) (by simpa using hblock) hunit ht2
    obtain ⟨out, hout, ho⟩ := transpose_back t3 _ offset.val ht3
    refine ⟨out, ?_, ho⟩
    simp only [blockRun, if_true, htranspose, bind_tc_ok] at *
    simp only [h1, h2, h3, hout, bind_tc_ok]

def blockBody (dit : Bool) (table : fft8.Fft8) (data : Slice fr8.Fr8) (offset : Usize) :
    Result (ControlFlow (Slice fr8.Fr8 × Usize) (Slice fr8.Fr8)) :=
  if dit then fft8.Fft8.dit_loop0.body table.vectors table.wide table.short data offset
  else fft8.Fft8.dif_loop1.body table.vectors table.wide table.short data offset

private theorem block_body_run (dit : Bool) (table : fft8.Fft8) (data : Slice fr8.Fr8)
    (offset next : Usize) (hat : offset.val < table.vectors.val) (hnext : next.val = offset.val+8) :
    blockBody dit table data offset = (do
      let block ← blockRun dit table data offset
      let output ← fft8.set_block data offset block
      ok (cont (output,next))) := by
  have hadd : offset+fr8.LANES = ok next := by
    rw [fr8.LANES, scalar_add_ok offset 8#usize (by scalar_tac)]
    congr 1
    apply UScalar.eq_of_val_eq
    simpa using hnext.symm
  cases dit <;> simp [blockBody, blockRun, fft8.Fft8.dit_loop0.body,
    fft8.Fft8.dif_loop1.body, UScalar.lt_equiv, hat, hadd, lift]

private theorem block_loops (dit : Bool) (table : fft8.Fft8)
    (values roots : _root_.Array Fr) (htable : FftInvariant table roots)
    (hsize : values.size = roots.size) (hunit : roots[0]! = 1)
    (n : Nat) (hn : values.size = 8*n) (hsmall : n ≤ 512)
    (hvectors : table.vectors.val = n) (remaining : Nat) :
    ∀ (data : Slice fr8.Fr8) (offset : Usize), n = offset.val+8*remaining →
      BlockPrefix data values (shortStages dit values roots) n offset.val →
      ∃ out, loop (fun (d,i) => blockBody dit table d i) (data,offset) = ok out ∧
        BlockPrefix out values (shortStages dit values roots) n n := by
  induction remaining with
  | zero =>
    intro data offset hcount hp
    have ha : offset.val = n := by omega
    refine ⟨data, ?_, by simpa only [ha] using hp⟩
    rw [loop.eq_1]
    cases dit <;> simp [blockBody, fft8.Fft8.dit_loop0.body,
      fft8.Fft8.dif_loop1.body, UScalar.lt_equiv, hvectors, ha]
  | succ remaining ih =>
    intro data offset hcount hp
    have hat : offset.val+8 ≤ n := by omega
    let next : Usize := UScalar.ofNatCore (offset.val+8) (by scalar_tac)
    have hnext : next.val = offset.val+8 := UScalar.ofNatCore_val_eq _
    have hrows : ∀ row : Fin 8, Represents data.val[offset.val+row.val]!
        (fun lane => values[8*(offset.val+row.val)+lane.val]!) := by
      intro row
      simpa only [show ¬offset.val+row.val<offset.val by omega, if_false] using
        hp.2 ⟨offset.val+row.val, by omega⟩
    obtain ⟨block, hrun, hb⟩ := block_run_representation dit table data offset values roots
      htable hsize hunit (by rw [hp.1]; exact hat) (by omega) hrows
    obtain ⟨updated, hstore, hupdated⟩ := set_block_prefix data block values
      (shortStages dit values roots) n offset hat hsmall hb hp
    obtain ⟨out, hout, ho⟩ := ih updated next (by omega) (by simpa only [hnext] using hupdated)
    refine ⟨out, ?_, ho⟩
    rw [loop.eq_1]
    dsimp only
    rw [block_body_run dit table data offset next (by omega) hnext]
    simp only [hrun, hstore, bind_tc_ok]
    exact hout

theorem blocks_refinement (dit : Bool) (table : fft8.Fft8)
    (data : Slice fr8.Fr8) (values roots : _root_.Array Fr)
    (htable : FftInvariant table roots) (hsize : values.size = roots.size)
    (hunit : roots[0]! = 1) (hdata : DataRep data values) :
    ∃ out, (if dit then fft8.Fft8.dit_loop0 table.vectors table.wide table.short data 0#usize
      else fft8.Fft8.dif_loop1 table.vectors table.wide table.short data 0#usize) = ok out ∧
      DataRep out (shortStages dit values roots) := by
  obtain ⟨k, hk6, hk12, hk⟩ := htable.1
  have hsmall : roots.size ≤ 4096 := by rw [hk]; exact Nat.pow_le_pow_right (by decide) hk12
  have hn64 : roots.size = 64 * 2^(k-6) := by
    rw [hk]
    conv_lhs => rw [show k = (k-6)+6 by omega, Nat.pow_add]
    ring
  have hdsize := hdata.1
  have hlen : data.val.length = 8*2^(k-6) := by omega
  have hvectors : table.vectors.val = data.val.length := by
    rw [htable.2.1, ← hsize, hdata.1]
    omega
  have hp : BlockPrefix data values (shortStages dit values roots) data.val.length 0 := by
    refine ⟨rfl, ?_⟩
    intro v
    simpa only [getElem!_pos data.val v.val v.isLt, Nat.not_lt_zero, if_false] using hdata.2 v
  obtain ⟨out, hout, ho⟩ := block_loops dit table values roots htable hsize hunit
    data.val.length hdata.1 (by omega) hvectors (2^(k-6)) data 0#usize
    (by simpa using hlen) hp
  refine ⟨out, ?_, ?_, ?_⟩
  · cases dit <;> simpa only [blockBody, Bool.false_eq_true, Bool.true_eq, if_true, if_false,
      fft8.Fft8.dit_loop0, fft8.Fft8.dif_loop1] using hout
  · rw [size_shortStages, ho.1]
    exact hdata.1
  · intro v
    have hv : v.val < data.val.length := by simpa only [ho.1] using v.isLt
    simpa only [getElem!_pos out.val v.val v.isLt, hv, if_true] using ho.2 ⟨v.val,hv⟩

end LeanBlsSimd.Kzg.Extender.Kernel
