import LeanBlsSimd.Kzg.Extender.Kernel.Fr8
import LeanBlsSimd.Kzg.Extender.Decode
open LeanBlsSimd.Kzg.Extender
open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg
namespace LeanBlsSimd.Kzg.Extender.Kernel.PairConstruction
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000

private theorem rem_eval {ty : UScalarTy} (x y : UScalar ty) (h : y.val ≠ 0) :
    x % y = ok (UScalar.ofNatCore (x.val % y.val) (by have := x.hmax; exact Nat.lt_of_le_of_lt (Nat.mod_le _ _) this)) := by
  obtain ⟨z, hz, hv⟩ := WP.spec_imp_exists (UScalar.rem_spec x h)
  rw [hz]
  congr 1
  apply UScalar.eq_of_val_eq
  simpa using hv
private theorem div_eval {ty : UScalarTy} (x y : UScalar ty) (h : y.val ≠ 0) :
    x / y = ok (UScalar.ofNatCore (x.val / y.val) (by have := x.hmax; exact Nat.lt_of_le_of_lt (Nat.div_le_self _ _) this)) := by
  obtain ⟨z, hz, hv⟩ := UScalar.div_spec x h
  rw [hz]
  congr 1
  apply UScalar.eq_of_val_eq
  simpa using hv
private theorem hcast_eval (x : Usize) (h : x.val < 2 ^ 63) :
    UScalar.hcast .I64 x = IScalar.ofIntCore (ty := .I64) x.val (by simp only [IScalarTy.numBits]; constructor <;> omega) := by
  apply IScalar.eq_of_val_eq
  have ht := UScalar.hcast_inBounds_spec .I64 x (by simp only [IScalar.max, IScalarTy.numBits]; omega)
  simpa only [lift, WP.spec_ok, IScalar.ofInt_val_eq] using ht

private theorem iadd_eval {ty : IScalarTy} (x y : IScalar ty)
    (h : -2^(ty.numBits-1) ≤ x.val + y.val ∧ x.val + y.val < 2^(ty.numBits-1)) :
    x + y = ok (IScalar.ofIntCore (x.val + y.val) h) := by
  change IScalar.tryMk ty (x.val + y.val) = _
  simp [IScalar.tryMk, IScalar.tryMkOpt, Result.ofOption, h]

private def indexI64 (n : Nat) : I64 := ⟨BitVec.ofNat 64 n⟩

private theorem array_update_ok (a : Array I64 8#usize) (i : Usize) (x : I64)
    (hi : i.val<8) : Array.update a i x = ok (a.set i x) := by
  have hb : i.val<a.val.length := by simpa only [a.property,UScalar.ofNatCore_val_eq] using hi
  simp [Array.update,Aeneas.Std.Array.set,List.getElem?_eq_getElem hb]

private theorem body0_eval (h : Usize) (hh : h.val=1 ∨ h.val=2 ∨ h.val=4)
    (upper lower : Array I64 8#usize) (m : Usize) (hm : m.val<8) :
    fft8.LanePairs.new_loop0.body h 4#usize upper lower m =
      ok (.cont (upper.set m (indexI64 (m.val%4/h.val*(2*h.val)+m.val%h.val+m.val/4*8)),
        lower.set m (indexI64 (m.val%4/h.val*(2*h.val)+m.val%h.val+m.val/4*8+h.val)),
        UScalar.ofNatCore (m.val+1) (by scalar_tac))) := by
  rcases hh with hh | hh | hh <;>
    simp (disch := first | decide | omega | scalar_tac)
      [fft8.LanePairs.new_loop0.body,fr8.LANES,UScalar.lt_equiv,hm,hh,rem_eval,div_eval,
        scalar_mul_ok,scalar_add_ok,hcast_eval,iadd_eval,lift,array_update_ok]
  all_goals constructor <;> congr 1 <;>
    simp [indexI64, IScalar.ofIntCore, IScalarTy.numBits]
  all_goals apply BitVec.eq_of_toNat_eq
  all_goals simp only [BitVec.toNat_ofNat]
  all_goals dsimp only [BitVec.toNat]
  all_goals omega

private theorem body1_eval (h : Usize) (hh : h.val=1 ∨ h.val=2 ∨ h.val=4)
    (first second : Array I64 8#usize) (m : Usize) (hm : m.val<8) :
    fft8.LanePairs.new_loop1.body h 4#usize first second m =
      ok (.cont (first.set m (indexI64 (m.val/(2*h.val)*h.val+m.val%h.val+
          (if m.val%(2*h.val)<h.val then 0 else 8))),
        second.set m (indexI64 (m.val/(2*h.val)*h.val+m.val%h.val+4+
          (if m.val%(2*h.val)<h.val then 0 else 8))),
        UScalar.ofNatCore (m.val+1) (by scalar_tac))) := by
  rcases hh with hh | hh | hh <;>
    simp (disch := first | decide | omega | scalar_tac)
      [fft8.LanePairs.new_loop1.body,fr8.LANES,UScalar.lt_equiv,hm,hh,rem_eval,div_eval,
        scalar_mul_ok,scalar_add_ok,hcast_eval,iadd_eval,lift,array_update_ok]
  all_goals split <;>
    simp (disch := first | omega | scalar_tac) [iadd_eval, *]
  all_goals constructor <;> congr 1 <;>
    simp [indexI64, IScalar.ofIntCore, IScalarTy.numBits]
  all_goals apply BitVec.eq_of_toNat_eq
  all_goals simp only [BitVec.toNat_ofNat]
  all_goals dsimp only [BitVec.toNat]
  all_goals omega


private theorem body0_done (h : Usize) (upper lower : Array I64 8#usize) :
    fft8.LanePairs.new_loop0.body h 4#usize upper lower 8#usize = ok (.done (upper,lower)) := by
  simp [fft8.LanePairs.new_loop0.body,fr8.LANES]

private theorem body1_done (h : Usize) (first second : Array I64 8#usize) :
    fft8.LanePairs.new_loop1.body h 4#usize first second 8#usize = ok (.done (first,second)) := by
  simp [fft8.LanePairs.new_loop1.body,fr8.LANES]

def concretePairs (h : Nat) : fft8.LanePairs :=
  { upper := .ofFn fun m => UInt64.ofNat (m.val % 4 / h * (2 * h) + m.val % h + m.val / 4 * 8)
    lower := .ofFn fun m => UInt64.ofNat (m.val % 4 / h * (2 * h) + m.val % h + m.val / 4 * 8 + h)
    first := .ofFn fun e => UInt64.ofNat (e.val / (2 * h) * h + e.val % h +
      (if e.val % (2 * h) < h then 0 else 8))
    second := .ofFn fun e => UInt64.ofNat (e.val / (2 * h) * h + e.val % h + 4 +
      (if e.val % (2 * h) < h then 0 else 8)) }

private def put (a : Array I64 8#usize) (i x : Nat) : Array I64 8#usize :=
  ⟨a.val.set i (indexI64 x), by simp [a.property]⟩

private def fill (f g : Nat → Nat) : Nat → Nat → Array I64 8#usize → Array I64 8#usize →
    Array I64 8#usize × Array I64 8#usize
  | 0, _, a, b => (a,b)
  | remaining+1, i, a, b => fill f g remaining (i+1) (put a i (f i)) (put b i (g i))

private theorem loop_fill
    (body : Array I64 8#usize → Array I64 8#usize → Usize →
      Result (ControlFlow (Array I64 8#usize × Array I64 8#usize × Usize)
        (Array I64 8#usize × Array I64 8#usize)))
    (f g : Nat → Nat)
    (hstep : ∀ (a b : Array I64 8#usize) (i : Usize) (hi : i.val < 8),
      body a b i = ok (.cont (put a i.val (f i.val), put b i.val (g i.val),
        UScalar.ofNatCore (i.val+1) (by scalar_tac))))
    (hdone : ∀ a b, body a b 8#usize = ok (.done (a,b)))
    (remaining : Nat) :
    ∀ (a b : Array I64 8#usize) (i : Usize), i.val+remaining=8 →
      loop (fun (a,b,i) => body a b i) (a,b,i) = ok (fill f g remaining i.val a b) := by
  induction remaining with
  | zero =>
    intro a b i hi
    have he : i=8#usize := UScalar.eq_of_val_eq (by simpa using hi)
    subst i
    rw [loop.eq_1]
    dsimp only
    rw [hdone]
    rfl
  | succ remaining ih =>
    intro a b i hi
    have hib : i.val < 8 := by omega
    rw [loop.eq_1]
    dsimp only
    rw [hstep a b i hib]
    exact ih _ _ _ (by simp only [UScalar.ofNatCore_val_eq]; omega)

private theorem pair1_loop0 :
    fft8.LanePairs.new_loop0 1#usize 4#usize
      (Array.repeat 8#usize 0#i64) (Array.repeat 8#usize 0#i64) 0#usize =
      ok (⟨[0#i64, 2#i64, 4#i64, 6#i64, 8#i64, 10#i64, 12#i64, 14#i64], by decide⟩, ⟨[1#i64, 3#i64, 5#i64, 7#i64, 9#i64, 11#i64, 13#i64, 15#i64], by decide⟩) := by
  have hr := loop_fill (fft8.LanePairs.new_loop0.body 1#usize 4#usize)
    (fun m => m%4/1*(2*1)+m%1+m/4*8)
    (fun m => m%4/1*(2*1)+m%1+m/4*8+1)
    (fun a b i hi => body0_eval 1#usize (by decide) a b i hi)
    (body0_done 1#usize) 8
    (Array.repeat 8#usize 0#i64) (Array.repeat 8#usize 0#i64) 0#usize (by decide)
  exact hr

private theorem pair1_loop1 :
    fft8.LanePairs.new_loop1 1#usize 4#usize
      (Array.repeat 8#usize 0#i64) (Array.repeat 8#usize 0#i64) 0#usize =
      ok (⟨[0#i64, 8#i64, 1#i64, 9#i64, 2#i64, 10#i64, 3#i64, 11#i64], by decide⟩, ⟨[4#i64, 12#i64, 5#i64, 13#i64, 6#i64, 14#i64, 7#i64, 15#i64], by decide⟩) := by
  have hr := loop_fill (fft8.LanePairs.new_loop1.body 1#usize 4#usize)
    (fun m => m/(2*1)*1+m%1+(if m%(2*1)<1 then 0 else 8))
    (fun m => m/(2*1)*1+m%1+4+(if m%(2*1)<1 then 0 else 8))
    (fun a b i hi => body1_eval 1#usize (by decide) a b i hi)
    (body1_done 1#usize) 8
    (Array.repeat 8#usize 0#i64) (Array.repeat 8#usize 0#i64) 0#usize (by decide)
  exact hr

theorem pair1 : fft8.LanePairs.new 1#usize = ok (concretePairs 1) := by
  unfold fft8.LanePairs.new
  simp only [fr8.LANES, show (8#usize / 2#usize) = ok 4#usize from by rfl,
    bind_tc_ok, pair1_loop0, pair1_loop1]
  simp [fft8.index_vector, Array.index_usize, concretePairs]
  simp only [core.core_arch.x86.avx512f._mm512_set_epi64, bind_tc_ok]
  congr 2 <;> apply Vector.ext <;> intro i hi <;> interval_cases i <;>
    simp [LeanBlsSimd._mm512_set_epi64] <;> rfl

private theorem pair2_loop0 :
    fft8.LanePairs.new_loop0 2#usize 4#usize
      (Array.repeat 8#usize 0#i64) (Array.repeat 8#usize 0#i64) 0#usize =
      ok (⟨[0#i64, 1#i64, 4#i64, 5#i64, 8#i64, 9#i64, 12#i64, 13#i64], by decide⟩, ⟨[2#i64, 3#i64, 6#i64, 7#i64, 10#i64, 11#i64, 14#i64, 15#i64], by decide⟩) := by
  have hr := loop_fill (fft8.LanePairs.new_loop0.body 2#usize 4#usize)
    (fun m => m%4/2*(2*2)+m%2+m/4*8)
    (fun m => m%4/2*(2*2)+m%2+m/4*8+2)
    (fun a b i hi => body0_eval 2#usize (by decide) a b i hi)
    (body0_done 2#usize) 8
    (Array.repeat 8#usize 0#i64) (Array.repeat 8#usize 0#i64) 0#usize (by decide)
  exact hr

private theorem pair2_loop1 :
    fft8.LanePairs.new_loop1 2#usize 4#usize
      (Array.repeat 8#usize 0#i64) (Array.repeat 8#usize 0#i64) 0#usize =
      ok (⟨[0#i64, 1#i64, 8#i64, 9#i64, 2#i64, 3#i64, 10#i64, 11#i64], by decide⟩, ⟨[4#i64, 5#i64, 12#i64, 13#i64, 6#i64, 7#i64, 14#i64, 15#i64], by decide⟩) := by
  have hr := loop_fill (fft8.LanePairs.new_loop1.body 2#usize 4#usize)
    (fun m => m/(2*2)*2+m%2+(if m%(2*2)<2 then 0 else 8))
    (fun m => m/(2*2)*2+m%2+4+(if m%(2*2)<2 then 0 else 8))
    (fun a b i hi => body1_eval 2#usize (by decide) a b i hi)
    (body1_done 2#usize) 8
    (Array.repeat 8#usize 0#i64) (Array.repeat 8#usize 0#i64) 0#usize (by decide)
  exact hr

theorem pair2 : fft8.LanePairs.new 2#usize = ok (concretePairs 2) := by
  unfold fft8.LanePairs.new
  simp only [fr8.LANES, show (8#usize / 2#usize) = ok 4#usize from by rfl,
    bind_tc_ok, pair2_loop0, pair2_loop1]
  simp [fft8.index_vector, Array.index_usize, concretePairs]
  simp only [core.core_arch.x86.avx512f._mm512_set_epi64, bind_tc_ok]
  congr 2 <;> apply Vector.ext <;> intro i hi <;> interval_cases i <;>
    simp [LeanBlsSimd._mm512_set_epi64] <;> rfl

private theorem pair4_loop0 :
    fft8.LanePairs.new_loop0 4#usize 4#usize
      (Array.repeat 8#usize 0#i64) (Array.repeat 8#usize 0#i64) 0#usize =
      ok (⟨[0#i64, 1#i64, 2#i64, 3#i64, 8#i64, 9#i64, 10#i64, 11#i64], by decide⟩, ⟨[4#i64, 5#i64, 6#i64, 7#i64, 12#i64, 13#i64, 14#i64, 15#i64], by decide⟩) := by
  have hr := loop_fill (fft8.LanePairs.new_loop0.body 4#usize 4#usize)
    (fun m => m%4/4*(2*4)+m%4+m/4*8)
    (fun m => m%4/4*(2*4)+m%4+m/4*8+4)
    (fun a b i hi => body0_eval 4#usize (by decide) a b i hi)
    (body0_done 4#usize) 8
    (Array.repeat 8#usize 0#i64) (Array.repeat 8#usize 0#i64) 0#usize (by decide)
  exact hr

private theorem pair4_loop1 :
    fft8.LanePairs.new_loop1 4#usize 4#usize
      (Array.repeat 8#usize 0#i64) (Array.repeat 8#usize 0#i64) 0#usize =
      ok (⟨[0#i64, 1#i64, 2#i64, 3#i64, 8#i64, 9#i64, 10#i64, 11#i64], by decide⟩, ⟨[4#i64, 5#i64, 6#i64, 7#i64, 12#i64, 13#i64, 14#i64, 15#i64], by decide⟩) := by
  have hr := loop_fill (fft8.LanePairs.new_loop1.body 4#usize 4#usize)
    (fun m => m/(2*4)*4+m%4+(if m%(2*4)<4 then 0 else 8))
    (fun m => m/(2*4)*4+m%4+4+(if m%(2*4)<4 then 0 else 8))
    (fun a b i hi => body1_eval 4#usize (by decide) a b i hi)
    (body1_done 4#usize) 8
    (Array.repeat 8#usize 0#i64) (Array.repeat 8#usize 0#i64) 0#usize (by decide)
  exact hr

theorem pair4 : fft8.LanePairs.new 4#usize = ok (concretePairs 4) := by
  unfold fft8.LanePairs.new
  simp only [fr8.LANES, show (8#usize / 2#usize) = ok 4#usize from by rfl,
    bind_tc_ok, pair4_loop0, pair4_loop1]
  simp [fft8.index_vector, Array.index_usize, concretePairs]
  simp only [core.core_arch.x86.avx512f._mm512_set_epi64, bind_tc_ok]
  congr 2 <;> apply Vector.ext <;> intro i hi <;> interval_cases i <;>
    simp [LeanBlsSimd._mm512_set_epi64] <;> rfl


private theorem concretePairs_valid (h : Nat) (hh : h=1 ∨ h=2 ∨ h=4) :
    LanePairsInvariant (concretePairs h) h := by
  rcases hh with rfl | rfl | rfl <;>
    (refine ⟨by decide, ?_, ?_⟩ <;> intro m <;> fin_cases m <;> decide)

theorem lane_pairs_refinement (h : Usize) (hh : h.val=1 ∨ h.val=2 ∨ h.val=4) :
    ∃ pairs, fft8.LanePairs.new h = ok pairs ∧ LanePairsInvariant pairs h.val := by
  rcases hh with hh | hh | hh
  · have he : h=1#usize := UScalar.eq_of_val_eq (by simpa using hh)
    subst h
    exact ⟨concretePairs 1,pair1,concretePairs_valid 1 (by decide)⟩
  · have he : h=2#usize := UScalar.eq_of_val_eq (by simpa using hh)
    subst h
    exact ⟨concretePairs 2,pair2,concretePairs_valid 2 (by decide)⟩
  · have he : h=4#usize := UScalar.eq_of_val_eq (by simpa using hh)
    subst h
    exact ⟨concretePairs 4,pair4,concretePairs_valid 4 (by decide)⟩

end LeanBlsSimd.Kzg.Extender.Kernel.PairConstruction
