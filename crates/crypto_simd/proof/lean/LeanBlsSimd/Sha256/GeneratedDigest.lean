import LeanBlsSimd.Sha256.SpecDigest

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Sha256.Generated

set_option maxRecDepth 2048
attribute [local irreducible] Spec.digest

def writtenBytes (state : Array U32 8#usize) : Array U8 32#usize :=
  ⟨List.ofFn (fun i : Fin 32 => (core.num.U32.to_be_bytes state.val[i.val/4]!).val[i.val%4]!),by simp⟩

theorem writtenBytes_get (state : Array U32 8#usize) (w b : Nat) (hw : w < 8) (hb : b < 4) :
    (writtenBytes state).val[4*w+b]! = (core.num.U32.to_be_bytes state.val[w]!).val[b]! := by
  rw [getElem!_pos _ _ (by rw [(writtenBytes state).property]; change 4*w+b < 32; omega)]
  simp only [writtenBytes,List.getElem_ofFn]
  have hd : (4*w+b)/4 = w := by omega
  have hm : (4*w+b)%4 = b := by omega
  rw [hd,hm]

theorem digest_step (state : Array U32 8#usize) (digest : Array U8 32#usize)
    (i : Usize) (hi : i.val < 8) :
    ∃ next : Usize, next.val = i.val+1 ∧
      sha256.portable.Sha256.finish_loop.body state digest i =
        ok (cont (digest.setSlice! (4*i.val) (core.num.U32.to_be_bytes state.val[i.val]!).val,next)) := by
  let next : Usize := UScalar.ofNatCore (i.val+1) (by scalar_tac)
  refine ⟨next,rfl,?_⟩
  simp only [sha256.portable.Sha256.finish_loop.body,show i < 8#usize from hi,if_true]
  simp (disch := scalar_tac) only [mul_ok,add_ok,bind_tc_ok,UScalar.ofNatCore_val_eq]
  rw [index_mut_range _ _ _ (by scalar_tac) (by scalar_tac)]
  simp only [bind_tc_ok,Function.uncurry_apply_pair]
  rw [Portable.index_word state i hi]
  simp only [bind_tc_ok,lift]
  rw [copy_eq _ _ (by
    rw [range_length _ _ _ (by simp only [Array.to_slice,digest.property,UScalar.ofNatCore_val_eq]; scalar_tac)]
    simp only [Array.to_slice,(core.num.U32.to_be_bytes _).property,UScalar.ofNatCore_val_eq]
    change 4*i.val+4-4*i.val = 4
    omega)]
  simp (disch := scalar_tac) only [bind_tc_ok,add_ok]
  congr 1
  rw [words_get state i.val hi,← getElem!_pos state.val i.val (by rw [state.property]; exact hi),word_ofWord]
  rfl

theorem digest_loop_refines (state : Array U32 8#usize) (digest : Array U8 32#usize)
    (i : Usize) (hi : i.val ≤ 8)
    (hpre : ∀ k < 4*i.val, digest.val[k]! = (writtenBytes state).val[k]!) :
    sha256.portable.Sha256.finish_loop state digest i = ok (writtenBytes state) := by
  induction hn : 8-i.val generalizing digest i with
  | zero =>
    have he : i.val = 8 := by omega
    have hd : digest = writtenBytes state := by
      apply Subtype.ext
      apply List.ext_getElem
      · rw [digest.property,(writtenBytes state).property]
      · intro k hk hk'
        rw [← getElem!_pos digest.val k hk,← getElem!_pos (writtenBytes state).val k hk']
        exact hpre k (by rw [digest.property] at hk; change k < 32 at hk; omega)
    rw [sha256.portable.Sha256.finish_loop,loop.eq_1]
    simp [sha256.portable.Sha256.finish_loop.body,show ¬i < 8#usize by change ¬i.val < 8; omega,hd]
  | succ n ih =>
    obtain ⟨next,hnext,hbody⟩ := digest_step state digest i (by omega)
    let chunk := (core.num.U32.to_be_bytes state.val[i.val]!).val
    have hchunk : chunk.length = 4 := (core.num.U32.to_be_bytes _).property
    let digest' := digest.setSlice! (4*i.val) chunk
    have hpre' : ∀ k < 4*next.val, digest'.val[k]! = (writtenBytes state).val[k]! := by
      intro k hk
      change (digest.val.setSlice! (4*i.val) chunk)[k]! = _
      by_cases hold : k < 4*i.val
      · rw [List.getElem!_setSlice!_prefix _ _ _ _ hold]
        exact hpre k hold
      · rw [List.getElem!_setSlice!_middle]
        · have hb : k-4*i.val < 4 := by omega
          have he : 4*i.val+(k-4*i.val) = k := by omega
          simpa only [he] using (writtenBytes_get state i.val (k-4*i.val) (by omega) hb).symm
        · rw [hchunk,digest.property]; change 4*i.val ≤ k ∧ k-4*i.val < 4 ∧ k < 32; omega
    have hr := ih digest' next (by omega) hpre' (by omega)
    rw [sha256.portable.Sha256.finish_loop,loop.eq_1]
    simpa only [hbody] using hr


private theorem bytes_ext (a b : ByteArray) (hs : a.size=b.size)
    (h : ∀ i < a.size, a[i]! = b[i]!) : a=b := by
  apply ByteArray.ext
  apply _root_.Array.ext
  · exact hs
  · intro i hi hi'
    exact (getElem!_pos a i hi).symm.trans ((h i hi).trans (getElem!_pos b i hi'))

theorem writtenBytes_model (state : Array U32 8#usize) :
    Spec.bytes ((writtenBytes state).val.map ofU8) = Spec.digest (words state) := by
  have hs : (Spec.bytes ((writtenBytes state).val.map ofU8)).size = 32 := by
    rw [Spec.bytes_size,List.length_map,(writtenBytes state).property]; rfl
  have he : ∀ w < 8, ∀ b < 4,
      (Spec.bytes ((writtenBytes state).val.map ofU8))[4*w+b]! = (Spec.digest (words state))[4*w+b]! := by
    intro w hw b hb
    have hi : 4*w+b < (writtenBytes state).val.length := by
      rw [(writtenBytes state).property]; change 4*w+b < 32; omega
    rw [Spec.bytes_get,getElem!_pos _ _ (by rw [List.length_map]; exact hi),List.getElem_map,
      ← getElem!_pos (writtenBytes state).val (4*w+b) hi,writtenBytes_get state w b hw hb,
      be_u32 _ b hb,Spec.digest_get _ w b hw hb,words_get state w hw,
      ← getElem!_pos state.val w (by rw [state.property]; exact hw)]
    rfl
  apply bytes_ext _ _ (hs.trans (Spec.digest_size _).symm)
  intro i hi
  have hi32 : i < 32 := by omega
  have h := he (i/4) (by omega) (i%4) (by omega)
  simpa only [show 4*(i/4)+i%4 = i by omega] using h

end LeanBlsSimd.Sha256.Generated
