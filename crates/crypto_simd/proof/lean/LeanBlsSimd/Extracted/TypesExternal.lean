import Aeneas
import LeanBlsSimd.Model.Intrinsics
import LeanBlsSimd.Model.ShaIntrinsics
open Aeneas Aeneas.Std Result ControlFlow Error

/-!
Handwritten representation of the external `__m512i` type. The starting template is
`TypesExternal_Template.lean`, generated beside `Types.lean`; `extract.sh` preserves this file.
-/

set_option linter.style.nameCheck false in
/-- [core::core_arch::x86::__m512i]
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/macros.rs', lines 90:8-90:48
    Name pattern: [core::core_arch::x86::__m512i]
    Visibility: public -/
@[rust_type "core::core_arch::x86::__m512i"]
abbrev core.core_arch.x86.__m512i : Type := LeanBlsSimd.M512

set_option linter.style.nameCheck false in
@[rust_type "core::core_arch::x86::__m128i"]
abbrev core.core_arch.x86.__m128i : Type := LeanBlsSimd.M128
