import Aeneas
import LeanBlsSimd.Model.Intrinsics
open Aeneas Aeneas.Std Result ControlFlow Error

/-!
The external type of the extraction. Written by hand from the `TypesExternal_Template.lean` that
Aeneas generates beside `Types.lean`; regeneration leaves this file alone.
-/

set_option linter.style.nameCheck false in
/-- [core::core_arch::x86::__m512i]
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/macros.rs', lines 90:8-90:48
    Name pattern: [core::core_arch::x86::__m512i]
    Visibility: public -/
@[rust_type "core::core_arch::x86::__m512i"]
abbrev core.core_arch.x86.__m512i : Type := LeanBlsSimd.M512
