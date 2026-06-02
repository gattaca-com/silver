//! Proc-macro support for the silver crates. Currently exposes
//! `#[timed]`, which wraps a function body in a thread-local flux
//! `Timer` so processing time is emitted to a per-function shmem
//! queue. Storage and Drop-side recording live in
//! `silver_metrics`; this crate is only the attribute-macro
//! glue.

use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, LitStr, parse_macro_input};

/// Wrap a function body in a per-function thread-local flux `Timer`.
///
/// Default timer name is `concat!(module_path!(), "::", fn_name)`
/// resolved at the call site — so the queue file becomes
/// `timing-{crate}::{module}::{fn_name}` and stays unambiguous across
/// crates without manual labelling.
///
/// Pass a string literal to override: `#[timed("custom_name")]` uses
/// that name verbatim (no module prefix).
///
/// Records processing time on every exit path — normal return, `?`,
/// early `return`, panic-unwind — via a Drop guard.
#[proc_macro_attribute]
pub fn timed(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);

    let timer_name_expr = if attr.is_empty() {
        let func_name_str = input.sig.ident.to_string();
        quote! { concat!(module_path!(), "::", #func_name_str) }
    } else {
        let lit = parse_macro_input!(attr as LitStr);
        let s = lit.value();
        quote! { #s }
    };

    let ItemFn { attrs, vis, sig, block } = input;

    let expanded = quote! {
        #(#attrs)* #vis #sig {
            ::std::thread_local! {
                static __TIMED_TIMER: ::core::cell::RefCell<
                    ::core::option::Option<::flux::Timer>
                > = ::core::cell::RefCell::new(::core::option::Option::None);
            }
            let __timed_guard = ::silver_metrics::TimerGuard::new(
                &__TIMED_TIMER,
                #timer_name_expr,
            );
            #block
        }
    };

    expanded.into()
}
