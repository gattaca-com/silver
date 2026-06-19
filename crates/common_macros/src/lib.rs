//! Proc-macro support for the silver crates. Exposes `#[timed]`, which wraps a
//! function body in a thread-local flux `Timer` so processing time is emitted
//! to a per-function shmem queue (or folded into an in-process call tree under
//! the perf harness). Built with the `perf` feature, the same guard also
//! records hardware counters (instructions, cycles, branch/cache misses) via
//! rdpmc. Storage and Drop-side recording live in `silver_metrics`; this crate
//! is only the attribute-macro glue.

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Ident, ItemFn, LitInt, LitStr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

struct TimedArgs {
    name: Option<LitStr>,
    sample: u64,
}

impl Parse for TimedArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut name = None;
        let mut sample = 1u64;
        if input.peek(LitStr) {
            name = Some(input.parse()?);
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }
        if !input.is_empty() {
            let ident: Ident = input.parse()?;
            if ident != "sample" {
                return Err(syn::Error::new(ident.span(), "expected `sample = N`"));
            }
            input.parse::<Token![=]>()?;
            let lit: LitInt = input.parse()?;
            sample = lit.base10_parse()?;
            if sample == 0 {
                return Err(syn::Error::new(lit.span(), "sample must be >= 1"));
            }
        }
        Ok(Self { name, sample })
    }
}

/// Wrap a function body in a per-function thread-local flux `Timer`.
///
/// Default timer name is `concat!(module_path!(), "::", fn_name)`
/// resolved at the call site — so the queue file becomes
/// `timing-{crate}::{module}::{fn_name}` and stays unambiguous across
/// crates without manual labelling.
///
/// On a method, the default name auto-qualifies by the monomorphized `Self`:
/// `type_name` bakes the concrete type in per instantiation, so generic code
/// whose frames would otherwise collapse onto one compile-time string (e.g.
/// `ColumnGroup<Balances>` vs `ColumnGroup<Inactivity>`) stays split — the type
/// info a flamegraph can't recover from a bare address in-process. Generic
/// helpers called underneath still split by their qualified parent path, so
/// only the receiver type is folded in (not fn-level type params, which would
/// fork a frame per closure type / call site). The name is a `&'static str`
/// (no hot-path cost); the report unwraps the marker into a `fn<Type>` label.
/// Free functions keep the plain `module::path::fn` name.
///
/// Pass a string literal to override: `#[timed("custom_name")]` uses that name
/// verbatim (no module prefix, no type qualification).
///
/// `sample = N` throttles the hardware-counter dimension (built with the `perf`
/// feature) to one in N calls on hot paths — timing is still recorded every
/// call. Combinable: `#[timed("custom_name", sample = 1000)]`. Without the
/// `perf` feature `sample` only affects which calls would have been counted, so
/// it is a no-op there.
///
/// Records processing time on every exit path — normal return, `?`,
/// early `return`, panic-unwind — via a Drop guard.
#[proc_macro_attribute]
pub fn timed(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let args = parse_macro_input!(attr as TimedArgs);
    let func_name_str = input.sig.ident.to_string();

    let is_method = matches!(input.sig.inputs.first(), Some(syn::FnArg::Receiver(_)));
    let timer_name_expr = match &args.name {
        Some(lit) => {
            let s = lit.value();
            quote! { #s }
        }
        None if is_method => quote! {{
            struct __TimedTy<T: ?Sized>(::core::marker::PhantomData<T>);
            ::core::any::type_name::<__TimedTy<Self>>()
        }},
        None => quote! { concat!(module_path!(), "::", #func_name_str) },
    };

    let ItemFn { attrs, vis, sig, block } = input;

    let guard = if args.sample <= 1 {
        quote! {
            let __timed_guard = ::silver_metrics::TimerGuard::new(#timer_name_expr);
        }
    } else {
        let sample = args.sample;
        quote! {
            ::std::thread_local! {
                static __TIMED_SKIP: ::core::cell::Cell<u64> =
                    const { ::core::cell::Cell::new(0) };
            }
            let __timed_sample = __TIMED_SKIP.with(|c| {
                let n = c.get();
                c.set(n.wrapping_add(1));
                n % #sample == 0
            });
            let __timed_guard =
                ::silver_metrics::TimerGuard::new_sampled(#timer_name_expr, __timed_sample);
        }
    };

    let expanded = quote! {
        #(#attrs)* #vis #sig {
            #guard
            #block
        }
    };

    expanded.into()
}
