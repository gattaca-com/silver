//! Proc-macro support for the silver crates. Exposes `#[timed]` (wraps a
//! function body in a thread-local flux `Timer` so processing time is
//! emitted to a per-function shmem queue) and `#[perf]` (same shape, but
//! records instructions retired + CPU cycles via rdpmc onto `perf-{fn}`
//! queues). Storage and Drop-side recording live in `silver_metrics`;
//! this crate is only the attribute-macro glue.

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Ident, ItemFn, LitInt, LitStr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

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
/// Records processing time on every exit path — normal return, `?`,
/// early `return`, panic-unwind — via a Drop guard.
#[proc_macro_attribute]
pub fn timed(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let func_name_str = input.sig.ident.to_string();

    let is_method = matches!(input.sig.inputs.first(), Some(syn::FnArg::Receiver(_)));
    let timer_name_expr = if !attr.is_empty() {
        let s = parse_macro_input!(attr as LitStr).value();
        quote! { #s }
    } else if is_method {
        quote! {{
            struct __TimedTy<T: ?Sized>(::core::marker::PhantomData<T>);
            ::core::any::type_name::<__TimedTy<Self>>()
        }}
    } else {
        quote! { concat!(module_path!(), "::", #func_name_str) }
    };

    let ItemFn { attrs, vis, sig, block } = input;

    let expanded = quote! {
        #(#attrs)* #vis #sig {
            let __timed_guard = ::silver_metrics::TimerGuard::new(
                #timer_name_expr,
            );
            #block
        }
    };

    expanded.into()
}

/// Arguments to `#[perf]`: an optional name literal, then an optional
/// `sample = N`.
struct PerfArgs {
    name: Option<LitStr>,
    sample: u64,
}

impl Parse for PerfArgs {
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

/// Record instructions retired + CPU cycles for a function via a
/// Drop guard, emitted per call onto the `perf-{name}` shmem queue.
///
/// Naming matches `#[timed]`: default is
/// `concat!(module_path!(), "::", fn_name)`; pass a string literal to
/// override (`#[perf("custom_name")]`).
///
/// `sample = N` measures one in N calls (per thread, via a
/// thread-local call counter) — use on hot paths where two rdpmc
/// reads per call is too much. Default 1 = every call. Combinable:
/// `#[perf("custom_name", sample = 1000)]`.
///
/// Collection requires the `perf` feature on `silver_metrics` (rdpmc)
/// and `kernel.perf_event_paranoid <= 2` at runtime; otherwise the
/// guard is inert.
#[proc_macro_attribute]
pub fn perf(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let args = parse_macro_input!(attr as PerfArgs);

    let name_expr = match &args.name {
        Some(lit) => {
            let s = lit.value();
            quote! { #s }
        }
        None => {
            let func_name_str = input.sig.ident.to_string();
            quote! { concat!(module_path!(), "::", #func_name_str) }
        }
    };

    let ItemFn { attrs, vis, sig, block } = input;

    let guard = if args.sample <= 1 {
        quote! {
            let __perf_guard = ::silver_metrics::PerfGuard::new(
                #name_expr,
            );
        }
    } else {
        let sample = args.sample;
        quote! {
            ::std::thread_local! {
                static __PERF_SKIP: ::core::cell::Cell<u64> =
                    const { ::core::cell::Cell::new(0) };
            }
            let __perf_guard = __PERF_SKIP.with(|c| {
                let n = c.get();
                c.set(n.wrapping_add(1));
                (n % #sample == 0).then(|| ::silver_metrics::PerfGuard::new(#name_expr))
            });
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
