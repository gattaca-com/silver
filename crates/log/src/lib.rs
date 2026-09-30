//! The workspace's logging macros. `warn!` and `error!` also register their
//! callsite in `LOG_SITES` at link time and count every event, so a node can
//! publish per-callsite counts without a subscriber in the loop.

use std::{
    ptr,
    sync::atomic::{AtomicPtr, AtomicU64, Ordering},
};

#[doc(hidden)]
pub mod __private {
    pub use linkme;
    pub use tracing;
}

pub use tracing::{debug, info, trace};

pub mod counts;

pub struct LogSite {
    pub file: &'static str,
    pub line: u32,
    pub level: &'static str,
    /// The format string, or the whole argument list when it has none.
    pub template: &'static str,
}

#[linkme::distributed_slice]
pub static LOG_SITES: [LogSite];

static COUNTERS: AtomicPtr<AtomicU64> = AtomicPtr::new(ptr::null_mut());

/// Counter `i` counts `LOG_SITES[i]`. Events before this are not counted.
pub(crate) fn attach(counters: &'static [AtomicU64]) {
    assert_eq!(counters.len(), LOG_SITES.len());
    COUNTERS.store(counters.as_ptr().cast_mut(), Ordering::Release);
}

impl LogSite {
    #[inline]
    pub fn count(&'static self) {
        let counters = COUNTERS.load(Ordering::Acquire);
        if counters.is_null() {
            return;
        }
        let index = (ptr::from_ref(self).addr() - LOG_SITES.as_ptr().addr()) / size_of::<Self>();
        unsafe { (*counters.add(index)).fetch_add(1, Ordering::Relaxed) };
    }
}

/// The first argument that is a lone literal: fields like `%e` or `n = 1` span
/// several tokens, so `@skip` walks to the next comma.
#[doc(hidden)]
#[macro_export]
macro_rules! __template {
    (@skip , $($rest:tt)*) => { $crate::__template!($($rest)*) };
    (@skip $next:tt $($rest:tt)*) => { $crate::__template!(@skip $($rest)*) };
    (@skip) => { None };
    ($template:literal $(, $($rest:tt)*)?) => { Some($template) };
    ($($rest:tt)*) => { $crate::__template!(@skip $($rest)*) };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __counted {
    ($level:ident, $($arg:tt)+) => {{
        #[$crate::__private::linkme::distributed_slice($crate::LOG_SITES)]
        #[linkme(crate = $crate::__private::linkme)]
        static SITE: $crate::LogSite = $crate::LogSite {
            file: file!(),
            line: line!(),
            level: stringify!($level),
            template: match $crate::__template!($($arg)+) {
                Some(template) => template,
                None => stringify!($($arg)+),
            },
        };
        SITE.count();
        $crate::__private::tracing::event!($crate::__private::tracing::Level::$level, $($arg)+)
    }};
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => { $crate::__counted!(ERROR, $($arg)+) };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => { $crate::__counted!(WARN, $($arg)+) };
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{LOG_SITES, LogSite, attach};

    macro_rules! forwarded {
        ($message:expr) => {
            warn!($message)
        };
    }

    fn site(template: &str) -> (usize, &'static LogSite) {
        let mut sites = LOG_SITES.iter().enumerate().filter(|(_, s)| s.template == template);
        let site = sites.next().unwrap();
        assert!(sites.next().is_none(), "{template}");
        site
    }

    #[test]
    fn sites_carry_their_template_and_count_events() {
        let counters = Box::leak((0..LOG_SITES.len()).map(|_| AtomicU64::new(0)).collect());
        attach(counters);

        let n = 1;
        let plain = line!() + 2;
        for _ in 0..3 {
            warn!("plain");
            error!(%n, "fields then {}", n);
            warn!(
                "multi \
                   line {n}"
            );
            warn!(concat!("a", "b"));
            forwarded!("forwarded");
        }

        assert_eq!((site("plain").1.file, site("plain").1.line), (file!(), plain));
        for (level, template) in [
            ("WARN", "plain"),
            ("ERROR", "fields then {}"),
            ("WARN", "multi line {n}"),
            ("WARN", "concat!(\"a\", \"b\")"),
            ("WARN", "forwarded"),
        ] {
            let (index, site) = site(template);
            assert_eq!(site.level, level, "{template}");
            assert_eq!(counters[index].load(Ordering::Relaxed), 3, "{template}");
        }
    }
}
