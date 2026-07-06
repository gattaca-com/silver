//! Format a resolved `#[timed]` frame name for display and identity: strip the
//! module path to a leaf, and unwrap the `__TimedTy` method marker into a
//! `fn<Type>` label. Shared by the stats model (leaf matching) and the
//! call-tree renderer.

use std::borrow::Cow;

const MARK: &str = "::__TimedTy<";

/// A plain `#[timed]` free function is `module::path::fn`, displayed as the
/// trailing `fn`. A `#[timed]` method embeds its receiver as a
/// `…::fn::__TimedTy<ConcreteSelf>` marker (so each monomorphization is a
/// distinct frame a string-keyed sink could otherwise not tell apart),
/// unwrapped here into `fn<Type>`. Plain frames stay borrowed — the threshold
/// gauges match on these and must be unaffected.
pub(super) fn leaf_name(qualified: &str) -> Cow<'_, str> {
    let Some(at) = qualified.find(MARK) else {
        return Cow::Borrowed(leaf(qualified));
    };
    let func = leaf(&qualified[..at]);
    let rest = &qualified[at + MARK.len()..];
    let ty = rest.strip_suffix('>').unwrap_or(rest);
    Cow::Owned(format!("{func}<{}>", short_type_name(ty)))
}

fn leaf(path: &str) -> &str {
    path.rsplit("::").next().unwrap_or(path)
}

/// Shorten a fully-qualified `type_name` for display: keep only the leaf of
/// each `::`-path and drop lifetime arguments, so
/// `crate::col::ColumnGroup<'_, crate::col::Balances>` renders as
/// `ColumnGroup<Balances>`. (Same job as `disqualified::ShortName` / `tynm`,
/// inlined to keep this low-level crate dependency-free.)
fn short_type_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut seg = 0; // start of the current path segment within `out`
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < s.len() {
        match bytes[i] {
            b'\'' => {
                i += 1;
                while i < s.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                if s[i..].starts_with(", ") {
                    i += 2;
                } else if i < s.len() && bytes[i] == b',' {
                    i += 1;
                }
            }
            b':' if s[i..].starts_with("::") => {
                out.truncate(seg); // everything since `seg` was a module prefix
                i += 2;
            }
            b'<' | b'>' | b',' | b' ' => {
                out.push(bytes[i] as char);
                i += 1;
                seg = out.len();
            }
            _ => {
                let ch = s[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    out
}
