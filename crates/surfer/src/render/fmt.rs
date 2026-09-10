use ratatui::{
    style::{Color, Style},
    text::Span,
};
use silver_common::Nanos;

/// Auto-unit duration via flux's `Nanos` Display ("2.345s", "12.5ms", "910μs"),
/// with a plain "0" for the zero it would otherwise render blank.
pub fn fmt_nanos(d: Nanos) -> String {
    if d.0 == 0 { "0".to_string() } else { d.to_string() }
}

/// First 4 bytes of a root as 8 hex chars.
pub fn root_prefix(root: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", root[0], root[1], root[2], root[3])
}

pub fn wall_time(ts: Nanos) -> String {
    ts.with_fmt_utc("%H:%M:%S%.3f")
}

pub fn fmt_u64(v: u64) -> String {
    if v >= 1_000_000_000 {
        format!("{:.2}G", v as f64 / 1e9)
    } else if v >= 1_000_000 {
        format!("{:.2}M", v as f64 / 1e6)
    } else if v >= 1_000 {
        format!("{:.2}k", v as f64 / 1e3)
    } else {
        v.to_string()
    }
}

/// Render a counter delta as a coloured span. Zero = dim, positive =
/// cyan, negative (wraparound on a gauge dec) = magenta. Returns a
/// padded right-aligned span of `width` chars.
pub fn delta_span(delta: i64, width: usize) -> Span<'static> {
    let s = if delta == 0 {
        format!("{:>w$}", "·", w = width)
    } else {
        format!("{:>+w$}", fmt_signed(delta), w = width)
    };
    let style = if delta == 0 {
        Style::default().fg(Color::DarkGray)
    } else if delta > 0 {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::Magenta)
    };
    Span::styled(s, style)
}

/// Format the time span covered by `n` buckets (each
/// `crate::sources::counters::BUCKET_SECS` wide) as a human-readable
/// "Nm Ns" string. Anchored to the leftmost bucket's age.
pub fn fmt_span_ago(n: usize) -> String {
    fmt_secs_ago(n as u64 * crate::sources::counters::BUCKET_SECS)
}

pub fn fmt_secs_ago(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

pub fn fmt_signed(v: i64) -> String {
    let mag = v.unsigned_abs();
    let suffix = if mag >= 1_000_000_000 {
        format!("{:.2}G", mag as f64 / 1e9)
    } else if mag >= 1_000_000 {
        format!("{:.2}M", mag as f64 / 1e6)
    } else if mag >= 1_000 {
        format!("{:.2}k", mag as f64 / 1e3)
    } else {
        mag.to_string()
    };
    if v < 0 { format!("-{suffix}") } else { suffix }
}
