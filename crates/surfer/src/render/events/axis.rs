use silver_common::Nanos;

/// The shared time scale: into-slot nanoseconds → axis cells.
pub struct Axis {
    pub width: usize,
    range: Nanos,
}

impl Axis {
    /// Covers the deadline and every visible bar, with 5% headroom.
    pub fn fit(width: usize, deadline: Nanos, max_offset: Nanos) -> Self {
        let range = Nanos(deadline.0.max(max_offset.0).max(1) * 21 / 20);
        Self { width, range }
    }

    fn cell(&self, offset: Nanos) -> Option<usize> {
        (offset <= self.range)
            .then(|| {
                ((offset.0 as u128 * self.width as u128) / self.range.0.max(1) as u128) as usize
            })
            .filter(|&c| c < self.width)
    }

    /// Spaces up to the bar, at least one bar cell, then padding to the axis
    /// width so the columns after it align. All spaces when the start offset
    /// is unknown (replay clock).
    pub fn bar(&self, start: Option<Nanos>, len: Nanos) -> String {
        let mut out = String::new();
        if let Some(start_cell) = start.and_then(|s| self.cell(s)) {
            let end_cell = start
                .map(|s| s + len)
                .and_then(|e| self.cell(e))
                .unwrap_or(self.width.saturating_sub(1));
            let bar_len = end_cell.saturating_sub(start_cell).max(1);
            out.push_str(&" ".repeat(start_cell));
            out.push_str(&"\u{2588}".repeat(bar_len));
        }
        out.push_str(&" ".repeat(self.width.saturating_sub(out.chars().count())));
        out
    }

    /// Second marks along the axis, `╌` between them; exactly `width` chars,
    /// so a mark that would run past the edge is left off.
    pub fn ticks(&self) -> String {
        let mut labels = String::new();
        for sec in 0.. {
            let Some(cell) = self.cell(Nanos::from_secs(sec)) else {
                break;
            };
            let label = format!("{sec}s");
            if cell + label.len() > self.width {
                break;
            }
            while labels.chars().count() < cell {
                labels.push('\u{254c}');
            }
            labels.push_str(&label);
        }
        while labels.chars().count() < self.width {
            labels.push('\u{254c}');
        }
        labels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 20 cells over 4 s of deadline: 21 cells per 4.2 s, i.e. 210 ms each.
    fn axis() -> Axis {
        Axis::fit(20, Nanos::from_secs(4), Nanos(0))
    }

    #[test]
    fn bars_are_padded_to_the_axis_width() {
        let axis = axis();
        assert_eq!(axis.bar(Some(Nanos(0)), Nanos(0)), format!("\u{2588}{}", " ".repeat(19)));
        assert_eq!(
            axis.bar(Some(Nanos::from_millis(420)), Nanos::from_millis(630)),
            format!("  {}{}", "\u{2588}".repeat(3), " ".repeat(15))
        );
        assert_eq!(
            axis.bar(None, Nanos::from_secs(1)),
            " ".repeat(20),
            "replay clock draws nothing"
        );
    }

    #[test]
    fn bars_past_the_range_run_to_the_edge() {
        let axis = axis();
        let bar = axis.bar(Some(Nanos::from_secs(3)), Nanos::from_secs(9));
        assert_eq!(bar.chars().count(), 20);
        assert_eq!(bar.trim_end(), format!("{}{}", " ".repeat(14), "\u{2588}".repeat(5)));
    }

    #[test]
    fn ticks_fill_the_width() {
        let ticks = axis().ticks();
        assert_eq!(ticks.chars().count(), 20);
        assert!(ticks.starts_with("0s"));
        assert!(!ticks.contains('4'), "4s lands on the last cell and would overflow");

        let wide = Axis::fit(42, Nanos::from_secs(4), Nanos(0)).ticks();
        assert_eq!(wide.chars().count(), 42);
        assert!(wide.ends_with("4s"));
    }
}
