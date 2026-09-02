use silver_common::Nanos;

use super::theme::Symbols;

/// The shared time scale: into-slot nanoseconds → axis cells.
pub struct Axis {
    pub width: usize,
    range: Nanos,
    bar: char,
    tick: char,
}

impl Axis {
    pub fn fit(width: usize, deadline: Nanos, max_offset: Nanos, symbols: Symbols) -> Self {
        let range = Nanos(deadline.0.max(max_offset.0).max(1) * 105 / 100);
        Self { width, range, bar: symbols.bar, tick: symbols.tick }
    }

    fn cell(&self, offset: Nanos) -> Option<usize> {
        let cell = (offset.0 as u128 * self.width as u128 / self.range.0 as u128) as usize;
        (cell < self.width).then_some(cell)
    }

    /// At least one bar cell, padded to `width` so later columns align.
    pub fn bar(&self, start: Option<Nanos>, len: Nanos) -> String {
        let Some(start) = start else {
            return " ".repeat(self.width);
        };
        let mut out = String::new();
        if let Some(start_cell) = self.cell(start) {
            let end_cell = self.cell(start + len).unwrap_or(self.width.saturating_sub(1));
            let bar_len = end_cell.saturating_sub(start_cell).max(1);
            out.push_str(&" ".repeat(start_cell));
            out.extend(std::iter::repeat_n(self.bar, bar_len));
        }
        out.push_str(&" ".repeat(self.width.saturating_sub(out.chars().count())));
        out
    }

    /// Second marks along the axis; exactly `width` chars, so a mark that
    /// would run past the edge is left off.
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
                labels.push(self.tick);
            }
            labels.push_str(&label);
        }
        while labels.chars().count() < self.width {
            labels.push(self.tick);
        }
        labels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 20 cells over 4 s of deadline: 21 cells per 4.2 s, i.e. 210 ms each.
    fn axis() -> Axis {
        Axis::fit(20, Nanos::from_secs(4), Nanos(0), Symbols::default())
    }

    #[test]
    fn bars_are_padded_to_the_axis_width() {
        let axis = axis();
        assert_eq!(axis.bar(Some(Nanos(0)), Nanos(0)), format!("█{}", " ".repeat(19)));
        assert_eq!(
            axis.bar(Some(Nanos::from_millis(420)), Nanos::from_millis(630)),
            format!("  {}{}", "█".repeat(3), " ".repeat(15))
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
        assert_eq!(bar.trim_end(), format!("{}{}", " ".repeat(14), "█".repeat(5)));
    }

    #[test]
    fn ticks_fill_the_width() {
        let ticks = axis().ticks();
        assert_eq!(ticks.chars().count(), 20);
        assert!(ticks.starts_with("0s"));
        assert!(!ticks.contains('4'), "4s lands on the last cell and would overflow");

        let wide = Axis::fit(42, Nanos::from_secs(4), Nanos(0), Symbols::default()).ticks();
        assert_eq!(wide.chars().count(), 42);
        assert!(wide.ends_with("4s"));
    }
}
