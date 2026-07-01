//! A fixed-width text table: a header row, a rule, then value rows. Columns
//! auto-size to their widest cell and align per column. Shared by the surfer
//! call-tree pane and the perf report so both read as aligned tables rather
//! than repeating a label on every cell.

pub enum Align {
    Left,
    Right,
}

pub struct Column {
    header: String,
    align: Align,
}

impl Column {
    pub fn left(header: impl Into<String>) -> Self {
        Self { header: header.into(), align: Align::Left }
    }

    pub fn right(header: impl Into<String>) -> Self {
        Self { header: header.into(), align: Align::Right }
    }
}

pub struct Table {
    columns: Vec<Column>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(columns: Vec<Column>) -> Self {
        Self { columns, rows: Vec::new() }
    }

    pub fn row(&mut self, cells: Vec<String>) {
        debug_assert_eq!(cells.len(), self.columns.len(), "row width must match header");
        self.rows.push(cells);
    }

    pub fn render(&self) -> String {
        let widths: Vec<_> = self
            .columns
            .iter()
            .enumerate()
            .map(|(i, c)| {
                self.rows.iter().map(|r| width(&r[i])).chain([width(&c.header)]).max().unwrap_or(0)
            })
            .collect();

        let mut out = String::new();
        let headers: Vec<_> = self.columns.iter().map(|c| c.header.as_str()).collect();
        self.push_row(&mut out, &headers, &widths);
        push_rule(&mut out, &widths);
        for r in &self.rows {
            let cells: Vec<_> = r.iter().map(String::as_str).collect();
            self.push_row(&mut out, &cells, &widths);
        }
        out
    }

    fn push_row(&self, out: &mut String, cells: &[&str], widths: &[usize]) {
        let mut line = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i > 0 {
                line.push_str(GAP);
            }
            let pad = " ".repeat(widths[i].saturating_sub(width(cell)));
            match self.columns[i].align {
                Align::Left => line.push_str(&format!("{cell}{pad}")),
                Align::Right => line.push_str(&format!("{pad}{cell}")),
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
}

const GAP: &str = "  ";

fn push_rule(out: &mut String, widths: &[usize]) {
    let rule: Vec<_> = widths.iter().map(|w| "-".repeat(*w)).collect();
    out.push_str(rule.join(GAP).trim_end());
    out.push('\n');
}

fn width(s: &str) -> usize {
    s.chars().count()
}

#[cfg(test)]
mod tests {
    use super::{Column, Table};

    #[test]
    fn aligns_columns_and_rule_under_headers() {
        let mut t = Table::new(vec![Column::left("name"), Column::right("value")]);
        t.row(vec!["a".into(), "1".into()]);
        t.row(vec!["longer".into(), "1000".into()]);
        let out = t.render();
        let lines: Vec<_> = out.lines().collect();

        assert_eq!(lines[0], "name    value");
        assert_eq!(lines[1], "------  -----");
        // Left column pads right; right column pads left to the widest cell.
        assert_eq!(lines[2], "a           1");
        assert_eq!(lines[3], "longer   1000");
    }
}
