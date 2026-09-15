use crossterm::event::KeyCode;

/// Vim-style `/` search over the active pane's rows.
#[derive(Default)]
pub struct Search {
    /// The prompt's text while it is open.
    input: Option<String>,
    pattern: String,
    pub not_found: bool,
}

impl Search {
    pub fn open(&mut self) {
        self.input = Some(String::new());
        self.not_found = false;
    }

    pub fn is_open(&self) -> bool {
        self.input.is_some()
    }

    pub fn input(&self) -> Option<&str> {
        self.input.as_deref()
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Feeds a key to the open prompt; true when Enter submitted it. An empty
    /// submission repeats the previous pattern, as in vim.
    pub fn type_key(&mut self, code: KeyCode) -> bool {
        let Some(input) = &mut self.input else { return false };
        match code {
            KeyCode::Char(c) => input.push(c),
            KeyCode::Backspace => {
                input.pop();
            }
            KeyCode::Esc => self.input = None,
            KeyCode::Enter => {
                let input = self.input.take().unwrap_or_default();
                if !input.is_empty() {
                    self.pattern = input;
                }
                return true;
            }
            _ => {}
        }
        false
    }

    /// Position of the first matching row stepping `dir` from `from`,
    /// wrapping around; `from` itself is the last row tried.
    pub fn find(&mut self, rows: &[String], from: usize, dir: i32) -> Option<usize> {
        let n = rows.len() as i64;
        let hit = (1..=n)
            .map(|k| (from as i64 + dir as i64 * k).rem_euclid(n) as usize)
            .find(|&i| self.matches(&rows[i]));
        self.not_found = hit.is_none() && !self.pattern.is_empty();
        hit
    }

    /// Case-insensitive unless the pattern has an uppercase letter, like
    /// vim's `smartcase`.
    fn matches(&self, row: &str) -> bool {
        if self.pattern.is_empty() {
            return false;
        }
        if self.pattern.chars().any(char::is_uppercase) {
            row.contains(&self.pattern)
        } else {
            row.to_lowercase().contains(&self.pattern)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn typed(text: &str) -> Search {
        let mut search = Search::default();
        search.open();
        for c in text.chars() {
            search.type_key(KeyCode::Char(c));
        }
        assert!(search.type_key(KeyCode::Enter));
        search
    }

    #[test]
    fn searches_forward_from_the_row_after_the_selection_and_wraps() {
        let rows = rows(&["gossip", "stf", "gossip cols", "el"]);
        let mut search = typed("gossip");
        assert_eq!(search.find(&rows, 0, 1), Some(2));
        assert_eq!(search.find(&rows, 2, 1), Some(0));
        assert_eq!(search.find(&rows, 0, -1), Some(2));
        assert!(!search.not_found);
    }

    #[test]
    fn a_lone_match_is_found_from_itself() {
        let rows = rows(&["a", "b"]);
        let mut search = typed("b");
        assert_eq!(search.find(&rows, 1, 1), Some(1));
    }

    #[test]
    fn smartcase() {
        let rows = rows(&["Gossip", "gossip"]);
        assert_eq!(typed("gossip").find(&rows, 1, 1), Some(0));
        assert_eq!(typed("Gossip").find(&rows, 1, 1), Some(0));
        assert_eq!(typed("Gossip").find(&rows, 0, 1), Some(0), "wraps past the lowercase row");
    }

    #[test]
    fn a_miss_is_reported_and_an_empty_pattern_is_not() {
        let rows = rows(&["a"]);
        let mut search = typed("zzz");
        assert_eq!(search.find(&rows, 0, 1), None);
        assert!(search.not_found);

        let mut search = Search::default();
        assert_eq!(search.find(&rows, 0, 1), None);
        assert!(!search.not_found);
        assert_eq!(search.find(&[], 0, 1), None);
    }

    #[test]
    fn the_prompt_edits_and_cancels() {
        let mut search = Search::default();
        assert!(!search.type_key(KeyCode::Char('x')), "closed prompt ignores keys");
        search.open();
        search.type_key(KeyCode::Char('a'));
        search.type_key(KeyCode::Char('b'));
        search.type_key(KeyCode::Backspace);
        assert_eq!(search.input(), Some("a"));
        search.type_key(KeyCode::Esc);
        assert!(!search.is_open());
        assert_eq!(search.pattern(), "", "cancelling keeps the old pattern");
    }

    #[test]
    fn an_empty_submission_repeats_the_last_pattern() {
        let mut search = typed("stf");
        search.open();
        assert!(search.type_key(KeyCode::Enter));
        assert_eq!(search.pattern(), "stf");
    }
}
