use silver_metrics::flamegraph_timer::FlamegraphReader;

pub struct Flamegraph {
    reader: Option<FlamegraphReader>,
    tree: String,
    scroll: u16,
    /// When set, stop polling/folding so the tree holds still for reading — a
    /// live producer otherwise keeps growing the cumulative tree every tick.
    paused: bool,
    /// Outcome of the last `e` export, shown in the header until the next one.
    last_export: Option<String>,
}

impl Flamegraph {
    pub fn attach(app_name: &str) -> Self {
        Self {
            reader: FlamegraphReader::attach(app_name),
            tree: String::new(),
            scroll: 0,
            paused: false,
            last_export: None,
        }
    }

    pub fn sample(&mut self) {
        if self.paused {
            return;
        }
        if let Some(reader) = &mut self.reader {
            reader.poll();
        }
    }

    pub fn roll_bucket(&mut self) {
        if self.paused {
            return;
        }
        if let Some(reader) = &self.reader {
            self.tree = reader.stats().call_tree();
        }
    }

    pub fn scroll_by(&mut self, dir: i32) {
        self.scroll = self.scroll.saturating_add_signed(dir as i16);
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    /// `e`: dump the whole retained run to a Fuchsia FXT trace in the cwd, to
    /// open at https://magic-trace.org (shows real wall-clock time per slice).
    pub fn export_trace(&mut self) {
        let Some(reader) = &self.reader else { return };
        let path = format!("silver-trace-{}.fxt", reader.pid());
        self.last_export = Some(match std::fs::write(&path, reader.export_trace()) {
            Ok(()) => format!("exported → {path}"),
            Err(e) => format!("export failed: {e}"),
        });
    }

    pub fn last_export(&self) -> Option<&str> {
        self.last_export.as_deref()
    }

    /// Drop the accumulator and start a fresh cumulative window from now —
    /// sheds one-time boot frames so steady-state stands out.
    pub fn clear(&mut self, app_name: &str) {
        self.reattach(app_name);
        self.paused = false;
    }

    /// Reattach when a fresh pid is published — surfer started before the
    /// producer, or the producer restarted with a new pid and new rings.
    pub fn reattach_if_restarted(&mut self, app_name: &str) {
        if let Some(pid) = FlamegraphReader::published_pid(app_name) {
            if self.reader.as_ref().map(FlamegraphReader::pid) != Some(pid) {
                self.reattach(app_name);
            }
        }
    }

    fn reattach(&mut self, app_name: &str) {
        self.reader = FlamegraphReader::attach(app_name);
        self.tree.clear();
        self.scroll = 0;
    }

    pub fn is_attached(&self) -> bool {
        self.reader.is_some()
    }

    pub fn tree(&self) -> &str {
        &self.tree
    }

    pub fn paused(&self) -> bool {
        self.paused
    }

    pub fn scroll(&self) -> u16 {
        self.scroll
    }
}
