//! Terminal metrics viewer for silver. Reads `counters-*`,
//! `timing-*`, `tilemetrics-*` files from flux's shmem queues
//! directory — `{base_dir}/{app_name}/shmem/queues/` — and renders
//! them in a ratatui-based TUI.
//!
//! Usage: `surfer [BASE_DIR] [APP_NAME]`.
//! Defaults: `BASE_DIR = flux::utils::directories::local_share_dir()`
//! (Linux: `$XDG_DATA_HOME`, default `~/.local/share`),
//! `APP_NAME = silver`.

use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

mod app;
mod discovery;
mod render;
mod schema;
mod sources;

use crate::{
    app::App,
    sources::{counters::CounterSet, tilemetrics::TileMetricsSet, timings::TimingSet},
};

const TICK: Duration = Duration::from_millis(100);
const BUCKET: Duration = Duration::from_secs(sources::counters::BUCKET_SECS);

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let base_dir =
        args.next().map(PathBuf::from).unwrap_or_else(flux::utils::directories::local_share_dir);
    let app_name = args.next().unwrap_or_else(|| "silver".to_string());

    let sources = discovery::discover(&base_dir, &app_name)?;
    let mut counter_sets: Vec<CounterSet> = sources
        .counters
        .iter()
        .filter_map(|f| match CounterSet::open(f) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("surfer: skipping {}: {e}", f.path.display());
                None
            }
        })
        .collect();
    for c in &mut counter_sets {
        c.sample();
    }

    let mut timing_sets: Vec<TimingSet> = sources
        .timings
        .iter()
        .filter_map(|f| match TimingSet::open(f) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("surfer: skipping {}: {e}", f.path.display());
                None
            }
        })
        .collect();
    for t in &mut timing_sets {
        t.drain();
    }

    let mut tile_sets: Vec<TileMetricsSet> = sources
        .tilemetrics
        .iter()
        .filter_map(|f| match TileMetricsSet::open(f) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("surfer: skipping {}: {e}", f.path.display());
                None
            }
        })
        .collect();
    for t in &mut tile_sets {
        t.drain();
    }
    let mut app = App::new(counter_sets, timing_sets, tile_sets);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let result = run(&mut term, &mut app);

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;

    result
}

fn run<B: ratatui::backend::Backend>(term: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    let mut last_tick = Instant::now();
    let mut last_bucket = Instant::now();
    loop {
        term.draw(|f| render::draw(f, app))?;

        let timeout = TICK.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    handle_key(app, key.code);
                }
            }
        }
        if last_tick.elapsed() >= TICK {
            app.sample();
            last_tick = Instant::now();
        }
        if last_bucket.elapsed() >= BUCKET {
            app.roll_bucket();
            last_bucket = Instant::now();
        }
        if app.quit {
            return Ok(());
        }
    }
}

fn handle_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('q') => app.quit = true,
        KeyCode::Esc | KeyCode::Backspace if app.drilled_in => app.drilled_in = false,
        KeyCode::Enter => app.drilled_in = !app.drilled_in,
        KeyCode::Tab => {
            app.pane = app.pane.next();
            app.drilled_in = false;
        }
        KeyCode::Down => app.move_selection(1),
        KeyCode::Up => app.move_selection(-1),
        KeyCode::Char('[') => app.adjust_split(-1),
        KeyCode::Char(']') => app.adjust_split(1),
        _ => {}
    }
}
