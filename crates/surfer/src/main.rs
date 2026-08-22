//! Terminal metrics viewer for silver. Reads `counters-*`,
//! `latency-*`, `tilemetrics-*` files from flux's shmem
//! queues directory — `{base_dir}/{app_name}/shmem/queues/` — and
//! renders them in a ratatui-based TUI. `#[timed]` perf counters are
//! folded into the flamegraph pane, not surfaced as a separate source.
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
mod flamegraph;
mod render;
mod schema;
mod sources;

use crate::{
    app::App,
    flamegraph::Flamegraph,
    render::events_pane::EventsPane,
    sources::{
        counters::CounterSet,
        events::{MAINNET_GENESIS_UNIX_SECS, MAINNET_SLOT_MS},
        tilemetrics::TileMetricsSet,
        timings::TimingSet,
    },
};

const TICK: Duration = Duration::from_millis(100);
const BUCKET: Duration = Duration::from_secs(sources::counters::BUCKET_SECS);
/// How often to rescan the discovery directory for new sources.
/// Insertion-only — existing handles never close mid-run.
const DISCOVER: Duration = Duration::from_secs(10);

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

    let mut tcache_sets: Vec<CounterSet> = sources
        .tcaches
        .iter()
        .filter_map(|f| match CounterSet::open(f) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("surfer: skipping {}: {e}", f.path.display());
                None
            }
        })
        .collect();
    for c in &mut tcache_sets {
        c.sample();
    }

    let mut timing_sets: Vec<TimingSet> = sources
        .timings
        .iter()
        .filter_map(|f| match TimingSet::open(f) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("surfer: skipping {}: {e}", f.name);
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

    // Events pane reads the node's spine directly (app name baked in as
    // `silver`, so a custom APP_NAME only affects the file sources above).
    // Slot timing is chain config surfer can't discover — env-overridable.
    let events = EventsPane::open(
        &base_dir,
        env_u64("SURFER_GENESIS_UNIX_SECS", MAINNET_GENESIS_UNIX_SECS),
        env_u64("SURFER_SLOT_MS", MAINNET_SLOT_MS),
    );

    let peers = sources::peers::Peers::open(&base_dir);

    let flamegraph = Flamegraph::attach(&app_name);
    let mut app =
        App::new(counter_sets, tcache_sets, timing_sets, tile_sets, peers, events, flamegraph);

    // Restore the terminal before the panic message prints, else it lands
    // on top of the raw-mode alternate screen and leaves the shell broken.
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        default_panic(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let result = run(&mut term, &mut app, &base_dir, &app_name);

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;

    result
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn run<B: ratatui::backend::Backend>(
    term: &mut Terminal<B>,
    app: &mut App,
    base_dir: &std::path::Path,
    app_name: &str,
) -> io::Result<()> {
    let mut last_tick = Instant::now();
    let mut last_bucket = Instant::now();
    let mut last_discover = Instant::now();
    loop {
        term.draw(|f| render::draw(f, app))?;

        let timeout = TICK.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    handle_key(app, key.code, app_name);
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
        if last_discover.elapsed() >= DISCOVER {
            if let Ok(s) = discovery::discover(base_dir, app_name) {
                app.merge_new_sources(s);
            }
            app.flamegraph.reattach_if_restarted(app_name);
            last_discover = Instant::now();
        }
        if app.quit {
            return Ok(());
        }
    }
}

fn handle_key(app: &mut App, code: KeyCode, app_name: &str) {
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
        KeyCode::Left if app.pane == app::Pane::Peers => app.adjust_peers_sort(-1),
        KeyCode::Right if app.pane == app::Pane::Peers => app.adjust_peers_sort(1),
        KeyCode::Char('r') if app.pane == app::Pane::Peers => {
            app.peers_sort_desc = !app.peers_sort_desc
        }
        KeyCode::Char('t') if app.pane == app::Pane::Peers => app.select_top_peer(),
        KeyCode::Char('[') => app.adjust_split(-1),
        KeyCode::Char(']') => app.adjust_split(1),
        KeyCode::Char('p') => app.flamegraph.toggle_pause(),
        KeyCode::Char('c') => app.flamegraph.clear(app_name),
        _ => {}
    }
}
