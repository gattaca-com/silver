pub mod counters_pane;
pub mod events;
pub mod flamegraph_pane;
pub mod fmt;
pub mod gossip_pane;
pub mod peers_pane;
pub mod tcaches_pane;
pub mod tiles_pane;
pub mod timings_pane;

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::app::{App, PANES, Pane};

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1), Constraint::Length(1)])
        .split(area);
    draw_header(f, chunks[0], app);
    match app.pane {
        Pane::Counters => counters_pane::draw(f, chunks[1], app),
        Pane::TCaches => tcaches_pane::draw(f, chunks[1], app),
        Pane::Timings => timings_pane::draw(f, chunks[1], app),
        Pane::Tiles => tiles_pane::draw(f, chunks[1], app),
        Pane::Peers => peers_pane::draw(f, chunks[1], app),
        Pane::Gossip => gossip_pane::draw(f, chunks[1], app),
        Pane::Events => app.events.draw(f, chunks[1]),
        Pane::Flamegraph => flamegraph_pane::draw(f, chunks[1], app),
    }
    draw_footer(f, chunks[2], app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let spans: Vec<Span> = PANES
        .iter()
        .flat_map(|&p| {
            let style = if p == app.pane {
                Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            [Span::styled(format!(" {} ", p.label()), style), Span::raw(" ")]
        })
        .collect();
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    if let Some(input) = app.search.input() {
        let prompt = format!("/{input}");
        f.set_cursor_position(Position::new(area.x + prompt.chars().count() as u16, area.y));
        f.render_widget(Paragraph::new(prompt), area);
        return;
    }

    let bold = Style::default().add_modifier(Modifier::BOLD);
    let mut spans = vec![
        Span::styled("TAB", bold),
        Span::raw("/"),
        Span::styled("S-TAB", bold),
        Span::raw(" pane  "),
        Span::styled("↑/↓", bold),
        Span::raw(" select  "),
    ];
    if app.pane == Pane::Flamegraph {
        for (key, action) in [("p", " pause  "), ("c", " clear  ")] {
            spans.push(Span::styled(key, bold));
            spans.push(Span::raw(action));
        }
    } else if app.drilled_in {
        spans.push(Span::styled("Esc", bold));
        spans.push(Span::raw(" close plot  "));
    } else {
        let enter_action = if app.pane == Pane::Events { " expand  " } else { " expand plot  " };
        spans.push(Span::styled("Enter", bold));
        spans.push(Span::raw(enter_action));
        spans.push(Span::styled("[/]", bold));
        spans.push(Span::raw(" resize  "));
    }
    spans.push(Span::styled("/", bold));
    spans.push(Span::raw(" search  "));
    if !app.search.pattern().is_empty() {
        spans.push(Span::styled("n/N", bold));
        spans.push(Span::raw(" next/prev  "));
    }
    spans.push(Span::styled("q", bold));
    spans.push(Span::raw(" quit"));
    if app.search.not_found {
        spans.push(Span::styled(
            format!("   /{} not found", app.search.pattern()),
            Style::default().fg(Color::Red),
        ));
    }

    let dim = Style::default().fg(Color::DarkGray);
    let build_info = Line::from(app.build_info.as_deref().unwrap_or_default());
    let [keys, build] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(build_info.width() as u16 + 1)])
            .areas(area);
    f.render_widget(Paragraph::new(Line::from(spans)).style(dim), keys);
    f.render_widget(Paragraph::new(build_info).style(dim).alignment(Alignment::Right), build);
}
