pub mod counters_pane;
pub mod flamegraph_pane;
pub mod fmt;
pub mod tcaches_pane;
pub mod tiles_pane;
pub mod timings_pane;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
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
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let mut spans = vec![
        Span::styled("TAB", bold),
        Span::raw(" pane  "),
        Span::styled("↑/↓", bold),
        Span::raw(" select  "),
    ];
    if app.drilled_in {
        spans.push(Span::styled("Esc", bold));
        spans.push(Span::raw(" close plot  "));
    } else {
        spans.push(Span::styled("Enter", bold));
        spans.push(Span::raw(" expand plot  "));
        spans.push(Span::styled("[/]", bold));
        spans.push(Span::raw(" resize  "));
    }
    spans.push(Span::styled("q", bold));
    spans.push(Span::raw(" quit"));
    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().fg(Color::DarkGray)),
        area,
    );
}
