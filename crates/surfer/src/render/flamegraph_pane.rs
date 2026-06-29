use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::App;

pub fn draw(f: &mut Frame, area: Rect, app: &App) {
    let fg = &app.flamegraph;
    let block = block(fg.missed(), fg.paused(), fg.last_export());

    if !fg.is_attached() {
        f.render_widget(
            Paragraph::new(
                "waiting for a running silver — no pid published in this app's shmem dir yet",
            )
            .style(Style::default().fg(Color::DarkGray))
            .block(block),
            area,
        );
        return;
    }

    if fg.tree().is_empty() {
        f.render_widget(
            Paragraph::new("attached — folding marks…")
                .style(Style::default().fg(Color::DarkGray))
                .block(block),
            area,
        );
        return;
    }

    f.render_widget(Paragraph::new(fg.tree()).block(block).scroll((fg.scroll(), 0)), area);
}

fn block(missed: bool, paused: bool, export: Option<&str>) -> Block<'static> {
    let mut spans = if missed {
        vec![Span::styled(
            " Flamegraph (cumulative) — EVENTS LOST: producer outran the reader ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )]
    } else if paused {
        vec![Span::styled(
            " Flamegraph (cumulative) — PAUSED (p resume · c clear) ",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )]
    } else {
        vec![Span::raw(" Flamegraph (cumulative) — p pause · e export · c clear ")]
    };
    if let Some(note) = export {
        spans.push(Span::styled(format!("· {note} "), Style::default().fg(Color::DarkGray)));
    }
    Block::default().borders(Borders::ALL).title(Line::from(spans))
}
