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
    let block = block(fg.missed(), fg.paused());

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

fn block(missed: bool, paused: bool) -> Block<'static> {
    let title = if missed {
        Line::from(Span::styled(
            " Flamegraph (cumulative) — EVENTS LOST: producer outran the reader ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ))
    } else if paused {
        Line::from(Span::styled(
            " Flamegraph (cumulative) — PAUSED (p resume · c clear) ",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ))
    } else {
        Line::from(" Flamegraph (cumulative) — p pause · c clear ")
    };
    Block::default().borders(Borders::ALL).title(title)
}
