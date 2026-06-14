use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use super::{
    app::{AppState, View},
    widgets,
};

pub fn draw(f: &mut Frame, state: &AppState) {
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(0),    // body
            Constraint::Length(1), // status bar
        ])
        .split(area);

    draw_header(f, state, chunks[0]);
    match state.view {
        View::Dashboard => widgets::dashboard::draw(f, state, chunks[1]),
        View::Flows => widgets::flows::draw(f, state, chunks[1]),
        View::Packets => widgets::packets::draw(f, state, chunks[1]),
        View::Help => draw_help(f, chunks[1]),
    }
    draw_statusbar(f, state, chunks[2]);
}

fn draw_header(f: &mut Frame, state: &AppState, area: ratatui::layout::Rect) {
    let snap = state.session.snapshot();
    let title = format!(
        " B579-Arwah  │  pkts: {}  bytes: {}  flows: {} ",
        snap.total_packets,
        humanize_bytes(snap.total_bytes),
        state.session.active_flows().len(),
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    let para = Paragraph::new(title).block(block);
    f.render_widget(para, area);
}

fn draw_statusbar(f: &mut Frame, state: &AppState, area: ratatui::layout::Rect) {
    let tabs = Line::from(vec![
        nav_tab("[1] Dashboard", state.view == View::Dashboard),
        Span::raw("  "),
        nav_tab("[2] Flows", state.view == View::Flows),
        Span::raw("  "),
        nav_tab("[3] Packets", state.view == View::Packets),
        Span::raw("  "),
        nav_tab("[?] Help", state.view == View::Help),
        Span::raw("  "),
        Span::styled("[q] Quit", Style::default().fg(Color::Red)),
    ]);
    f.render_widget(Paragraph::new(tabs), area);
}

fn draw_help(f: &mut Frame, area: ratatui::layout::Rect) {
    let text = vec![
        Line::from("B579-Arwah — Keyboard Shortcuts"),
        Line::from(""),
        Line::from("  1          → Dashboard view"),
        Line::from("  2          → Active flows"),
        Line::from("  3          → Packet stream"),
        Line::from("  q / Ctrl-C → Quit"),
        Line::from("  ?          → This help"),
    ];
    let block = Block::default().title(" Help ").borders(Borders::ALL);
    let para = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn nav_tab(label: &str, active: bool) -> Span<'_> {
    if active {
        Span::styled(label, Style::default().fg(Color::Black).bg(Color::Cyan))
    } else {
        Span::styled(label, Style::default().fg(Color::DarkGray))
    }
}

fn humanize_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if b >= GB {
        format!("{:.1}G", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.1}M", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.1}K", b as f64 / KB as f64)
    } else {
        format!("{b}B")
    }
}
