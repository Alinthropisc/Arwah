use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{BarChart, Block, Borders, List, ListItem},
};

use crate::tui::app::AppState;

pub fn draw(f: &mut Frame, state: &AppState, area: Rect) {
    let snap = state.session.snapshot();

    let halves = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Left: top talkers list.
    let items: Vec<ListItem> = snap
        .top_talkers
        .iter()
        .enumerate()
        .map(|(i, (ip, bytes))| {
            ListItem::new(format!("  {:>2}. {:>40}  {:>10}B", i + 1, ip, bytes))
        })
        .collect();

    let talkers = List::new(items)
        .block(
            Block::default()
                .title(" Top Talkers ")
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(talkers, halves[0]);

    // Right: protocol distribution bar chart.
    let bar_data: Vec<(String, u64)> = snap
        .proto_dist
        .iter()
        .map(|(p, c)| (format!("{p:?}"), *c))
        .collect();

    let bar_refs: Vec<(&str, u64)> = bar_data.iter().map(|(l, v)| (l.as_str(), *v)).collect();

    let chart = BarChart::default()
        .block(
            Block::default()
                .title(" Protocol Distribution ")
                .borders(Borders::ALL),
        )
        .data(&bar_refs)
        .bar_width(8)
        .bar_gap(2)
        .bar_style(Style::default().fg(Color::Green))
        .value_style(Style::default().fg(Color::Black).bg(Color::Green));
    f.render_widget(chart, halves[1]);
}
