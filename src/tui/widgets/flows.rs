use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Row, Table, TableState},
};

use crate::tui::app::AppState;

pub fn draw(f: &mut Frame, state: &AppState, area: Rect) {
    let mut flows = state.session.active_flows();
    flows.sort_unstable_by(|a, b| b.total_bytes().cmp(&a.total_bytes()));

    let header_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(["SRC", "DST", "PROTO", "BYTES", "PKTS", "STATE"])
        .style(header_style)
        .height(1);

    let rows: Vec<Row> = flows
        .iter()
        .take(50)
        .map(|f| {
            Row::new([
                format!("{}:{}", f.key.src_ip, f.key.src_port),
                format!("{}:{}", f.key.dst_ip, f.key.dst_port),
                format!("{:?}", f.key.protocol),
                f.total_bytes().to_string(),
                f.total_packets().to_string(),
                format!("{:?}", f.state),
            ])
        })
        .collect();

    let widths = [
        ratatui::layout::Constraint::Percentage(27),
        ratatui::layout::Constraint::Percentage(27),
        ratatui::layout::Constraint::Percentage(8),
        ratatui::layout::Constraint::Percentage(12),
        ratatui::layout::Constraint::Percentage(10),
        ratatui::layout::Constraint::Percentage(16),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(" Active Flows ")
                .borders(Borders::ALL),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol("► ");

    let mut ts = TableState::default();
    f.render_stateful_widget(table, area, &mut ts);
}
