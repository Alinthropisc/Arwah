use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem},
    Frame,
};

use crate::tui::app::AppState;

pub fn draw(f: &mut Frame, state: &AppState, area: Rect) {
    // Latest flows as a packet proxy (actual per-packet ring buffer to be added).
    let flows = state.session.active_flows();
    let items: Vec<ListItem> = flows
        .iter()
        .take(area.height as usize)
        .map(|fl| {
            let line = Line::from(format!(
                "  {} → {}  {:?}  {} B",
                fl.key.src_ip,
                fl.key.dst_ip,
                fl.key.protocol,
                fl.total_bytes(),
            ));
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Packet Stream ")
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(Color::White));

    f.render_widget(list, area);
}
