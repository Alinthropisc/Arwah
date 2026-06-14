use anyhow::Result;
use arwah_engine::{capture::LiveCapture, session::CaptureSession};
use b579_core::capture::CaptureSource;
use crossterm::{
    event::{EventStream, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{io, sync::Arc};

use super::{event::{AppEvent, next_event}, render};

/// Active TUI view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Dashboard,
    Flows,
    Packets,
    Help,
}

pub struct AppState {
    pub view: View,
    pub session: Arc<CaptureSession>,
    pub should_quit: bool,
    pub tick_ms: u64,
}

/// Launch the full-screen TUI. Runs until the user presses `q` or `Ctrl-C`.
pub fn run(interface: Option<&str>, bpf: Option<&str>, tick_ms: u64) -> Result<()> {
    let iface = resolve_interface(interface)?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut cap = LiveCapture::open(&iface)?;
        if let Some(expr) = bpf {
            cap.set_bpf_filter(expr)?;
        }

        let session = Arc::new(CaptureSession::new());
        let session_bg = session.clone();

        tokio::spawn(async move {
            session_bg.run(Box::new(cap) as Box<dyn CaptureSource>).await;
        });

        run_tui(session, tick_ms).await
    })
}

async fn run_tui(session: Arc<CaptureSession>, tick_ms: u64) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState {
        view: View::Dashboard,
        session,
        should_quit: false,
        tick_ms,
    };

    let mut event_stream = EventStream::new();

    while !state.should_quit {
        terminal.draw(|f| render::draw(f, &state))?;

        if let Some(ev) = next_event(&mut event_stream, state.tick_ms).await {
            handle_event(&mut state, ev);
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn handle_event(state: &mut AppState, ev: AppEvent) {
    match ev {
        AppEvent::Key(k) => match (k.modifiers, k.code) {
            (KeyModifiers::NONE, KeyCode::Char('q'))
            | (KeyModifiers::CONTROL, KeyCode::Char('c')) => {
                state.should_quit = true;
            }
            (KeyModifiers::NONE, KeyCode::Char('1')) => state.view = View::Dashboard,
            (KeyModifiers::NONE, KeyCode::Char('2')) => state.view = View::Flows,
            (KeyModifiers::NONE, KeyCode::Char('3')) => state.view = View::Packets,
            (KeyModifiers::NONE, KeyCode::Char('?')) => state.view = View::Help,
            _ => {}
        },
        _ => {}
    }
}

fn resolve_interface(iface: Option<&str>) -> Result<String> {
    if let Some(i) = iface {
        return Ok(i.to_owned());
    }
    let devices = pcap::Device::list().map_err(|e| anyhow::anyhow!("pcap: {e}"))?;
    devices
        .into_iter()
        .find(|d| d.name != "lo")
        .map(|d| d.name)
        .ok_or_else(|| anyhow::anyhow!("no suitable network interface found"))
}
