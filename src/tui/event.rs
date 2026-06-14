use crossterm::event::{Event, EventStream, KeyEvent};
use futures::StreamExt;
use std::time::Duration;

#[derive(Debug)]
pub enum AppEvent {
    Tick,
    Key(KeyEvent),
    Resize,
}

pub async fn next_event(stream: &mut EventStream, tick_ms: u64) -> Option<AppEvent> {
    let timeout = tokio::time::sleep(Duration::from_millis(tick_ms));
    tokio::select! {
        _ = timeout => Some(AppEvent::Tick),
        maybe_ev = stream.next() => {
            match maybe_ev? {
                Ok(Event::Key(k)) => Some(AppEvent::Key(k)),
                Ok(Event::Resize(..)) => Some(AppEvent::Resize),
                _ => None,
            }
        }
    }
}
