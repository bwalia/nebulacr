//! WebSocket endpoint for live scan progress.
//!
//! Clients (the dashboard SPA, a dev CLI) connect to
//! `/v2/ws/scan/{digest}` and receive a JSON frame every time the backing
//! Redis record changes. We poll at 500ms — cheap for a single-key GET, and
//! the ephemeral store already caps worst-case traffic via TTL. Stream
//! closes when the scan reaches a terminal state (`completed` or `failed`),
//! or after an idle ceiling so stuck connections don't leak.

use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::Response;
use futures::SinkExt;
use serde::Serialize;
use tracing::{debug, warn};

use crate::api::ScannerState;
use crate::model::{ScanResult, ScanStatus};

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_LIFETIME: Duration = Duration::from_secs(600);

pub async fn progress_ws(
    ws: WebSocketUpgrade,
    State(state): State<ScannerState>,
    Path(digest): Path<String>,
) -> Response {
    ws.on_upgrade(move |socket| progress_loop(socket, state, digest))
}

#[derive(Serialize)]
struct ProgressFrame<'a> {
    status: &'a str,
    result: Option<&'a ScanResult>,
}

async fn progress_loop(mut socket: WebSocket, state: ScannerState, digest: String) {
    let deadline = tokio::time::Instant::now() + MAX_LIFETIME;
    let mut last_status = String::new();

    loop {
        if tokio::time::Instant::now() >= deadline {
            let _ = socket
                .send(Message::Text("{\"status\":\"timeout\"}".into()))
                .await;
            break;
        }
        match state.store.get(&digest).await {
            Ok(Some(result)) => {
                let status_label = status_str(&result.status);
                if status_label != last_status {
                    let frame = ProgressFrame {
                        status: status_label,
                        result: Some(&result),
                    };
                    let msg = serde_json::to_string(&frame).unwrap_or_else(|_| "{}".into());
                    if socket.send(Message::Text(msg.into())).await.is_err() {
                        debug!("client disconnected from progress ws");
                        break;
                    }
                    last_status = status_label.to_string();
                }
                if matches!(result.status, ScanStatus::Completed | ScanStatus::Failed) {
                    break;
                }
            }
            Ok(None) => {
                if last_status.is_empty() {
                    let _ = socket
                        .send(Message::Text("{\"status\":\"not_found\"}".into()))
                        .await;
                    last_status = "not_found".into();
                }
            }
            Err(e) => {
                warn!(error = %e, "redis read failed in progress ws");
            }
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    let _ = socket.close().await;
}

fn status_str(s: &ScanStatus) -> &'static str {
    match s {
        ScanStatus::Queued => "queued",
        ScanStatus::InProgress => "in_progress",
        ScanStatus::Completed => "completed",
        ScanStatus::Failed => "failed",
    }
}
