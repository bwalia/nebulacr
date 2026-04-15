//! Scan-job queue abstraction.
//!
//! First implementation: in-process Tokio mpsc. Future (NATS/Kafka)
//! implementations slot in behind the same trait; the rest of the pipeline
//! never calls the concrete queue directly.

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};

use crate::model::ScanJob;

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("queue closed")]
    Closed,
    #[error("queue full")]
    Full,
}

#[async_trait]
pub trait Queue: Send + Sync {
    async fn enqueue(&self, job: ScanJob) -> Result<(), QueueError>;
    async fn dequeue(&self) -> Option<ScanJob>;
}

pub struct TokioQueue {
    tx: mpsc::Sender<ScanJob>,
    rx: Mutex<mpsc::Receiver<ScanJob>>,
}

impl TokioQueue {
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            tx,
            rx: Mutex::new(rx),
        }
    }

    /// Producer handle suitable for cloning into webhook subscribers.
    pub fn sender(&self) -> mpsc::Sender<ScanJob> {
        self.tx.clone()
    }
}

#[async_trait]
impl Queue for TokioQueue {
    async fn enqueue(&self, job: ScanJob) -> Result<(), QueueError> {
        self.tx.send(job).await.map_err(|_| QueueError::Closed)
    }

    async fn dequeue(&self) -> Option<ScanJob> {
        let mut rx = self.rx.lock().await;
        rx.recv().await
    }
}
