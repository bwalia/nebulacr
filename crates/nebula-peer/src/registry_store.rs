//! Registry-side mesh membership store.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct MeshRow {
    pub id: Uuid,
    pub cluster_name: String,
    pub bootstrap_url: String,
    pub last_heartbeat: DateTime<Utc>,
    pub peer_count: i32,
}

#[derive(Debug, Clone)]
pub struct NodeRow {
    pub id: Uuid,
    pub mesh_id: Uuid,
    pub node_name: String,
    pub libp2p_id: String,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
pub trait PeerMeshStore: Send + Sync {
    async fn upsert_mesh(
        &self,
        cluster_name: &str,
        bootstrap_url: &str,
    ) -> Result<MeshRow, StoreError>;
    async fn list_meshes(&self) -> Result<Vec<MeshRow>, StoreError>;
    async fn upsert_node(
        &self,
        mesh_id: Uuid,
        node_name: &str,
        libp2p_id: &str,
    ) -> Result<NodeRow, StoreError>;
    async fn heartbeat(&self, node_id: Uuid) -> Result<(), StoreError>;
}

pub struct PgPeerMeshStore {
    pool: Pool<Postgres>,
}

impl PgPeerMeshStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PeerMeshStore for PgPeerMeshStore {
    async fn upsert_mesh(
        &self,
        cluster_name: &str,
        bootstrap_url: &str,
    ) -> Result<MeshRow, StoreError> {
        let id = Uuid::new_v4();
        let row: (Uuid, String, String, DateTime<Utc>, i32) = sqlx::query_as(
            "INSERT INTO peer_meshes (id, cluster_name, bootstrap_url)
             VALUES ($1, $2, $3)
             ON CONFLICT (cluster_name) DO UPDATE
             SET bootstrap_url = EXCLUDED.bootstrap_url,
                 last_heartbeat = NOW()
             RETURNING id, cluster_name, bootstrap_url, last_heartbeat, peer_count",
        )
        .bind(id)
        .bind(cluster_name)
        .bind(bootstrap_url)
        .fetch_one(&self.pool)
        .await?;
        Ok(MeshRow {
            id: row.0,
            cluster_name: row.1,
            bootstrap_url: row.2,
            last_heartbeat: row.3,
            peer_count: row.4,
        })
    }

    async fn list_meshes(&self) -> Result<Vec<MeshRow>, StoreError> {
        let rows: Vec<(Uuid, String, String, DateTime<Utc>, i32)> = sqlx::query_as(
            "SELECT id, cluster_name, bootstrap_url, last_heartbeat, peer_count
             FROM peer_meshes ORDER BY cluster_name",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, cn, url, hb, pc)| MeshRow {
                id,
                cluster_name: cn,
                bootstrap_url: url,
                last_heartbeat: hb,
                peer_count: pc,
            })
            .collect())
    }

    async fn upsert_node(
        &self,
        mesh_id: Uuid,
        node_name: &str,
        libp2p_id: &str,
    ) -> Result<NodeRow, StoreError> {
        let id = Uuid::new_v4();
        let row: (Uuid, Uuid, String, String, DateTime<Utc>) = sqlx::query_as(
            "INSERT INTO peer_nodes (id, mesh_id, node_name, libp2p_id)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (mesh_id, node_name) DO UPDATE
             SET libp2p_id = EXCLUDED.libp2p_id,
                 last_seen = NOW()
             RETURNING id, mesh_id, node_name, libp2p_id, last_seen",
        )
        .bind(id)
        .bind(mesh_id)
        .bind(node_name)
        .bind(libp2p_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(NodeRow {
            id: row.0,
            mesh_id: row.1,
            node_name: row.2,
            libp2p_id: row.3,
            last_seen: row.4,
        })
    }

    async fn heartbeat(&self, node_id: Uuid) -> Result<(), StoreError> {
        sqlx::query("UPDATE peer_nodes SET last_seen = NOW() WHERE id = $1")
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
