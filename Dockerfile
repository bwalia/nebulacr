# ============================================================================
# NebulaCR Multi-Stage Dockerfile
# Builds both nebula-auth and nebula-registry binaries in a single image.
# ============================================================================

# ── Builder stage ────────────────────────────────────────────────────────────

FROM rust:1.94-bookworm AS builder

WORKDIR /build

# Cache dependency compilation: copy manifests first, then build a dummy
# project so that changing application source does not invalidate the
# dependency layer.
COPY Cargo.toml Cargo.lock ./
COPY crates/nebula-common/Cargo.toml      crates/nebula-common/Cargo.toml
COPY crates/nebula-auth/Cargo.toml        crates/nebula-auth/Cargo.toml
COPY crates/nebula-registry/Cargo.toml    crates/nebula-registry/Cargo.toml
COPY crates/nebula-controller/Cargo.toml  crates/nebula-controller/Cargo.toml
COPY crates/nebula-resilience/Cargo.toml  crates/nebula-resilience/Cargo.toml
COPY crates/nebula-mirror/Cargo.toml      crates/nebula-mirror/Cargo.toml
COPY crates/nebula-replication/Cargo.toml crates/nebula-replication/Cargo.toml
COPY crates/nebula-db/Cargo.toml          crates/nebula-db/Cargo.toml
COPY crates/nebula-ai/Cargo.toml          crates/nebula-ai/Cargo.toml
COPY crates/nebula-scanner/Cargo.toml     crates/nebula-scanner/Cargo.toml

# Create stub source files so Cargo can resolve the workspace
RUN mkdir -p crates/nebula-common/src      && echo "pub fn _stub(){}" > crates/nebula-common/src/lib.rs \
 && mkdir -p crates/nebula-auth/src        && echo "fn main(){}" > crates/nebula-auth/src/main.rs \
 && mkdir -p crates/nebula-registry/src    && echo "fn main(){}" > crates/nebula-registry/src/main.rs \
 && mkdir -p crates/nebula-controller/src  && echo "fn main(){}" > crates/nebula-controller/src/main.rs \
 && mkdir -p crates/nebula-resilience/src  && echo "pub fn _stub(){}" > crates/nebula-resilience/src/lib.rs \
 && mkdir -p crates/nebula-mirror/src      && echo "pub fn _stub(){}" > crates/nebula-mirror/src/lib.rs \
 && mkdir -p crates/nebula-replication/src && echo "pub fn _stub(){}" > crates/nebula-replication/src/lib.rs \
 && mkdir -p crates/nebula-db/src          && echo "pub fn _stub(){}" > crates/nebula-db/src/lib.rs \
 && mkdir -p crates/nebula-ai/src          && echo "pub fn _stub(){}" > crates/nebula-ai/src/lib.rs \
 && mkdir -p crates/nebula-scanner/src     && echo "pub fn _stub(){}" > crates/nebula-scanner/src/lib.rs \
 && mkdir -p crates/nebula-scanner/src/bin && echo "fn main(){}" > crates/nebula-scanner/src/bin/nebula-scanner.rs

# Build dependencies only (this layer is cached unless Cargo.toml/lock change)
RUN cargo build --release --workspace 2>&1 || true

# Remove the stub artifacts so the real source gets compiled
RUN rm -rf crates/nebula-common/src crates/nebula-auth/src crates/nebula-registry/src \
    crates/nebula-controller/src crates/nebula-resilience/src crates/nebula-mirror/src \
    crates/nebula-replication/src crates/nebula-db/src crates/nebula-ai/src \
    crates/nebula-scanner/src \
 && rm -rf target/release/.fingerprint/nebula-*

# Copy the actual source code
COPY crates/ crates/

# Build the real binaries (embed git SHA as build hash)
ARG NEBULACR_BUILD_HASH=dev
ENV NEBULACR_BUILD_HASH=${NEBULACR_BUILD_HASH}
RUN cargo build --release --bin nebula-auth --bin nebula-registry --bin nebula-scanner

# ── Runtime stage ────────────────────────────────────────────────────────────

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 10001 nebulacr \
 && useradd --uid 10001 --gid nebulacr --shell /sbin/nologin --create-home nebulacr

# Create directories for data, config, and keys
RUN mkdir -p /var/lib/nebulacr/data \
             /etc/nebulacr/keys \
 && chown -R nebulacr:nebulacr /var/lib/nebulacr /etc/nebulacr

# Copy binaries from the builder stage
COPY --from=builder /build/target/release/nebula-auth     /usr/local/bin/nebula-auth
COPY --from=builder /build/target/release/nebula-registry /usr/local/bin/nebula-registry
COPY --from=builder /build/target/release/nebula-scanner  /usr/local/bin/nebula-scanner

# Ensure binaries are executable
RUN chmod +x /usr/local/bin/nebula-auth /usr/local/bin/nebula-registry /usr/local/bin/nebula-scanner

# Switch to non-root user
USER nebulacr

# Expose ports:
#   5000 - OCI Registry API (Docker Registry HTTP API V2)
#   5001 - Auth / Token service
#   9090 - Prometheus metrics
EXPOSE 5000 5001 9090

# Health check: probe the registry health endpoint every 30 seconds
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/nebula-registry", "--health-check"] || exit 1

# Use tini as PID 1 for proper signal handling
ENTRYPOINT ["tini", "--"]

# Default: run the registry service. Override with nebula-auth to run auth.
CMD ["nebula-registry"]
