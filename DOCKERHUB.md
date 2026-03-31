# NebulaCR

A cloud-native Docker/OCI container registry built in Rust with multi-tenancy, zero-trust authentication, and pull-through caching.

## Quick Start

```bash
docker run -d -p 5000:5000 bwalia/nebulacr:latest
```

Then push an image:

```bash
docker tag nginx:latest localhost:5000/myorg/nginx:latest
docker push localhost:5000/myorg/nginx:latest
```

## Key Features

- **OCI Distribution API v2** compliant
- **Pull-through cache** for Docker Hub, GHCR, GCR, Quay.io, registry.k8s.io
- **Multi-tenancy** with Tenant, Project, and AccessPolicy CRDs
- **Zero-trust auth** via OIDC (Google, GitHub Actions, GitLab CI, Azure AD)
- **Multiple storage backends** -- filesystem, S3, GCS, Azure Blob
- **High availability** -- stateless services, HPA, circuit breakers
- **Multi-region replication** with async/semi-sync modes
- **Observability** -- Prometheus metrics, JSON logging, OpenTelemetry tracing
- **Multi-architecture** -- linux/amd64 and linux/arm64

## Image Tags

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release |
| `vX.Y.Z` | Specific version |
| `edge` | Latest development build from main |

## Docker Compose

```yaml
services:
  registry:
    image: bwalia/nebulacr:latest
    command: ["nebula-registry"]
    ports:
      - "5000:5000"
      - "9090:9090"
    environment:
      NEBULACR_STORAGE__BACKEND: filesystem
      NEBULACR_STORAGE__ROOT: /var/lib/nebulacr/data
      NEBULACR_AUTH__VERIFICATION_KEY_PATH: /etc/nebulacr/keys/public.pem
    volumes:
      - registry-data:/var/lib/nebulacr/data
```

See the full [docker-compose.yml](https://github.com/bwalia/nebulacr/blob/main/docker-compose.yml) for a complete setup with auth and key generation.

## Kubernetes (Helm)

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --namespace nebulacr --create-namespace
```

## Ports

| Port | Service |
|------|---------|
| 5000 | OCI Registry API |
| 5001 | Auth / Token service |
| 9090 | Prometheus metrics |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NEBULACR_STORAGE__BACKEND` | `filesystem` | Storage backend (`filesystem`, `s3`, `gcs`, `azure`) |
| `NEBULACR_STORAGE__ROOT` | `/var/lib/nebulacr/data` | Filesystem storage root |
| `NEBULACR_SERVER__LISTEN_ADDR` | `0.0.0.0:5000` | Registry listen address |
| `NEBULACR_AUTH__VERIFICATION_KEY_PATH` | -- | Path to JWT public key |
| `RUST_LOG` | `info` | Log level |

## Links

- [GitHub Repository](https://github.com/bwalia/nebulacr)
- [Documentation](https://github.com/bwalia/nebulacr/tree/main/docs)
- [Helm Chart](https://github.com/bwalia/nebulacr/tree/main/deploy/helm/nebulacr)

## License

Apache-2.0
