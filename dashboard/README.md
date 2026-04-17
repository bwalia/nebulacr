# NebulaCR Dashboard

A React + Vite + TypeScript SPA for browsing scan results, filtering
vulnerabilities, and watching live scan progress over WebSocket.

## Develop

```bash
cd dashboard
npm install
npm run dev
```

The Vite dev server runs on `http://localhost:5173` and proxies `/v2` and
`/admin` (including the `/v2/ws/scan/:digest` upgrade) to the local
registry + scanner at `http://localhost:5000`.

## Build

```bash
npm run build
```

Outputs static assets under `dist/` — serve behind the same origin as the
scanner so auth headers travel on every request.

## Routes

- `/` — API-key bar + CVE search
- `/scan/:digest` — scan drill-down with severity filter + live progress
  over `/v2/ws/scan/:digest`

Auth: paste a scanner API key (`nck_…`) into the top-right field. It stays
in memory only — refresh the page and you re-enter it, by design.
