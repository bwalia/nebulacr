import { useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import { fetchLiveScan, ScanResult, Vulnerability } from './api';

// Drill-down view: subscribes to /v2/ws/scan/{digest}, renders a severity-
// filterable table, and surfaces the policy verdict as a banner. Falls
// back to an HTTP fetch if WebSocket is unavailable in the host runtime.
export function ScanDetail() {
  const { digest = '' } = useParams<{ digest: string }>();
  const [result, setResult] = useState<ScanResult | null>(null);
  const [status, setStatus] = useState<string>('connecting…');
  const [filter, setFilter] = useState<string>('all');

  useEffect(() => {
    let ws: WebSocket | null = null;
    try {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${proto}//${location.host}/v2/ws/scan/${digest}`);
      ws.onmessage = (ev) => {
        try {
          const frame = JSON.parse(ev.data);
          setStatus(frame.status);
          if (frame.result) setResult(frame.result);
        } catch {}
      };
      ws.onerror = () => setStatus('ws error');
      ws.onclose = () => setStatus((s) => (s === 'connecting…' ? 'disconnected' : s));
    } catch {
      fetchLiveScan(digest)
        .then((r) => {
          setStatus(r.status);
          setResult(r.result || null);
        })
        .catch(() => setStatus('fetch failed'));
    }
    return () => {
      if (ws && ws.readyState === WebSocket.OPEN) ws.close();
    };
  }, [digest]);

  const visible: Vulnerability[] = useMemo(() => {
    const vs = result?.vulnerabilities ?? [];
    if (filter === 'all') return vs;
    return vs.filter((v) => v.severity.toLowerCase() === filter);
  }, [result, filter]);

  return (
    <main>
      <header className="topbar">
        <h1>Scan {digest.slice(0, 18)}…</h1>
        <span className={`pill ${status.replace(/\W/g, '_')}`}>{status}</span>
      </header>

      {result?.policy_evaluation && (
        <div className={`verdict verdict-${result.policy_evaluation.status.toLowerCase()}`}>
          {result.policy_evaluation.status}
          {result.policy_evaluation.reason ? ` — ${result.policy_evaluation.reason}` : ''}
        </div>
      )}

      {result && (
        <>
          <section className="summary-pills">
            {(['critical', 'high', 'medium', 'low', 'unknown'] as const).map((k) => (
              <button
                key={k}
                className={`pill sev ${k} ${filter === k ? 'active' : ''}`}
                onClick={() => setFilter(filter === k ? 'all' : k)}
              >
                {k}: {result.summary[k]}
              </button>
            ))}
            <button
              className={`pill ${filter === 'all' ? 'active' : ''}`}
              onClick={() => setFilter('all')}
            >
              all
            </button>
          </section>

          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Severity</th>
                <th>Package</th>
                <th>Installed</th>
                <th>Fixed</th>
                <th>Layer</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((v) => (
                <tr key={`${v.id}-${v.package}`} className={v.suppressed ? 'suppressed' : ''}>
                  <td>
                    <code>{v.id}</code>
                  </td>
                  <td>
                    <span className={`sev ${v.severity.toLowerCase()}`}>{v.severity}</span>
                  </td>
                  <td>{v.package}</td>
                  <td>
                    <code>{v.installed_version}</code>
                  </td>
                  <td>{v.fixed_version ? <code>{v.fixed_version}</code> : '—'}</td>
                  <td>
                    {v.layer_digest ? (
                      <code title={v.layer_digest}>{v.layer_digest.slice(7, 19)}</code>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td>{v.summary || ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </main>
  );
}
