import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getApiKey, searchCves, setApiKey, CveHit } from './api';

// Home view: API-key prompt + live CVE search box that the operator can
// use to sanity-check the own-DB population. Scan drill-down moves to
// /scan/{digest} so links can be shared as-is.
export function App() {
  const [key, setKey] = useState(getApiKey() || '');
  const [query, setQuery] = useState('');
  const [hits, setHits] = useState<CveHit[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setApiKey(key);
  }, [key]);

  async function runSearch(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      const resp = await searchCves({ q: query, limit: '25' });
      setHits(resp.results);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main>
      <header className="topbar">
        <h1>NebulaCR</h1>
        <input
          type="password"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="API key (nck_…)"
          aria-label="API key"
        />
      </header>

      <section>
        <form onSubmit={runSearch}>
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="CVE search: keyword, package, or id"
          />
          <button type="submit" disabled={loading}>
            Search
          </button>
        </form>

        <ul className="results">
          {hits.map((h) => (
            <li key={h.id}>
              <code>{h.id}</code>
              <span className={`sev ${(h.severity || 'unknown').toLowerCase()}`}>
                {h.severity || 'UNK'}
              </span>
              <span>{h.summary}</span>
              <div className="affected">
                {h.affected.slice(0, 3).map((a, i) => (
                  <span key={i}>
                    <code>{a.ecosystem}:{a.package}</code>
                    {a.fixed ? ` → ${a.fixed}` : ''}
                  </span>
                ))}
              </div>
            </li>
          ))}
        </ul>
      </section>

      <footer>
        <p>
          Scan drill-down: open <Link to="/scan/sha256:…">/scan/&lt;digest&gt;</Link> to
          watch a live scan over WebSocket.
        </p>
      </footer>
    </main>
  );
}
