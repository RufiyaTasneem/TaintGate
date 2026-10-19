
import { useEffect, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Activity,
  RefreshCw,
  CircleCheck,
  CircleX,
  FileText,
  Clock3,
} from "lucide-react";
import "./App.css";

const API = "http://127.0.0.1:8000";

function App() {
  const [summary, setSummary] = useState({
    total_decisions: 0,
    allowed: 0,
    blocked: 0,
  });
  const [decisions, setDecisions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("ALL");
  const [reasonFilter, setReasonFilter] = useState("ALL");
  async function refreshData() {
    setLoading(true);
    setError("");

    try {
      const [summaryResponse, decisionsResponse] = await Promise.all([
        fetch(`${API}/api/summary`),
        fetch(`${API}/api/decisions?limit=50`),
      ]);

      if (!summaryResponse.ok || !decisionsResponse.ok) {
        throw new Error("The API returned an error.");
      }

      const summaryData = await summaryResponse.json();
      const decisionsData = await decisionsResponse.json();

      setSummary(summaryData);
      setDecisions(decisionsData);
    } catch {
      setError(
        "Cannot connect to TaintGate API. Check that the backend is running."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refreshData();
  }, []);
  const reasonCodes = [
    ...new Set(
      decisions.map((item) => item.reason_code || "LEGACY")
    ),
  ].sort();

  const filteredDecisions = decisions.filter((item) => {
    const term = search.trim().toLowerCase();

    const searchableText = [
      item.tool,
      item.reason,
      item.reason_code,
      ...(item.sources || []),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();

    const matchesSearch =
      !term || searchableText.includes(term);

    const matchesDecision =
      decisionFilter === "ALL" ||
      item.decision === decisionFilter;

    const matchesReason =
      reasonFilter === "ALL" ||
      (item.reason_code || "LEGACY") === reasonFilter;

    return matchesSearch && matchesDecision && matchesReason;
  });
  const blockRate = summary.total_decisions
    ? Math.round((summary.blocked / summary.total_decisions) * 100)
    : 0;

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={23} />
          </div>
          <div>
            <h1>TaintGate</h1>
            <p>SECURITY GATEWAY</p>
          </div>
        </div>

        <div className="nav-label">MONITORING</div>
        <div className="nav-item active">
          <Activity size={18} />
          <span>Overview</span>
        </div>
        <div className="nav-item">
          <ShieldAlert size={18} />
          <span>Security decisions</span>
        </div>
        <div className="nav-item">
          <FileText size={18} />
          <span>Provenance & audit</span>
        </div>

        <div className="sidebar-bottom">
          <span className="status-dot" />
          <div>
            <strong>Gateway API</strong>
            <p>Local environment</p>
          </div>
        </div>
      </aside>

      <section className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY CENTER / OVERVIEW</p>
            <h2>Security overview</h2>
            <p className="subtitle">
              Monitor tool calls, policy enforcement, and untrusted data.
            </p>
          </div>

          <button
            className="refresh-button"
            onClick={refreshData}
            disabled={loading}
          >
            <RefreshCw size={16} className={loading ? "spin" : ""} />
            {loading ? "Refreshing..." : "Refresh data"}
          </button>
        </header>

        {error && <div className="error-banner">{error}</div>}

        <div className="status-banner">
          <div className="status-icon">
            <ShieldCheck size={21} />
          </div>
          <div>
            <strong>TaintGate monitoring is active</strong>
            <p>Audit records are loaded from your local API.</p>
          </div>
          <span className="live-label">
            <span className="status-dot" /> LOCAL
          </span>
        </div>

        <section className="stats-grid">
          <article className="stat-card">
            <div className="stat-heading">
              Total decisions <Activity size={18} />
            </div>
            <strong className="stat-number">{summary.total_decisions}</strong>
            <p>Recorded audit events</p>
          </article>

          <article className="stat-card allowed-card">
            <div className="stat-heading">
              Allowed <CircleCheck size={18} />
            </div>
            <strong className="stat-number">{summary.allowed}</strong>
            <p>Calls that passed policy checks</p>
          </article>

          <article className="stat-card blocked-card">
            <div className="stat-heading">
              Blocked <CircleX size={18} />
            </div>
            <strong className="stat-number">{summary.blocked}</strong>
            <p>Calls rejected by security checks</p>
          </article>

          <article className="stat-card">
            <div className="stat-heading">
              Block rate <ShieldAlert size={18} />
            </div>
            <strong className="stat-number">{blockRate}%</strong>
            <p>Of all recorded decisions</p>
          </article>
        </section>

        <section className="activity-panel">
          <div className="panel-heading">
            <div>
              <h3>Recent security decisions</h3>
              <p>Latest audit records, newest first</p>
            </div>
            <span className="record-count">
              {filteredDecisions.length} of {decisions.length} records
            </span>
          </div>
          <div className="filters-row">
            <input
              type="search"
              placeholder="Search tool, source, or reason..."
              aria-label="Search security decisions"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />

            <select
              aria-label="Filter by decision"
              value={decisionFilter}
              onChange={(event) => setDecisionFilter(event.target.value)}
            >
              <option value="ALL">All decisions</option>
              <option value="BLOCKED">Blocked</option>
              <option value="ALLOWED">Allowed</option>
            </select>

            <select
              aria-label="Filter by reason code"
              value={reasonFilter}
              onChange={(event) => setReasonFilter(event.target.value)}
            >
              <option value="ALL">All reason codes</option>
              {reasonCodes.map((code) => (
                <option key={code} value={code}>
                  {code}
                </option>
              ))}
            </select>


            <button
              type="button"
              className="clear-filters"
              onClick={() => {
                console.log("Clear button clicked");
                setSearch("");
                setDecisionFilter("ALL");
                setReasonFilter("ALL");
              }}
            >
              Clear
            </button>

          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>DECISION</th>
                  <th>TOOL</th>
                  <th>REASON CODE</th>
                  <th>SOURCES</th>
                  <th>TIME (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {filteredDecisions.map((item, index) => (
                  <tr key={`${item.timestamp}-${index}`}>
                    <td>
                      <span
                        className={`decision-pill ${item.decision === "BLOCKED"
                          ? "blocked-pill"
                          : item.decision === "ALLOWED"
                            ? "allowed-pill"
                            : ""
                          }`}
                      >
                        {item.decision === "BLOCKED" ? (
                          <CircleX size={14} />
                        ) : (
                          <CircleCheck size={14} />
                        )}
                        {item.decision || "UNKNOWN"}
                      </span>
                    </td>
                    <td className="tool-name">{item.tool || "—"}</td>
                    <td>
                      <span className="reason-code">
                        {item.reason_code || "LEGACY"}
                      </span>
                      <p className="reason-text">{item.reason || ""}</p>
                    </td>
                    <td>
                      {(item.sources || []).length ? (
                        item.sources.map((source) => (
                          <span className="source-tag" key={source}>
                            <FileText size={12} />
                            {source}
                          </span>
                        ))
                      ) : (
                        <span className="muted">No source recorded</span>
                      )}
                    </td>
                    <td className="time-cell">
                      <Clock3 size={13} />
                      {item.timestamp
                        ? new Date(item.timestamp).toLocaleString()
                        : "—"}
                    </td>
                  </tr>
                ))}
                {!filteredDecisions.length && !loading && (
                  <tr>
                    <td colSpan="5" className="empty-state">
                      No matching security decisions found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <footer>
          <span>TaintGate · Local security monitoring</span>
          <span>Data source: FastAPI audit API</span>
        </footer>
      </section>
    </main>
  );
}

export default App;
