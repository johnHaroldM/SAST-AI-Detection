import { useState, useMemo } from 'react';
import { router } from '@inertiajs/react';
import axios from 'axios';
import AppLayout from '../../Layouts/AppLayout';
import SeverityBadge from '../../Components/SeverityBadge';
import ConfidenceSignal from '../../Components/ConfidenceSignal';

const FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'pending', label: 'Pending' },
  { key: 'true_positive', label: 'Predicted TP' },
  { key: 'false_positive', label: 'Predicted FP' },
];

/**
 * props.scan: the Scan model with count aggregates (see ScanController::show)
 * props.findings: paginated Finding[] from ScanController::findings, each with .rule
 *
 * Triage decisions POST directly to the existing JSON API
 * (TriageController@store / @bulkStore) with optimistic local state updates,
 * rather than a full Inertia round-trip — keeps the review flow snappy
 * when working through a long queue.
 */
export default function ScanShow({ scan, findings: initialFindings }) {
  const [findings, setFindings] = useState(initialFindings.data);
  const [filter, setFilter] = useState('pending');
  const [selected, setSelected] = useState(new Set());
  const [expandedId, setExpandedId] = useState(null);

  const visible = useMemo(() => {
    if (filter === 'all') return findings;
    if (filter === 'pending') return findings.filter((f) => f.status === 'pending');
    return findings.filter((f) => f.predicted_label === filter);
  }, [findings, filter]);

  async function triageSingle(finding, correctedLabel) {
    setFindings((prev) =>
      prev.map((f) => (f.id === finding.id ? { ...f, status: 'triaged', final_label: correctedLabel } : f))
    );
    await axios.post(`/api/findings/${finding.id}/triage`, { corrected_label: correctedLabel });
  }

  async function triageBulk(correctedLabel) {
    const ids = [...selected];
    if (ids.length === 0) return;

    setFindings((prev) =>
      prev.map((f) => (ids.includes(f.id) ? { ...f, status: 'triaged', final_label: correctedLabel } : f))
    );
    setSelected(new Set());

    await axios.post('/api/findings/bulk-triage', {
      decisions: ids.map((id) => ({ finding_id: id, corrected_label: correctedLabel })),
    });
  }

  function toggleSelected(id) {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  return (
    <AppLayout title={`Scan ${scan.commit_sha.slice(0, 7)} · ${scan.branch}`}>
      <StatStrip scan={scan} />

      <div className="flex items-center justify-between mt-6 mb-3">
        <div className="flex gap-1 p-0.5 bg-panel rounded-md border border-hairline w-fit">
          {FILTERS.map((f) => (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                filter === f.key ? 'bg-panel-raised text-paper' : 'text-fog hover:text-paper'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        {selected.size > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-fog font-mono">{selected.size} selected</span>
            <button
              onClick={() => triageBulk('true_positive')}
              className="px-3 py-1.5 rounded text-xs font-medium border border-signal-red/40 text-signal-red hover:bg-signal-red/10"
            >
              Confirm true positive
            </button>
            <button
              onClick={() => triageBulk('false_positive')}
              className="px-3 py-1.5 rounded text-xs font-medium border border-signal-green/40 text-signal-green hover:bg-signal-green/10"
            >
              Mark false positive
            </button>
          </div>
        )}
      </div>

      <div className="border border-hairline rounded-lg overflow-hidden">
        {visible.length === 0 ? (
          <div className="py-14 text-center text-sm text-fog">Nothing in this filter — queue's clear.</div>
        ) : (
          visible.map((finding) => (
            <FindingRow
              key={finding.id}
              finding={finding}
              expanded={expandedId === finding.id}
              selected={selected.has(finding.id)}
              onToggleExpand={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
              onToggleSelect={() => toggleSelected(finding.id)}
              onTriage={(label) => triageSingle(finding, label)}
            />
          ))
        )}
      </div>
    </AppLayout>
  );
}

function StatStrip({ scan }) {
  const stats = [
    { label: 'Total findings', value: scan.findings_count },
    { label: 'Predicted TP', value: scan.true_positive_count, tone: 'text-signal-red' },
    { label: 'Predicted FP', value: scan.false_positive_count, tone: 'text-signal-green' },
    { label: 'Pending triage', value: scan.pending_triage_count, tone: 'text-amber' },
    { label: 'Auto-suppressed', value: scan.suppressed_count },
  ];

  return (
    <div className="grid grid-cols-5 gap-px bg-hairline border border-hairline rounded-lg overflow-hidden">
      {stats.map((s) => (
        <div key={s.label} className="bg-panel px-4 py-3">
          <div className="kicker">{s.label}</div>
          <div className={`font-display text-2xl font-semibold mt-1 tabular-nums ${s.tone ?? 'text-paper'}`}>
            {s.value ?? 0}
          </div>
        </div>
      ))}
    </div>
  );
}

function FindingRow({ finding, expanded, selected, onToggleExpand, onToggleSelect, onTriage }) {
  const isTriaged = finding.status === 'triaged';

  return (
    <div className={`border-t border-hairline first:border-t-0 ${isTriaged ? 'opacity-50' : ''}`}>
      <div className="flex items-center gap-3 px-4 py-3">
        <input
          type="checkbox"
          checked={selected}
          onChange={onToggleSelect}
          disabled={isTriaged}
          className="accent-amber"
        />

        <button onClick={onToggleExpand} className="flex-1 min-w-0 flex items-center gap-3 text-left">
          <SeverityBadge severity={finding.severity} />
          <div className="min-w-0">
            <div className="text-sm text-paper truncate">{finding.message}</div>
            <div className="font-mono text-[11px] text-fog truncate">
              {finding.file_path}:{finding.line_number} · {finding.rule?.external_id} · CWE-{finding.cwe_id}
            </div>
          </div>
        </button>

        <ConfidenceSignal probability={finding.tp_probability} label={finding.predicted_label} />

        <div className="flex items-center gap-1.5 w-56 justify-end">
          {isTriaged ? (
            <span className="font-mono text-[11px] text-fog">
              confirmed · {finding.final_label === 'true_positive' ? 'TP' : 'FP'}
            </span>
          ) : (
            <>
              <button
                onClick={() => onTriage('true_positive')}
                className="px-2.5 py-1 rounded text-xs font-medium border border-signal-red/40 text-signal-red hover:bg-signal-red/10"
              >
                True positive
              </button>
              <button
                onClick={() => onTriage('false_positive')}
                className="px-2.5 py-1 rounded text-xs font-medium border border-signal-green/40 text-signal-green hover:bg-signal-green/10"
              >
                False positive
              </button>
            </>
          )}
        </div>
      </div>

      {expanded && finding.raw_snippet && (
        <pre className="mx-4 mb-3 px-3 py-2.5 bg-ink border border-hairline rounded font-mono text-xs text-fog overflow-x-auto">
          {finding.raw_snippet}
        </pre>
      )}
    </div>
  );
}
