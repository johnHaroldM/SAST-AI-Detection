import { forwardRef, useCallback, useEffect, useRef, useState } from 'react';
import { Link, router } from '@inertiajs/react';
import axios from 'axios';
import AppLayout from '../../layouts/AppLayout';
import SeverityBadge from '../../components/SeverityBadge';

/**
 * The labelling queue.
 *
 * Optimised for judging many findings quickly and consistently:
 *  - grouped by rule, so one set of criteria is held in mind at a time
 *  - keyboard-first (J/K to move, T/F to label, U to undo)
 *  - code context inline, so no clicking to see what is being judged
 *  - guidance for the current rule always on screen
 *
 * Decisions POST straight to the triage API with optimistic local state, the
 * same approach the per-scan view uses, because a full round-trip per label
 * makes a 200-item queue unbearable.
 */
export default function TriageQueue({
  findings,
  breakdown,
  focusedRule,
  projects,
  readiness,
  guidance,
  filters,
}) {
  const [rows, setRows] = useState(findings.data);
  const [cursor, setCursor] = useState(0);
  const [history, setHistory] = useState([]);
  const [saving, setSaving] = useState(false);
  const rowRefs = useRef([]);

  useEffect(() => {
    setRows(findings.data);
    setCursor(0);
    setHistory([]);
  }, [findings]);

  const pending = rows.filter((r) => !r.final_label);
  const labelledHere = rows.length - pending.length;

  const current = rows[cursor];
  const activeGuidance = current ? guidance[current.cwe_id ?? 'unknown'] : null;

  const label = useCallback(
    async (finding, value) => {
      if (!finding || finding.final_label) return;

      setRows((prev) =>
        prev.map((r) => (r.id === finding.id ? { ...r, final_label: value } : r))
      );
      setHistory((prev) => [...prev, finding.id]);
      setCursor((c) => Math.min(c + 1, rows.length - 1));
      setSaving(true);

      try {
        await axios.post(`/api/findings/${finding.id}/triage`, { corrected_label: value });
      } catch {
        // Roll the optimistic update back so the queue never claims a label
        // the server did not accept.
        setRows((prev) =>
          prev.map((r) => (r.id === finding.id ? { ...r, final_label: null } : r))
        );
        setHistory((prev) => prev.filter((id) => id !== finding.id));
      } finally {
        setSaving(false);
      }
    },
    [rows.length]
  );

  const undo = useCallback(async () => {
    const lastId = history[history.length - 1];
    if (!lastId) return;

    setHistory((prev) => prev.slice(0, -1));
    setRows((prev) => prev.map((r) => (r.id === lastId ? { ...r, final_label: null } : r)));

    const index = rows.findIndex((r) => r.id === lastId);
    if (index >= 0) setCursor(index);

    try {
      await axios.delete(`/api/findings/${lastId}/triage`);
    } catch {
      // Server kept the label — put it back rather than showing a queue that
      // disagrees with the database.
      setRows((prev) => prev.map((r) => (r.id === lastId ? { ...r, final_label: 'unknown' } : r)));
    }
  }, [history, rows]);

  useEffect(() => {
    function onKey(event) {
      if (event.target.matches('input, select, textarea')) return;

      const key = event.key.toLowerCase();
      const handlers = {
        j: () => setCursor((c) => Math.min(c + 1, rows.length - 1)),
        k: () => setCursor((c) => Math.max(c - 1, 0)),
        arrowdown: () => setCursor((c) => Math.min(c + 1, rows.length - 1)),
        arrowup: () => setCursor((c) => Math.max(c - 1, 0)),
        t: () => label(rows[cursor], 'true_positive'),
        f: () => label(rows[cursor], 'false_positive'),
        u: () => undo(),
      };

      if (handlers[key]) {
        event.preventDefault();
        handlers[key]();
      }
    }

    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [rows, cursor, label, undo]);

  useEffect(() => {
    rowRefs.current[cursor]?.scrollIntoView({ block: 'nearest' });
  }, [cursor]);

  function focusRule(ruleId) {
    router.get('/triage', { ...filters, rule: ruleId }, { preserveState: false, preserveScroll: true });
  }

  function labelAllVisible(value) {
    const targets = pending.slice();
    if (targets.length === 0) return;
    if (!window.confirm(`Mark all ${targets.length} findings on this page as ${value.replace('_', ' ')}?`)) return;

    setRows((prev) => prev.map((r) => (r.final_label ? r : { ...r, final_label: value })));

    axios.post('/api/findings/bulk-triage', {
      decisions: targets.map((t) => ({ finding_id: t.id, corrected_label: value })),
    });
  }

  return (
    <AppLayout title="Triage queue">
      <ReadinessBar readiness={readiness} justLabelled={labelledHere} />

      <div className="mt-6 grid gap-6 lg:grid-cols-[240px_minmax(0,1fr)]">
        <aside className="space-y-4">
          <RuleList breakdown={breakdown} focusedRule={focusedRule} onSelect={focusRule} />
          <ProjectFilter projects={projects} filters={filters} focusedRule={focusedRule} />
          <ShortcutLegend />
        </aside>

        <div className="min-w-0">
          {activeGuidance && <GuidancePanel guidance={activeGuidance} />}

          <div className="mb-3 mt-4 flex items-center justify-between">
            <div className="font-mono text-xs text-fog">
              {pending.length} left on this page · {findings.total} total unlabelled
              {saving && <span className="ml-2 text-amber">saving…</span>}
            </div>
            {pending.length > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-fog">Whole page:</span>
                <button
                  onClick={() => labelAllVisible('false_positive')}
                  className="rounded border border-signal-green/40 px-2.5 py-1 text-xs font-medium text-signal-green hover:bg-signal-green/10"
                >
                  All false positive
                </button>
                <button
                  onClick={() => labelAllVisible('true_positive')}
                  className="rounded border border-signal-red/40 px-2.5 py-1 text-xs font-medium text-signal-red hover:bg-signal-red/10"
                >
                  All true positive
                </button>
              </div>
            )}
          </div>

          <div className="overflow-hidden rounded-lg border border-hairline">
            {rows.length === 0 ? (
              <div className="py-16 text-center text-sm text-fog">
                Nothing left in this filter — pick another rule on the left.
              </div>
            ) : (
              rows.map((finding, index) => (
                <FindingCard
                  key={finding.id}
                  ref={(el) => (rowRefs.current[index] = el)}
                  finding={finding}
                  active={index === cursor}
                  onFocus={() => setCursor(index)}
                  onLabel={(value) => label(finding, value)}
                />
              ))
            )}
          </div>

          <Pagination links={findings.links} />
        </div>
      </div>
    </AppLayout>
  );
}

function ReadinessBar({ readiness, justLabelled }) {
  const total = readiness.total + justLabelled;
  const pct = Math.min(100, Math.round((total / Math.max(1, readiness.required)) * 100));
  const ready = total >= readiness.required && readiness.true_positive > 0 && readiness.false_positive > 0;

  return (
    <div className="rounded-lg border border-hairline bg-panel p-5">
      <div className="flex items-baseline justify-between">
        <div className="kicker">Labels toward training</div>
        <div className="font-mono text-xs text-fog">
          {total} / {readiness.required}
        </div>
      </div>

      <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-ink">
        <div
          className={`h-full rounded-full transition-all ${ready ? 'bg-signal-green' : 'bg-amber'}`}
          style={{ width: `${pct}%` }}
        />
      </div>

      <div className="mt-3 flex gap-6 font-mono text-xs text-fog">
        <span className="text-signal-red">{readiness.true_positive} true positive</span>
        <span className="text-signal-green">{readiness.false_positive} false positive</span>
        {ready ? (
          <span className="text-signal-green">— ready to train</span>
        ) : (
          <span>— both classes required</span>
        )}
      </div>
    </div>
  );
}

function RuleList({ breakdown, focusedRule, onSelect }) {
  return (
    <div className="rounded-lg border border-hairline bg-panel p-3">
      <div className="kicker mb-2 px-1">Rules pending</div>
      <div className="space-y-0.5">
        {breakdown.map((rule) => {
          const active = rule.rule_id === focusedRule;
          const short = rule.rule_id.split('.').pop();

          return (
            <button
              key={rule.rule_id}
              onClick={() => onSelect(rule.rule_id)}
              className={`flex w-full items-center justify-between rounded px-2 py-1.5 text-left text-xs transition-colors ${
                active ? 'bg-panel-raised text-paper' : 'text-fog hover:bg-panel-raised/60 hover:text-paper'
              }`}
            >
              <span className="truncate" title={rule.rule_id}>
                {short}
              </span>
              <span className="ml-2 font-mono tabular-nums">{rule.pending}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function ProjectFilter({ projects, filters, focusedRule }) {
  return (
    <div className="rounded-lg border border-hairline bg-panel p-3">
      <div className="kicker mb-2 px-1">Project</div>
      <select
        value={filters.project ?? ''}
        onChange={(e) =>
          router.get('/triage', {
            rule: focusedRule,
            project: e.target.value || undefined,
            severity: filters.severity || undefined,
          })
        }
        className="w-full rounded border border-hairline bg-ink px-2 py-1.5 text-xs text-paper"
      >
        <option value="">All projects</option>
        {projects.map((p) => (
          <option key={p.id} value={p.id}>
            {p.name}
          </option>
        ))}
      </select>
    </div>
  );
}

function ShortcutLegend() {
  const keys = [
    ['J / ↓', 'next'],
    ['K / ↑', 'previous'],
    ['T', 'true positive'],
    ['F', 'false positive'],
    ['U', 'undo last'],
  ];

  return (
    <div className="rounded-lg border border-hairline bg-panel p-3">
      <div className="kicker mb-2 px-1">Keyboard</div>
      <dl className="space-y-1 px-1">
        {keys.map(([key, meaning]) => (
          <div key={key} className="flex items-center justify-between text-[11px]">
            <dt className="font-mono text-paper">{key}</dt>
            <dd className="text-fog">{meaning}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function GuidancePanel({ guidance }) {
  const [showFix, setShowFix] = useState(false);

  return (
    <div className="rounded-lg border border-hairline bg-panel/60 p-4">
      <div className="mb-2 flex items-center justify-between">
        <div className="kicker">{guidance.title} — how to judge</div>
        <button
          onClick={() => setShowFix((v) => !v)}
          className="rounded border border-hairline px-2 py-0.5 text-[11px] text-fog hover:border-amber/50 hover:text-amber"
        >
          {showFix ? 'Hide' : 'What is the risk & how do I fix it?'}
        </button>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded border border-signal-red/30 bg-signal-red/5 p-2.5">
          <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-signal-red">True positive</div>
          <p className="text-xs leading-relaxed text-fog">{guidance.truePositive}</p>
        </div>
        <div className="rounded border border-signal-green/30 bg-signal-green/5 p-2.5">
          <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-signal-green">False positive</div>
          <p className="text-xs leading-relaxed text-fog">{guidance.falsePositive}</p>
        </div>
      </div>

      {showFix && <RemediationPanel guidance={guidance} />}
    </div>
  );
}

/**
 * The "so what do I do about it" half: impact, the fix, and a concrete
 * before/after. Collapsed by default — once a reviewer knows a rule they
 * want the queue, not the lecture.
 */
function RemediationPanel({ guidance }) {
  return (
    <div className="mt-3 space-y-3 border-t border-hairline pt-3">
      <div>
        <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-amber">What an attacker gains</div>
        <p className="text-xs leading-relaxed text-fog">{guidance.risk}</p>
      </div>

      <div>
        <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-signal-green">How to fix it</div>
        <p className="text-xs leading-relaxed text-fog">{guidance.fix}</p>
      </div>

      {guidance.vulnerable && (
        <div className="grid gap-2 md:grid-cols-2">
          <div>
            <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-signal-red">Vulnerable</div>
            <pre className="overflow-x-auto rounded border border-signal-red/30 bg-ink px-3 py-2 font-mono text-[11px] text-fog">
              {guidance.vulnerable}
            </pre>
          </div>
          <div>
            <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-signal-green">Secure</div>
            <pre className="overflow-x-auto rounded border border-signal-green/30 bg-ink px-3 py-2 font-mono text-[11px] text-fog">
              {guidance.secure}
            </pre>
          </div>
        </div>
      )}

      {guidance.reference && (
        <a
          href={guidance.reference}
          target="_blank"
          rel="noreferrer noopener"
          className="inline-block font-mono text-[11px] text-amber hover:underline"
        >
          Reference ↗
        </a>
      )}
    </div>
  );
}

function directoryOf(path) {
  const parts = String(path ?? '').split('/');
  parts.pop();
  return parts.join('/') || '.';
}

function fileOf(path) {
  return String(path ?? '').split('/').pop();
}

const FindingCard = forwardRef(function FindingCard({ finding, active, onFocus, onLabel }, ref) {
  const done = Boolean(finding.final_label);

  return (
    <div
      ref={ref}
      onClick={onFocus}
      className={`border-t border-hairline first:border-t-0 px-4 py-3 transition-colors ${
        active ? 'bg-panel-raised/70' : ''
      } ${done ? 'opacity-45' : 'cursor-pointer'}`}
    >
      <div className="flex items-start gap-3">
        <div className={`mt-1 h-4 w-0.5 shrink-0 rounded ${active ? 'bg-amber' : 'bg-transparent'}`} />

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <span className="truncate text-sm text-paper">{finding.message}</span>
          </div>

          <div className="mt-1 flex flex-wrap items-center gap-x-1.5 font-mono text-[11px]">
            {/* Several registered projects share paths like
                app/Http/Controllers/FormController.php, so the project has to
                be visually distinct from the path, not just prefixed to it. */}
            <span className="rounded bg-amber/15 px-1.5 py-0.5 text-amber">
              {finding.scan?.project?.name ?? 'unknown'}
            </span>
            <span className="truncate text-fog/70">{directoryOf(finding.file_path)}</span>
            <span className="text-fog/40">/</span>
            <span className="text-paper">{fileOf(finding.file_path)}</span>
            <span className="text-fog/40">:</span>
            <span className="text-amber">{finding.line_number}</span>
            {finding.cwe_id && <span className="ml-1 text-fog/60">CWE-{finding.cwe_id}</span>}
          </div>

          {finding.raw_snippet && (
            <pre className="mt-2 overflow-x-auto rounded border border-hairline bg-ink px-3 py-2 font-mono text-[11px] text-fog">
              {finding.raw_snippet}
            </pre>
          )}
        </div>

        <div className="flex w-64 shrink-0 items-center justify-end gap-1.5">
          <Link
            href={`/findings/${finding.id}`}
            onClick={(e) => e.stopPropagation()}
            className="rounded border border-hairline px-2 py-1 text-[11px] text-fog hover:border-amber/50 hover:text-amber"
            title="Full report: what, why, and the exact change to make"
          >
            Explain
          </Link>

          {done ? (
            <span className="font-mono text-[11px] text-fog">
              {finding.final_label === 'true_positive' ? 'true positive' : 'false positive'}
            </span>
          ) : (
            <>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onLabel('true_positive');
                }}
                className="rounded border border-signal-red/40 px-2.5 py-1 text-xs font-medium text-signal-red hover:bg-signal-red/10"
              >
                True <span className="opacity-60">T</span>
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onLabel('false_positive');
                }}
                className="rounded border border-signal-green/40 px-2.5 py-1 text-xs font-medium text-signal-green hover:bg-signal-green/10"
              >
                False <span className="opacity-60">F</span>
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
});

function Pagination({ links }) {
  if (!links || links.length <= 3) return null;

  return (
    <div className="mt-4 flex flex-wrap gap-1">
      {links.map((link, i) => (
        <button
          key={i}
          disabled={!link.url}
          onClick={() => link.url && router.get(link.url)}
          className={`rounded px-2.5 py-1 text-xs ${
            link.active
              ? 'bg-panel-raised text-paper'
              : link.url
                ? 'text-fog hover:bg-panel-raised/60 hover:text-paper'
                : 'text-fog/30'
          }`}
          dangerouslySetInnerHTML={{ __html: link.label }}
        />
      ))}
    </div>
  );
}
