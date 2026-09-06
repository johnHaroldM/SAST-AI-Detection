import { useState, useMemo, useEffect, useCallback } from 'react';
import { Link, useForm } from '@inertiajs/react';
import axios from 'axios';
import { ArrowUpRight } from 'lucide-react';
import AppLayout from '../../layouts/AppLayout';
import SeverityBadge from '../../components/SeverityBadge';
import ConfidenceSignal from '../../components/ConfidenceSignal';

const FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'pending', label: 'Pending' },
  { key: 'true_positive', label: 'Predicted TP' },
  { key: 'false_positive', label: 'Predicted FP' },
];

const EMPTY_OUTCOME_MATRIX = {
  true_positive: 0,
  false_positive: 0,
  true_negative: 0,
  false_negative: 0,
  unresolved: 0,
};

const OUTCOME_COLUMNS = [
  { key: 'true_positive', short: 'TP', label: 'True positive', tone: 'text-signal-red' },
  { key: 'false_positive', short: 'FP', label: 'False positive', tone: 'text-signal-green' },
  { key: 'true_negative', short: 'TN', label: 'True negative', tone: 'text-cyan-300' },
  { key: 'false_negative', short: 'FN', label: 'False negative', tone: 'text-amber' },
  { key: 'unresolved', short: '?', label: 'Unresolved', tone: 'text-fog' },
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
export default function ScanShow({ scan, findings: initialFindings, guidance = {}, anino = {} }) {
  const [findings, setFindings] = useState(initialFindings.data);
  const [filter, setFilter] = useState('pending');
  const [selected, setSelected] = useState(new Set());
  const [expandedId, setExpandedId] = useState(null);
  const [aninoStatus, setAninoStatus] = useState(() => ({
    enabled: anino.enabled ?? false,
    total_findings: scan.findings_count ?? 0,
    contexts: scan.ai_context_count ?? 0,
    atake: 0,
    depensa: 0,
    adjudicated: scan.ai_reviewed_count ?? 0,
    outcomes: {
      atake: { ...EMPTY_OUTCOME_MATRIX },
      depensa: { ...EMPTY_OUTCOME_MATRIX },
    },
    retryable_findings: 0,
    training_candidates: 0,
    training_promoted: 0,
    training_threshold: 0.85,
    run: null,
    queue: { ai_analysis: 0, failed_ai_analysis: 0 },
    complete: false,
    logs: [],
  }));
  const { post, processing } = useForm();
  const { post: postTraining, processing: trainingProcessing } = useForm();
  const aninoRunActive = ['queued', 'running', 'running_with_errors'].includes(aninoStatus.run?.status);
  const retryAvailable = (aninoStatus.retryable_findings ?? 0) > 0;

  const fetchAninoStatus = useCallback(async () => {
    if (!anino.enabled) return;

    const response = await axios.get(`/api/scans/${scan.id}/anino-status`);
    setAninoStatus(response.data);
  }, [anino.enabled, scan.id]);

  useEffect(() => {
    fetchAninoStatus();

    if (!anino.enabled || aninoStatus.complete) return undefined;

    const timer = window.setInterval(fetchAninoStatus, 5000);

    return () => window.clearInterval(timer);
  }, [anino.enabled, aninoStatus.complete, fetchAninoStatus]);

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

      <div className="mt-4 rounded-lg border border-hairline bg-panel px-4 py-3">
        <div>
          <div className="text-sm font-semibold text-paper">ATAKE / DEPENSA review</div>
          <div className="mt-1 font-mono text-[11px] text-fog">
            {anino.enabled
              ? `${scan.ai_reviewed_count ?? 0}/${scan.ai_context_count ?? 0} findings reviewed · ${anino.atake_model} / ${anino.depensa_model}`
              : 'Disabled · set ANINO_AI_ENABLED=true to queue reviews'}
          </div>
        </div>

        <button
          type="button"
          disabled={!anino.enabled || processing || aninoRunActive || (scan.findings_count ?? 0) === 0}
          onClick={() =>
            post(`/scans/${scan.id}/anino-analysis`, {
              preserveScroll: true,
              onSuccess: fetchAninoStatus,
            })
          }
          className="px-3 py-1.5 rounded text-xs font-medium border border-amber/50 text-amber hover:bg-amber/10 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {processing
            ? 'Queueing...'
            : aninoRunActive
              ? 'Review running'
              : retryAvailable
                ? 'Retry failed review'
                : 'Run AI review'}
        </button>
        <button
          type="button"
          disabled={!anino.enabled || trainingProcessing || (aninoStatus.training_candidates ?? 0) === 0}
          onClick={() =>
            postTraining(`/scans/${scan.id}/anino-training`, {
              preserveScroll: true,
              onSuccess: fetchAninoStatus,
            })
          }
          className="ml-2 px-3 py-1.5 rounded text-xs font-medium border border-signal-green/50 text-signal-green hover:bg-signal-green/10 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {trainingProcessing ? 'Queueing...' : 'Teach Rubix'}
        </button>

        <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_28rem]">
          <AninoProgress status={aninoStatus} />
          <AninoLogs logs={aninoStatus.logs ?? []} enabled={anino.enabled} />
        </div>
      </div>

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
              advice={guidance[finding.cwe_id ?? 'unknown']}
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

function AninoProgress({ status }) {
  const runTotal = Math.max(1, status.run?.total_findings ?? status.total_findings ?? 0);
  const runProcessed = status.run?.processed_findings ?? status.run?.reviewed_findings ?? status.adjudicated ?? 0;
  const runReviewed = status.run?.reviewed_findings ?? status.adjudicated ?? 0;
  const progress = status.run?.progress_percent ?? Math.round((runReviewed / runTotal) * 100);
  const runStatus = status.run?.status ?? 'idle';
  const running = ['queued', 'running', 'running_with_errors'].includes(runStatus);
  const reviewStages = [
    { label: 'Context built', value: status.contexts, tone: 'bg-sky-400' },
    { label: 'ATAKE done', value: status.atake, tone: 'bg-amber' },
    { label: 'DEPENSA done', value: status.depensa, tone: 'bg-cyan-300' },
    { label: 'Adjudicated', value: status.adjudicated, tone: 'bg-signal-green' },
  ];
  const heartbeat = status.run?.heartbeat_age_seconds;
  const phaseElapsed = status.run?.phase_elapsed_seconds;
  const eta = status.run?.estimated_remaining_seconds;

  return (
    <div className="rounded border border-hairline bg-ink p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="font-mono text-[10px] uppercase text-fog">AI progress</div>
          <div className="mt-1 text-base font-semibold text-paper">
            {runProcessed} of {runTotal} findings processed
          </div>
          <div className="mt-1 font-mono text-[11px] text-fog">
            {status.adjudicated ?? 0}/{status.total_findings ?? 0} scan total · {status.run?.phase ? `phase ${status.run.phase}` : 'no active phase'} · current #{status.run?.current_finding_id ?? 'n/a'} · remaining {status.run?.remaining_findings ?? status.total_findings ?? 0}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className={`rounded border px-2 py-1 font-mono text-[10px] uppercase ${runTone(runStatus)}`}>
            {runStatus}
          </div>
          <div className="rounded border border-amber/40 px-3 py-1 font-mono text-sm text-amber">{progress}%</div>
        </div>
      </div>

      <div className="mt-4 h-4 overflow-hidden rounded bg-panel-raised">
        <div
          className={`h-full bg-amber transition-all duration-500 ${running ? 'animate-pulse' : ''}`}
          style={{ width: `${Math.max(progress, running ? 1 : 0)}%` }}
        />
      </div>

      <div className="mt-2 flex flex-wrap justify-between gap-x-4 gap-y-1 font-mono text-[11px] text-fog">
        <span>
          {running
            ? `${String(status.run?.phase ?? 'starting').toUpperCase()} working for ${formatDuration(phaseElapsed)}`
            : `Last phase: ${status.run?.phase ?? 'n/a'}`}
          {status.run?.current_finding_id ? ` on finding #${status.run.current_finding_id}` : ''}
        </span>
        <span>Estimated remaining: <span className="text-paper">{formatDuration(eta)}</span></span>
      </div>

      <div className="mt-4 grid gap-3 md:grid-cols-2">
        {reviewStages.map((stage) => (
          <StageProgress key={stage.label} stage={stage} total={status.total_findings ?? 0} />
        ))}
      </div>

      <OutcomeMatrix outcomes={status.outcomes} />

      <div className="mt-3 grid gap-2 sm:grid-cols-2">
        <MetricBox label="Trainable labels" value={status.training_candidates ?? 0} detail={`>= ${Math.round((status.training_threshold ?? 0.85) * 100)}% confidence`} />
        <MetricBox label="Promoted to Rubix" value={status.training_promoted ?? 0} detail="training labels created" />
      </div>

      <div className="mt-3 rounded border border-hairline bg-panel px-3 py-2 text-xs text-fog">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <span>Heartbeat: <span className="font-mono text-paper">{heartbeat == null ? 'n/a' : `${heartbeat}s ago`}</span></span>
          <span>Updated: <span className="font-mono text-paper">{status.run?.heartbeat_at ?? 'n/a'}</span></span>
          <span>Queued: <span className="font-mono text-paper">{status.queue?.ai_analysis ?? 0}</span></span>
          <span>Failed: <span className="font-mono text-paper">{status.queue?.failed_ai_analysis ?? 0}</span></span>
          <span>Average/reviewer: <span className="font-mono text-paper">{formatDuration(status.run?.average_seconds_per_review)}</span></span>
        </div>
        {status.run?.last_error && <div className="mt-1 break-words font-mono text-[10px] text-signal-red">{status.run.last_error}</div>}
      </div>
    </div>
  );
}

function OutcomeMatrix({ outcomes = {} }) {
  return (
    <div className="mt-4 border-t border-hairline pt-3">
      <div className="mb-2 font-mono text-[10px] uppercase text-fog">Reviewer flags</div>
      <div className="overflow-x-auto">
        <div className="grid min-w-[28rem] grid-cols-[minmax(7rem,1fr)_repeat(5,minmax(3rem,0.55fr))] items-center gap-px overflow-hidden rounded border border-hairline bg-hairline text-center font-mono">
          <div className="bg-panel px-3 py-2 text-left text-[10px] uppercase text-fog">Model</div>
          {OUTCOME_COLUMNS.map((column) => (
            <abbr
              key={column.key}
              title={column.label}
              className={`bg-panel px-2 py-2 text-[10px] no-underline ${column.tone}`}
            >
              {column.short}
            </abbr>
          ))}
          {['atake', 'depensa'].map((reviewer) => (
            <OutcomeRow key={reviewer} reviewer={reviewer} outcomes={outcomes[reviewer]} />
          ))}
        </div>
      </div>
    </div>
  );
}

function OutcomeRow({ reviewer, outcomes = EMPTY_OUTCOME_MATRIX }) {
  return (
    <>
      <div className="bg-ink px-3 py-2 text-left text-[11px] uppercase text-paper">{reviewer}</div>
      {OUTCOME_COLUMNS.map((column) => (
        <div key={column.key} className={`bg-ink px-2 py-2 text-sm tabular-nums ${column.tone}`}>
          {outcomes?.[column.key] ?? 0}
        </div>
      ))}
    </>
  );
}

function StageProgress({ stage, total }) {
  const denominator = Math.max(1, total);
  const value = stage.value ?? 0;
  const percent = Math.round((value / denominator) * 100);

  return (
    <div className="rounded border border-hairline bg-panel px-3 py-2.5">
      <div className="mb-2 flex items-center justify-between gap-3">
        <div className="font-mono text-[10px] uppercase text-fog">{stage.label}</div>
        <div className="font-mono text-[11px] text-paper">{value}/{total} · {percent}%</div>
      </div>
      <div className="h-2.5 overflow-hidden rounded bg-ink">
        <div className={`h-full transition-all ${stage.tone}`} style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}

function MetricBox({ label, value, detail }) {
  return (
    <div className="rounded border border-hairline bg-panel px-3 py-2.5">
      <div className="font-mono text-[10px] uppercase text-fog">{label}</div>
      <div className="mt-1 font-mono text-lg text-paper">{value}</div>
      <div className="mt-0.5 text-xs text-fog">{detail}</div>
    </div>
  );
}

function runTone(status) {
  if (status === 'complete') return 'border-signal-green/40 text-signal-green';
  if (status === 'failed' || status === 'stalled' || status === 'running_with_errors' || status === 'complete_with_errors') return 'border-signal-red/40 text-signal-red';
  if (status === 'skipped') return 'border-hairline text-fog';
  if (status === 'running' || status === 'queued') return 'border-amber/40 text-amber';

  return 'border-hairline text-fog';
}

function formatDuration(seconds) {
  if (seconds === null || seconds === undefined || Number.isNaN(Number(seconds))) return 'calculating';

  const value = Math.max(0, Math.round(Number(seconds)));
  if (value < 60) return `${value}s`;

  const minutes = Math.floor(value / 60);
  const remainder = value % 60;

  return remainder === 0 ? `${minutes}m` : `${minutes}m ${remainder}s`;
}

function AninoLogs({ logs, enabled }) {
  return (
    <div className="rounded border border-hairline bg-ink p-4">
      <div className="font-mono text-[10px] uppercase text-fog">Recent AI logs</div>

      <div className="mt-2 max-h-56 space-y-1.5 overflow-y-auto pr-1">
        {!enabled ? (
          <div className="text-xs text-fog">AI review is disabled.</div>
        ) : logs.length === 0 ? (
          <div className="text-xs text-fog">No AI activity for this scan yet.</div>
        ) : (
          logs.map((entry, index) => (
            <div key={`${entry.time}-${index}`} className="rounded border border-hairline bg-panel px-2.5 py-2">
              <div className="flex items-center justify-between gap-2">
                <span className={`font-mono text-[10px] uppercase ${entry.level === 'error' ? 'text-signal-red' : entry.level === 'warning' ? 'text-amber' : 'text-signal-green'}`}>
                  {entry.level}
                </span>
                <span className="font-mono text-[10px] text-fog">{entry.time ?? '--:--:--'}</span>
              </div>
              <div className="mt-1 text-xs text-paper">{entry.message}</div>
              {entry.detail && <div className="mt-1 break-words font-mono text-[10px] leading-relaxed text-fog">{entry.detail}</div>}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function FindingRow({ finding, advice, expanded, selected, onToggleExpand, onToggleSelect, onTriage }) {
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

      {expanded && (
        <div className="mx-4 mb-3 space-y-3">
          {finding.raw_snippet && (
            <pre className="px-3 py-2.5 bg-ink border border-hairline rounded font-mono text-xs text-fog overflow-x-auto">
              {finding.raw_snippet}
            </pre>
          )}

          {advice && <Remediation advice={advice} />}

          <AiAssessments assessments={finding.ai_assessments ?? []} predictedLabel={finding.predicted_label} />
        </div>
      )}
    </div>
  );
}

function AiAssessments({ assessments, predictedLabel }) {
  if (assessments.length === 0) {
    return (
      <div className="rounded border border-hairline bg-panel/50 p-3 text-xs text-fog">
        ATAKE and DEPENSA have not reviewed this finding yet.
      </div>
    );
  }

  return (
    <div className="grid gap-2 md:grid-cols-3">
      {assessments.map((assessment) => (
        <AiAssessmentCard key={assessment.id} assessment={assessment} predictedLabel={predictedLabel} />
      ))}
    </div>
  );
}

function AiAssessmentCard({ assessment, predictedLabel }) {
  const confidence = assessment.confidence == null ? 'n/a' : `${Math.round(assessment.confidence * 100)}%`;
  const outcome = resolveEvaluationOutcome(assessment, predictedLabel);

  return (
    <div className="rounded border border-hairline bg-panel/50 p-3">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="font-mono text-[10px] uppercase text-amber">{assessment.reviewer}</div>
          <div className="mt-1 text-sm font-semibold text-paper">{formatClassification(assessment.classification)}</div>
        </div>
        <div className="flex flex-col items-end gap-1">
          <span
            title={`${assessment.reviewer.toUpperCase()} compared with Rubix: ${formatClassification(outcome)}`}
            className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase ${outcomeTone(outcome)}`}
          >
            {formatClassification(outcome)}
          </span>
          <div className="font-mono text-[11px] text-fog">{confidence}</div>
        </div>
      </div>

      <p className="mt-2 text-xs leading-relaxed text-fog">{assessment.reasoning_summary}</p>

      <div className="mt-3 grid grid-cols-3 gap-1 text-center font-mono text-[10px] text-fog">
        <Signal label="Control" value={assessment.attacker_controlled} />
        <Signal label="Sink" value={assessment.sink_reachable} />
        <Signal label="Mitigate" value={assessment.mitigation_detected} inverse />
      </div>

      <Link
        href={`/findings/${assessment.finding_id}`}
        className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-amber hover:underline"
      >
        Why this flag
        <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
      </Link>
    </div>
  );
}

function resolveEvaluationOutcome(assessment, predictedLabel) {
  if (assessment.evaluation_outcome) return assessment.evaluation_outcome;

  const predictedPositive = predictedLabel === 'true_positive' ? true : predictedLabel === 'false_positive' ? false : null;
  const actualPositive = ['confirmed_tp', 'likely_tp'].includes(assessment.classification)
    ? true
    : ['confirmed_fp', 'likely_fp'].includes(assessment.classification)
      ? false
      : null;

  if (predictedPositive == null || actualPositive == null) return 'unresolved';
  if (predictedPositive) return actualPositive ? 'true_positive' : 'false_positive';

  return actualPositive ? 'false_negative' : 'true_negative';
}

function outcomeTone(outcome) {
  if (outcome === 'true_positive') return 'border-signal-red/40 text-signal-red';
  if (outcome === 'false_positive') return 'border-signal-green/40 text-signal-green';
  if (outcome === 'true_negative') return 'border-cyan-300/40 text-cyan-300';
  if (outcome === 'false_negative') return 'border-amber/40 text-amber';

  return 'border-hairline text-fog';
}

function Signal({ label, value, inverse = false }) {
  const known = value !== null && value !== undefined;
  const active = known && Boolean(value);
  const tone = !known ? 'text-fog' : active !== inverse ? 'text-signal-green' : 'text-signal-red';

  return (
    <div className={`rounded border border-hairline bg-ink px-1.5 py-1 ${tone}`}>
      <div>{label}</div>
      <div>{known ? (active ? 'yes' : 'no') : 'n/a'}</div>
    </div>
  );
}

function formatClassification(value) {
  return String(value ?? 'needs_validation')
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

/**
 * Impact and fix for the finding's CWE. Shown on expand so the reviewer can
 * act on a finding without going elsewhere to look up what it means.
 */
function Remediation({ advice }) {
  return (
    <div className="rounded border border-hairline bg-panel/50 p-3">
      <div className="kicker mb-2">{advice.title}</div>

      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-amber">Risk</div>
          <p className="text-xs leading-relaxed text-fog">{advice.risk}</p>
        </div>
        <div>
          <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-signal-green">Fix</div>
          <p className="text-xs leading-relaxed text-fog">{advice.fix}</p>
        </div>
      </div>

      {advice.vulnerable && (
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          <pre className="overflow-x-auto rounded border border-signal-red/30 bg-ink px-3 py-2 font-mono text-[11px] text-fog">
            {advice.vulnerable}
          </pre>
          <pre className="overflow-x-auto rounded border border-signal-green/30 bg-ink px-3 py-2 font-mono text-[11px] text-fog">
            {advice.secure}
          </pre>
        </div>
      )}

      {advice.reference && (
        <a
          href={advice.reference}
          target="_blank"
          rel="noreferrer noopener"
          className="mt-2 inline-block font-mono text-[11px] text-amber hover:underline"
        >
          Reference ↗
        </a>
      )}
    </div>
  );
}
