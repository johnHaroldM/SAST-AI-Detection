import { useForm } from '@inertiajs/react';
import AppLayout from '../../layouts/AppLayout';

/**
 * The training screen separates the active certified model from the latest
 * training attempt so a rejected challenger never looks deployed.
 */
export default function ModelIndex({
  readiness,
  has_trained_model,
  has_certified_model,
  active,
  latest,
  history = [],
  training_in_progress,
}) {
  const { post, processing } = useForm();

  function train(event) {
    event.preventDefault();
    post('/model/train', { preserveScroll: true });
  }

  const blocked = !readiness.ready || training_in_progress;

  return (
    <AppLayout title="Model training">
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="space-y-6">
          <DeploymentPanel
            active={active}
            hasCertifiedModel={has_certified_model}
            hasLegacyFile={has_trained_model}
          />
          <LabelProgress readiness={readiness} />
          {latest ? <MetricsPanel run={latest} activeId={active?.id} /> : <NoModelPanel readiness={readiness} />}
          {history.length > 1 && <TrendPanel history={history} />}
        </div>

        <aside className="space-y-4">
          <div className="rounded-lg border border-hairline bg-panel p-5">
            <div className="kicker mb-2">Classifier</div>
            <div className="font-display text-lg font-semibold">RandomForest</div>
            <p className="mt-1 text-xs text-fog">
              OneHotEncoder → ZScaleStandardizer → RandomForest, over a 9-field feature vector.
            </p>

            <div className="mt-4 flex items-center gap-2 text-xs">
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  has_certified_model ? 'bg-signal-green' : has_trained_model ? 'bg-amber' : 'bg-fog'
                }`}
              />
              <span className="text-fog">
                {has_certified_model
                  ? 'Certified model active'
                  : has_trained_model
                    ? 'Legacy model present — review-only'
                    : 'No certified model — review-only'}
              </span>
            </div>

            <form onSubmit={train} className="mt-5">
              <button
                type="submit"
                disabled={blocked || processing}
                className="w-full rounded-md bg-amber px-4 py-2.5 text-sm font-semibold uppercase tracking-wide text-ink hover:bg-amber/90 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {training_in_progress
                  ? 'Evaluating candidate…'
                  : processing
                    ? 'Queueing…'
                    : 'Train and evaluate candidate'}
              </button>
            </form>

            {!readiness.ready && (
              <p className="mt-2.5 text-[11px] leading-relaxed text-fog">
                Candidate evaluation unlocks once the trusted label set meets the minimum support. Work the
                triage queue to add independently reviewed examples from both classes.
              </p>
            )}
          </div>

          <div className="rounded-lg border border-hairline bg-panel p-5">
            <div className="kicker mb-2">From the CLI</div>
            <code className="block font-mono text-[11px] leading-relaxed text-fog">
              php artisan sast:train --sync
            </code>
            <p className="mt-2 text-[11px] text-fog">
              Runs candidate evaluation in-process. Without <span className="font-mono">--sync</span> it queues
              onto <span className="font-mono">ml-training</span>. A candidate is deployed only after it passes
              the configured quality gate.
            </p>
          </div>
        </aside>
      </div>
    </AppLayout>
  );
}

function DeploymentPanel({ active, hasCertifiedModel, hasLegacyFile }) {
  if (!hasCertifiedModel || !active) {
    return (
      <div className="rounded-lg border border-amber/40 bg-amber/5 p-5">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-amber" />
          <div className="kicker text-amber">Review-only mode</div>
        </div>
        <div className="mt-2 font-display text-lg font-semibold">No certified Rubix model is deployed</div>
        <p className="mt-1 max-w-2xl text-xs leading-relaxed text-fog">
          {hasLegacyFile
            ? 'A legacy model file exists, but it has not passed the current validation gate. Existing scores are advisory and should be reviewed by a person.'
            : 'New findings remain unclassified until a candidate has enough validation support and passes the deployment gate.'}
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-signal-green/40 bg-signal-green/5 p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-signal-green" />
            <div className="kicker text-signal-green">Active deployment</div>
          </div>
          <div className="mt-2 font-display text-lg font-semibold">Certified Rubix model</div>
          <p className="mt-1 text-xs text-fog">
            Deployed {formatDate(active.trained_at)} · validation F1 {formatPercent(active.f1_score)}
          </p>
        </div>
        <div className="rounded-md border border-signal-green/30 bg-ink px-3 py-2 text-right">
          <div className="text-[10px] uppercase tracking-wider text-fog">TP decision threshold</div>
          <div className="mt-0.5 font-mono text-lg text-signal-green">
            {formatThreshold(active.decision_threshold)}
          </div>
        </div>
      </div>
    </div>
  );
}

function LabelProgress({ readiness }) {
  const pct = Math.min(100, Math.round((readiness.total / Math.max(1, readiness.required)) * 100));

  return (
    <div className="rounded-lg border border-hairline bg-panel p-5">
      <div className="flex items-baseline justify-between">
        <div className="kicker">Trusted labeled data</div>
        <div className="font-mono text-xs text-fog">
          {readiness.total} / {readiness.required}
        </div>
      </div>

      <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-ink">
        <div
          className={`h-full rounded-full transition-all ${readiness.ready ? 'bg-signal-green' : 'bg-amber'}`}
          style={{ width: `${pct}%` }}
        />
      </div>

      <div className="mt-4 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-hairline bg-hairline">
        <div className="bg-ink px-4 py-3">
          <div className="kicker">True positives</div>
          <div className="mt-1 font-display text-xl font-semibold tabular-nums text-signal-red">
            {readiness.true_positive}
          </div>
        </div>
        <div className="bg-ink px-4 py-3">
          <div className="kicker">False positives</div>
          <div className="mt-1 font-display text-xl font-semibold tabular-nums text-signal-green">
            {readiness.false_positive}
          </div>
        </div>
      </div>

      {readiness.total >= readiness.required && !readiness.ready && (
        <p className="mt-3 text-xs text-amber">
          Both labels need enough independent support before a candidate can be evaluated safely.
        </p>
      )}
    </div>
  );
}

function MetricsPanel({ run, activeId }) {
  const metadata = asObject(run.evaluation_metadata);
  const validation = asObject(metadata.validation);
  const status = statusDescriptor(run.deployment_status);
  const isActive = activeId !== undefined && activeId !== null && run.id === activeId;
  const precisionDefined = metadata.precision_defined !== false;
  const metrics = [
    {
      label: 'Precision',
      value: precisionDefined ? run.precision : null,
      hint: 'of validation TP flags, share that were real',
    },
    { label: 'Recall', value: run.recall, hint: 'of validation TPs, share the candidate caught' },
    { label: 'F1 score', value: run.f1_score, hint: 'harmonic mean on validation data' },
  ];
  const cm = run.confusion_matrix ?? {};
  const hasValidationMetadata = Object.keys(validation).length > 0;

  return (
    <div className="rounded-lg border border-hairline bg-panel p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="kicker">Latest training attempt</div>
          <div className="mt-1 font-mono text-xs text-fog">
            {formatDate(run.trained_at)} · {run.sample_size} validation samples
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isActive && (
            <span className="rounded-full border border-signal-green/30 bg-signal-green/10 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-signal-green">
              Active
            </span>
          )}
          <span
            className={`rounded-full border px-2 py-1 text-[10px] font-semibold uppercase tracking-wider ${status.className}`}
          >
            {status.label}
          </span>
        </div>
      </div>

      {run.deployment_status === 'rejected' && (
        <div className="mt-4 rounded-md border border-signal-red/30 bg-signal-red/5 px-3 py-2.5 text-xs leading-relaxed text-signal-red">
          <span className="font-semibold">Candidate rejected.</span>{' '}
          {metadata.rejection_reason || 'It did not meet the configured deployment quality gate.'}
        </div>
      )}

      {(!run.deployment_status || run.deployment_status === 'legacy') && (
        <div className="mt-4 rounded-md border border-amber/30 bg-amber/5 px-3 py-2.5 text-xs leading-relaxed text-amber">
          Legacy metrics were recorded before certified, group-aware evaluation. They remain audit history and do
          not prove that this model is safe to deploy.
        </div>
      )}

      <div className="mt-4 grid grid-cols-3 gap-px overflow-hidden rounded-md border border-hairline bg-hairline">
        {metrics.map((metric) => (
          <div key={metric.label} className="bg-ink px-4 py-3">
            <div className="kicker">{metric.label}</div>
            <div className="mt-1 font-display text-2xl font-semibold tabular-nums">
              {formatPercent(metric.value)}
            </div>
            <div className="mt-1 text-[10px] leading-tight text-fog">{metric.hint}</div>
          </div>
        ))}
      </div>

      <div className="mt-4 grid gap-px overflow-hidden rounded-md border border-hairline bg-hairline sm:grid-cols-3">
        <SupportCell label="TP threshold" value={formatThreshold(run.decision_threshold)} />
        <SupportCell label="TP flags evaluated" value={metadata.flagged_count} />
        <SupportCell label="Validation coverage" value={formatPercent(metadata.coverage)} />
      </div>

      {hasValidationMetadata && (
        <div className="mt-4">
          <div className="kicker mb-2">Validation support</div>
          <div className="grid gap-px overflow-hidden rounded-md border border-hairline bg-hairline sm:grid-cols-5">
            <SupportCell label="Samples" value={validation.samples} />
            <SupportCell label="True positives" value={validation.true_positive} />
            <SupportCell label="False positives" value={validation.false_positive} />
            <SupportCell label="Independent groups" value={validation.groups} />
            <SupportCell label="TP groups" value={validation.true_positive_groups} />
          </div>
          <p className="mt-2 text-[10px] leading-relaxed text-fog">
            {metadata.strategy ? `Split: ${humanize(metadata.strategy)}. ` : ''}
            {metadata.min_precision !== undefined
              ? `Gate: at least ${formatPercent(metadata.min_precision)} precision across ${metadata.min_flags ?? 'the required number of'} TP flags and ${metadata.min_validation_tp_groups ?? 'multiple'} TP project groups. `
              : ''}
            {metadata.excluded_duplicates !== undefined
              ? `${metadata.excluded_duplicates} duplicate and ${metadata.excluded_conflicts ?? 0} conflicting rows were excluded.`
              : ''}
            {metadata.ambiguous_feature_rows
              ? ` ${metadata.ambiguous_feature_rows} rows share ${metadata.ambiguous_feature_vectors ?? 'multiple'} indistinguishable feature vectors across opposing labels, limiting what the current feature set can learn.`
              : ''}
            {metadata.pseudo_training_samples !== undefined
              ? ` ${metadata.pseudo_training_samples} capped AI weak labels augmented training; ${metadata.pseudo_validation_excluded ?? 0} validation-side weak labels were quarantined.`
              : ''}
          </p>
          {metadata.dataset_fingerprint && (
            <p className="mt-1 font-mono text-[10px] text-fog" title={metadata.dataset_fingerprint}>
              Dataset {String(metadata.dataset_fingerprint).slice(0, 12)}…
            </p>
          )}
        </div>
      )}

      <div className="mt-4">
        <div className="kicker mb-2">Confusion matrix</div>
        <div className="grid grid-cols-4 gap-px overflow-hidden rounded-md border border-hairline bg-hairline font-mono text-xs">
          {[
            ['TP', cm.tp, 'text-signal-green'],
            ['FP', cm.fp, 'text-signal-red'],
            ['FN', cm.fn, 'text-signal-red'],
            ['TN', cm.tn, 'text-signal-green'],
          ].map(([label, value, tone]) => (
            <div key={label} className="bg-ink px-3 py-2.5">
              <div className="text-[10px] uppercase tracking-wider text-fog">{label}</div>
              <div className={`mt-0.5 text-lg tabular-nums ${tone}`}>{value ?? 0}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function SupportCell({ label, value }) {
  return (
    <div className="bg-ink px-3 py-2.5">
      <div className="text-[10px] uppercase tracking-wider text-fog">{label}</div>
      <div className="mt-0.5 font-mono text-sm tabular-nums">{value ?? 'n/a'}</div>
    </div>
  );
}

function NoModelPanel({ readiness }) {
  return (
    <div className="rounded-lg border border-dashed border-hairline bg-panel/40 px-5 py-10 text-center">
      <div className="font-display text-lg font-semibold">No training attempts yet</div>
      <p className="mx-auto mt-2 max-w-md text-sm leading-relaxed text-fog">
        {readiness.ready
          ? 'You have enough labeled findings to evaluate a candidate. It will deploy only if its validation evidence passes the quality gate.'
          : 'Upload a scan, then review its findings as true or false positives. Candidate evaluation starts after the trusted label set reaches the required support.'}
      </p>
    </div>
  );
}

function TrendPanel({ history }) {
  const points = history.map((state, i) => ({
    x: (i / Math.max(1, history.length - 1)) * 100,
    y: 100 - state.f1_score * 100,
    state,
  }));

  const path = points
    .map((point, i) => `${i === 0 ? 'M' : 'L'}${point.x.toFixed(2)} ${point.y.toFixed(2)}`)
    .join(' ');

  return (
    <div className="rounded-lg border border-hairline bg-panel p-5">
      <div className="kicker mb-3">Candidate F1 across {history.length} attempts</div>
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="h-28 w-full">
        <line x1="0" y1="50" x2="100" y2="50" stroke="#2A3140" strokeWidth="0.4" strokeDasharray="2 2" />
        <path d={path} fill="none" stroke="#7D8799" strokeWidth="1" vectorEffect="non-scaling-stroke" />
        {points.map((point, i) => (
          <circle
            key={i}
            cx={point.x}
            cy={point.y}
            r="1.4"
            fill={statusColor(point.state.deployment_status)}
            vectorEffect="non-scaling-stroke"
          />
        ))}
      </svg>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-fog">
        <span>{new Date(history[0].trained_at).toLocaleDateString()}</span>
        <span>{new Date(history[history.length - 1].trained_at).toLocaleDateString()}</span>
      </div>
      <p className="mt-2 text-[10px] leading-relaxed text-fog">
        Green attempts were deployed; red candidates were rejected; amber points are uncertified legacy runs.
      </p>
    </div>
  );
}

function statusDescriptor(status) {
  if (status === 'deployed') {
    return {
      label: 'Deployed',
      className: 'border-signal-green/30 bg-signal-green/10 text-signal-green',
    };
  }

  if (status === 'rejected') {
    return {
      label: 'Rejected',
      className: 'border-signal-red/30 bg-signal-red/10 text-signal-red',
    };
  }

  return {
    label: status ? humanize(status) : 'Legacy',
    className: 'border-amber/30 bg-amber/10 text-amber',
  };
}

function statusColor(status) {
  if (status === 'deployed') return '#4ADE80';
  if (status === 'rejected') return '#F87171';

  return '#E8A33D';
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function formatPercent(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return 'n/a';

  return `${(Number(value) * 100).toFixed(1)}%`;
}

function formatThreshold(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return 'Review only';

  return `≥ ${formatPercent(value)}`;
}

function formatDate(value) {
  if (!value) return 'date unavailable';

  return new Date(value).toLocaleString();
}

function humanize(value) {
  return String(value).replaceAll('_', ' ');
}
