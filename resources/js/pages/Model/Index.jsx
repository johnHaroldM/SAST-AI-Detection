import { useForm } from '@inertiajs/react';
import AppLayout from '../../layouts/AppLayout';

/**
 * The training screen. Answers three questions a security engineer has
 * before hitting "train": is there enough labeled data, how did the last
 * run score, and is the score trending the right way.
 *
 * props.readiness  — label counts vs the configured minimum
 * props.latest     — most recent ModelState, or null before the first run
 * props.history    — up to 20 ModelStates, oldest first (for the trend line)
 */
export default function ModelIndex({ readiness, has_trained_model, latest, history, training_in_progress }) {
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
          <LabelProgress readiness={readiness} />
          {latest ? <MetricsPanel latest={latest} /> : <NoModelPanel readiness={readiness} />}
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
              <span className={`h-1.5 w-1.5 rounded-full ${has_trained_model ? 'bg-signal-green' : 'bg-amber'}`} />
              <span className="text-fog">
                {has_trained_model ? 'Trained and scoring new scans' : 'No model yet — scans queue up unscored'}
              </span>
            </div>

            <form onSubmit={train} className="mt-5">
              <button
                type="submit"
                disabled={blocked || processing}
                className="w-full rounded-md bg-amber px-4 py-2.5 text-sm font-semibold uppercase tracking-wide text-ink hover:bg-amber/90 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {training_in_progress ? 'Training in progress…' : processing ? 'Queueing…' : 'Train model'}
              </button>
            </form>

            {!readiness.ready && (
              <p className="mt-2.5 text-[11px] leading-relaxed text-fog">
                Training unlocks once you have {readiness.required} triaged findings with at least one of each
                label. Work the queue on any scan to get there.
              </p>
            )}
          </div>

          <div className="rounded-lg border border-hairline bg-panel p-5">
            <div className="kicker mb-2">From the CLI</div>
            <code className="block font-mono text-[11px] leading-relaxed text-fog">
              php artisan sast:train --sync
            </code>
            <p className="mt-2 text-[11px] text-fog">
              Runs in-process and prints the metrics table. Without <span className="font-mono">--sync</span> it
              queues onto <span className="font-mono">ml-training</span>.
            </p>
          </div>
        </aside>
      </div>
    </AppLayout>
  );
}

function LabelProgress({ readiness }) {
  const pct = Math.min(100, Math.round((readiness.total / Math.max(1, readiness.required)) * 100));

  return (
    <div className="rounded-lg border border-hairline bg-panel p-5">
      <div className="flex items-baseline justify-between">
        <div className="kicker">Labeled training data</div>
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
          Both labels are needed — a single-class dataset trains a model that answers the same way every time.
        </p>
      )}
    </div>
  );
}

function MetricsPanel({ latest }) {
  const metrics = [
    { label: 'Precision', value: latest.precision, hint: 'of flagged TPs, share that were real' },
    { label: 'Recall', value: latest.recall, hint: 'of real TPs, share the model caught' },
    { label: 'F1 score', value: latest.f1_score, hint: 'harmonic mean of the two' },
  ];

  const cm = latest.confusion_matrix ?? {};

  return (
    <div className="rounded-lg border border-hairline bg-panel p-5">
      <div className="flex items-baseline justify-between">
        <div className="kicker">Last training run</div>
        <div className="font-mono text-xs text-fog">
          {new Date(latest.trained_at).toLocaleString()} · {latest.sample_size} held-out samples
        </div>
      </div>

      <div className="mt-4 grid grid-cols-3 gap-px overflow-hidden rounded-md border border-hairline bg-hairline">
        {metrics.map((m) => (
          <div key={m.label} className="bg-ink px-4 py-3">
            <div className="kicker">{m.label}</div>
            <div className="mt-1 font-display text-2xl font-semibold tabular-nums">
              {(m.value * 100).toFixed(1)}
              <span className="text-base text-fog">%</span>
            </div>
            <div className="mt-1 text-[10px] leading-tight text-fog">{m.hint}</div>
          </div>
        ))}
      </div>

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

function NoModelPanel({ readiness }) {
  return (
    <div className="rounded-lg border border-dashed border-hairline bg-panel/40 px-5 py-10 text-center">
      <div className="font-display text-lg font-semibold">No training runs yet</div>
      <p className="mx-auto mt-2 max-w-md text-sm leading-relaxed text-fog">
        {readiness.ready
          ? 'You have enough labeled findings. Train the model to start scoring incoming scans.'
          : 'Upload a scan, then triage its findings as true or false positives. Once ' +
            `${readiness.required} are labeled, training unlocks and new scans get scored automatically.`}
      </p>
    </div>
  );
}

function TrendPanel({ history }) {
  const points = history.map((h, i) => ({
    x: (i / Math.max(1, history.length - 1)) * 100,
    y: 100 - h.f1_score * 100,
    state: h,
  }));

  const path = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(2)} ${p.y.toFixed(2)}`).join(' ');

  return (
    <div className="rounded-lg border border-hairline bg-panel p-5">
      <div className="kicker mb-3">F1 score over {history.length} runs</div>
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="h-28 w-full">
        <line x1="0" y1="50" x2="100" y2="50" stroke="#2A3140" strokeWidth="0.4" strokeDasharray="2 2" />
        <path d={path} fill="none" stroke="#E8A33D" strokeWidth="1" vectorEffect="non-scaling-stroke" />
        {points.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r="1.4" fill="#E8A33D" vectorEffect="non-scaling-stroke" />
        ))}
      </svg>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-fog">
        <span>{new Date(history[0].trained_at).toLocaleDateString()}</span>
        <span>{new Date(history[history.length - 1].trained_at).toLocaleDateString()}</span>
      </div>
    </div>
  );
}
