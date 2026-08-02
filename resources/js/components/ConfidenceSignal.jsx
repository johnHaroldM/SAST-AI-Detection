/**
 * The signature visual of the dashboard: renders a TP-probability score as
 * a scan-line reading rather than a generic progress bar or percent chip.
 * A tick mark at 80% shows the PR-auto-comment threshold from
 * PostPrCommentsJob, so reviewers can see at a glance whether a finding
 * already crossed the line that gets it posted to a PR automatically.
 *
 * Before the first training run every finding is unscored. Rendering that as
 * "0%" would read as "the model is confident this is a false positive",
 * which is a different and much stronger claim than "no model has looked at
 * this yet" — so the unscored state is drawn explicitly.
 */
export default function ConfidenceSignal({ probability, label }) {
  const isUnscored = probability === null || probability === undefined;

  if (isUnscored) {
    return (
      <div className="flex items-center gap-2.5 w-40" title="No trained model has scored this finding yet">
        <div className="relative h-5 flex-1 rounded-sm border border-dashed border-hairline bg-transparent" />
        <span className="font-mono text-[10px] uppercase tracking-wider text-fog w-9 text-right">n/a</span>
      </div>
    );
  }

  const pct = Math.round(probability * 100);
  const isTp = label === 'true_positive';
  const barColor = isTp ? 'bg-signal-red' : 'bg-signal-green';
  const THRESHOLD_PCT = 80;

  return (
    <div className="flex items-center gap-2.5 w-40">
      <div className="relative h-5 flex-1 rounded-sm bg-panel-raised overflow-hidden">
        {/* scan-line ticks */}
        <div className="absolute inset-0 flex justify-between px-[1px]">
          {Array.from({ length: 20 }).map((_, i) => (
            <span key={i} className="w-px h-full bg-ink/40" />
          ))}
        </div>
        <div
          className={`absolute inset-y-0 left-0 ${barColor} transition-all duration-300`}
          style={{ width: `${pct}%` }}
        />
        {/* threshold marker */}
        <div
          className="absolute inset-y-0 w-px bg-amber"
          style={{ left: `${THRESHOLD_PCT}%` }}
          title="Auto PR-comment threshold (80%)"
        />
      </div>
      <span className="font-mono text-xs text-fog tabular-nums w-9 text-right">{pct}%</span>
    </div>
  );
}
