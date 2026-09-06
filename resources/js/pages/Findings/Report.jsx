import { Link } from '@inertiajs/react';
import { useState } from 'react';
import axios from 'axios';
import { ArrowLeft, ArrowRight, CheckCircle2, CircleHelp, ExternalLink, XCircle } from 'lucide-react';
import AppLayout from '../../layouts/AppLayout';
import SeverityBadge from '../../components/SeverityBadge';

/**
 * The full write-up for one finding, structured as what / why / how.
 *
 * The point of difference from generic advice is the code snapshot: the
 * developer's own lines, with the flagged one marked, and a rewrite of that
 * exact statement. Reading about path traversal in the abstract teaches much
 * less than seeing your own file with the offending line highlighted.
 */
export default function FindingReport({ finding, location, what, why, how, code, aiReview }) {
  return (
    <AppLayout title="Finding explanation">
      <div className="mx-auto max-w-5xl space-y-5">
        <Header finding={finding} location={location} />

        <Section step="1" label="What" title={what.title}>
          <p className="text-sm leading-relaxed text-fog">{what.risk}</p>
          {what.reference && (
            <a
              href={what.reference}
              target="_blank"
              rel="noreferrer noopener"
              className="mt-3 inline-block font-mono text-[11px] text-amber hover:underline"
            >
              <span className="inline-flex items-center gap-1">
                Reference
                <ExternalLink className="h-3 w-3" aria-hidden="true" />
              </span>
            </a>
          )}
        </Section>

        <Section step="2" label="Why" title="Why this code was flagged">
          <p className="mb-4 text-sm leading-relaxed text-paper">{why.detected}</p>

          <CodeSnapshot code={code} location={location} />

          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <Criterion tone="red" heading="It is a real issue if" body={why.truePositive} />
            <Criterion tone="green" heading="It is a false alarm if" body={why.falsePositive} />
          </div>

          {why.reviewerNote && (
            <div className="mt-4 rounded border border-hairline bg-ink/60 p-3">
              <div className="kicker mb-1">Reviewer note</div>
              <p className="text-xs leading-relaxed text-fog">{why.reviewerNote}</p>
            </div>
          )}
        </Section>

        <AiReviewSection aiReview={aiReview} />

        <Section step="4" label="How" title="How to fix it">
          <p className="text-sm leading-relaxed text-fog">{how.summary}</p>

          {how.suggestion ? (
            <SuggestedChange suggestion={how.suggestion} />
          ) : (
            how.generic.vulnerable && <GenericExample generic={how.generic} />
          )}
        </Section>

        <TriageActions finding={finding} />
      </div>
    </AppLayout>
  );
}

function Header({ finding, location }) {
  return (
    <div className="rounded-lg border border-hairline bg-panel p-5">
      {finding.scan_id && (
        <Link
          href={`/scans/${finding.scan_id}`}
          className="mb-4 inline-flex items-center gap-1.5 text-xs text-fog hover:text-paper"
        >
          <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
          Back to scan
        </Link>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <SeverityBadge severity={finding.severity} />
        <h2 className="font-display text-lg font-semibold text-paper">{finding.message}</h2>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-fog">
        <span>{finding.rule_id}</span>
        {finding.cwe_id && (
          <a
            href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id}.html`}
            target="_blank"
            rel="noreferrer noopener"
            className="text-amber hover:underline"
          >
            CWE-{finding.cwe_id} ↗
          </a>
        )}
        {finding.branch && <span>branch: {finding.branch}</span>}
        <StatusChip finding={finding} />
      </div>

      <Breadcrumb location={location} lineNumber={finding.line_number} />
    </div>
  );
}

/**
 * Fourteen projects are registered and several share a path like
 * app/Http/Controllers/FormController.php, so the project and its directory
 * tree matter as much as the filename.
 */
function Breadcrumb({ location, lineNumber }) {
  return (
    <div className="mt-4 rounded border border-hairline bg-ink/60 p-3">
      <div className="kicker mb-2">Location</div>

      <div className="flex flex-wrap items-center gap-1 font-mono text-xs">
        <span className="rounded bg-amber/15 px-2 py-0.5 font-semibold text-amber">
          {location.project ?? 'unknown project'}
        </span>

        {location.segments.map((segment, i) => (
          <span key={i} className="flex items-center gap-1">
            <span className="text-fog/50">/</span>
            <span className="text-fog">{segment}</span>
          </span>
        ))}

        <span className="text-fog/50">/</span>
        <span className="font-semibold text-paper">{location.file}</span>
        <span className="text-fog/50">:</span>
        <span className="text-amber">{lineNumber}</span>
      </div>

      {location.absolute && (
        <div className="mt-2 select-all break-all font-mono text-[10px] text-fog/70">{location.absolute}</div>
      )}
    </div>
  );
}

function StatusChip({ finding }) {
  if (finding.final_label) {
    const tp = finding.final_label === 'true_positive';
    return (
      <span className={tp ? 'text-signal-red' : 'text-signal-green'}>
        reviewed · {tp ? 'true positive' : 'false positive'}
      </span>
    );
  }

  return <span className="text-amber">awaiting review</span>;
}

function AiReviewSection({ aiReview }) {
  const reviewers = aiReview?.reviewers?.length
    ? aiReview.reviewers
    : [
        { reviewer: 'atake', available: false },
        { reviewer: 'depensa', available: false },
      ];

  return (
    <Section step="3" label="AI review" title="Why ATAKE and DEPENSA flagged it">
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3 border-b border-hairline pb-4">
        <div>
          <div className="font-mono text-[10px] uppercase text-fog">Rubix prediction</div>
          <div className={`mt-1 text-sm font-semibold ${predictionTone(aiReview?.rubix_prediction)}`}>
            {predictionLabel(aiReview?.rubix_prediction)}
          </div>
        </div>
        <div className="text-right">
          <div className="font-mono text-[10px] uppercase text-fog">Vulnerability probability</div>
          <div className="mt-1 font-mono text-sm text-paper">{formatConfidence(aiReview?.rubix_probability)}</div>
        </div>
      </div>

      <div className="grid divide-y divide-hairline border-y border-hairline md:grid-cols-2 md:divide-x md:divide-y-0">
        {reviewers.map((review) => (
          <ReviewerExplanation key={review.reviewer} review={review} prediction={aiReview?.rubix_prediction} />
        ))}
      </div>
    </Section>
  );
}

function ReviewerExplanation({ review, prediction }) {
  return (
    <article className="min-w-0 py-4 first:pt-0 last:pb-0 md:px-4 md:py-4 md:first:pl-0 md:first:pt-4 md:last:pr-0 md:last:pb-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="font-display text-base font-semibold uppercase text-paper">{review.reviewer}</div>
          <div className="mt-0.5 break-all font-mono text-[10px] text-fog">{review.model ?? 'Model not configured'}</div>
        </div>
        {review.available && <OutcomeBadge outcome={review.evaluation_outcome} />}
      </div>

      {!review.available ? (
        <div className="py-10 text-center">
          <CircleHelp className="mx-auto h-5 w-5 text-fog" aria-hidden="true" />
          <div className="mt-2 text-sm text-paper">Waiting for review</div>
          <div className="mt-1 text-xs text-fog">No assessment has been returned for this finding.</div>
        </div>
      ) : (
        <>
          <div className="mt-4 flex flex-wrap items-center gap-2 font-mono text-[10px]">
            <span className={`rounded border px-2 py-1 ${predictionBadgeTone(prediction)}`}>
              {predictionLabel(prediction)}
            </span>
            <ArrowRight className="h-3.5 w-3.5 shrink-0 text-fog" aria-hidden="true" />
            <span className="rounded border border-hairline px-2 py-1 text-paper">
              {formatLabel(review.classification)}
            </span>
            <span className="ml-auto text-fog">{formatConfidence(review.confidence)}</span>
          </div>

          <p className="mt-3 text-xs leading-relaxed text-paper">{review.outcome_reason}</p>

          <div className="mt-4 border-t border-hairline pt-4">
            <div className="font-mono text-[10px] uppercase text-fog">Model reasoning</div>
            <p className="mt-1.5 text-xs leading-relaxed text-fog">
              {review.reasoning_summary || 'No reasoning summary was returned.'}
            </p>
          </div>

          <div className="mt-4 grid grid-cols-3 gap-px overflow-hidden rounded border border-hairline bg-hairline">
            <ReviewSignal label="Control" value={review.attacker_controlled} concernWhen />
            <ReviewSignal label="Sink" value={review.sink_reachable} concernWhen />
            <ReviewSignal label="Mitigation" value={review.mitigation_detected} concernWhen={false} />
          </div>

          <div className="mt-4 space-y-4">
            <EvidenceList title="Supporting evidence" items={review.supporting_evidence} kind="support" />
            <EvidenceList title="Contradicting evidence" items={review.contradicting_evidence} kind="contradict" />
            <EvidenceList title="Required preconditions" items={review.preconditions} kind="condition" />
            <EvidenceList title="Missing evidence" items={review.missing_evidence} kind="missing" />
            <EvidenceList title="Recommended remediation" items={review.remediation} kind="remediation" />
          </div>

          {review.completed_at && (
            <div className="mt-4 border-t border-hairline pt-3 font-mono text-[10px] text-fog">
              Completed {review.completed_at}
            </div>
          )}
        </>
      )}
    </article>
  );
}

function OutcomeBadge({ outcome }) {
  const styles = {
    true_positive: 'border-signal-red/40 text-signal-red',
    false_positive: 'border-signal-green/40 text-signal-green',
    true_negative: 'border-cyan-300/40 text-cyan-300',
    false_negative: 'border-amber/40 text-amber',
    unresolved: 'border-hairline text-fog',
  };

  return (
    <span className={`rounded border px-2 py-1 font-mono text-[10px] uppercase ${styles[outcome] ?? styles.unresolved}`}>
      {formatLabel(outcome)}
    </span>
  );
}

function ReviewSignal({ label, value, concernWhen }) {
  const known = value !== null && value !== undefined;
  const concern = known && Boolean(value) === concernWhen;
  const tone = !known ? 'text-fog' : concern ? 'text-signal-red' : 'text-signal-green';

  return (
    <div className="bg-ink px-2 py-2 text-center">
      <div className="font-mono text-[9px] uppercase text-fog">{label}</div>
      <div className={`mt-1 font-mono text-[10px] ${tone}`}>{known ? (value ? 'yes' : 'no') : 'unknown'}</div>
    </div>
  );
}

function EvidenceList({ title, items = [], kind }) {
  if (!items?.length) return null;

  const styles = {
    support: { icon: CheckCircle2, tone: 'text-signal-red' },
    contradict: { icon: XCircle, tone: 'text-signal-green' },
    condition: { icon: CircleHelp, tone: 'text-amber' },
    missing: { icon: CircleHelp, tone: 'text-fog' },
    remediation: { icon: CheckCircle2, tone: 'text-signal-green' },
  };
  const style = styles[kind] ?? styles.missing;
  const Icon = style.icon;

  return (
    <div>
      <div className={`font-mono text-[10px] uppercase ${style.tone}`}>{title}</div>
      <ul className="mt-1.5 space-y-1.5">
        {items.map((item, index) => (
          <li key={`${title}-${index}`} className="flex items-start gap-2 text-xs leading-relaxed text-fog">
            <Icon className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${style.tone}`} aria-hidden="true" />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function predictionLabel(prediction) {
  if (prediction === 'true_positive') return 'Predicted TP';
  if (prediction === 'false_positive') return 'Predicted FP';

  return 'Not scored';
}

function predictionTone(prediction) {
  if (prediction === 'true_positive') return 'text-signal-red';
  if (prediction === 'false_positive') return 'text-signal-green';

  return 'text-fog';
}

function predictionBadgeTone(prediction) {
  if (prediction === 'true_positive') return 'border-signal-red/40 text-signal-red';
  if (prediction === 'false_positive') return 'border-signal-green/40 text-signal-green';

  return 'border-hairline text-fog';
}

function formatConfidence(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return 'n/a';

  const numeric = Number(value);
  const normalized = numeric > 1 ? numeric / 100 : numeric;

  return `${Math.round(normalized * 100)}%`;
}

function formatLabel(value) {
  return String(value ?? 'unresolved')
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function Section({ step, label, title, children }) {
  return (
    <div className="rounded-lg border border-hairline bg-panel p-5">
      <div className="mb-3 flex items-baseline gap-3">
        <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-amber/40 font-mono text-[11px] text-amber">
          {step}
        </span>
        <div>
          <div className="kicker">{label}</div>
          <h3 className="font-display text-base font-semibold text-paper">{title}</h3>
        </div>
      </div>
      <div className="pl-9">{children}</div>
    </div>
  );
}

function Criterion({ tone, heading, body }) {
  // Tailwind scans for complete class strings, so these cannot be built by
  // interpolation — `border-${colour}/30` compiles to nothing.
  const styles =
    tone === 'red'
      ? { box: 'border-signal-red/30 bg-signal-red/5', label: 'text-signal-red' }
      : { box: 'border-signal-green/30 bg-signal-green/5', label: 'text-signal-green' };

  return (
    <div className={`rounded border p-3 ${styles.box}`}>
      <div className={`mb-1 font-mono text-[10px] uppercase tracking-wider ${styles.label}`}>{heading}</div>
      <p className="text-xs leading-relaxed text-fog">{body}</p>
    </div>
  );
}

function CodeSnapshot({ code, location }) {
  if (!code.available) {
    return (
      <div className="rounded border border-dashed border-hairline px-4 py-6 text-center text-xs text-fog">
        Source not shown — {code.reason}.
        <div className="mt-1 text-fog/60">
          Set the project&apos;s source_path, or enable git cloning, to see the code here.
        </div>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded border border-hairline">
      <div className="flex items-center justify-between border-b border-hairline bg-ink/60 px-3 py-1.5">
        <span className="font-mono text-[11px] text-fog">
          {location.directory}/{location.file}
        </span>
        <span className="font-mono text-[10px] text-fog/60">
          lines {code.lines[0]?.number}–{code.lines[code.lines.length - 1]?.number}
        </span>
      </div>

      <pre className="overflow-x-auto bg-ink py-2 font-mono text-[11px] leading-relaxed">
        {code.lines.map((line) => (
          <div
            key={line.number}
            className={line.flagged ? 'bg-signal-red/10 border-l-2 border-signal-red' : 'border-l-2 border-transparent'}
          >
            <span className="inline-block w-12 select-none pr-3 text-right text-fog/40">{line.number}</span>
            <span className={line.flagged ? 'text-paper' : 'text-fog'}>{line.text || ' '}</span>
          </div>
        ))}
      </pre>
    </div>
  );
}

function SuggestedChange({ suggestion }) {
  return (
    <div className="mt-4 space-y-3">
      <div>
        <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-signal-red">
          Your code today
        </div>
        <pre className="overflow-x-auto rounded border border-signal-red/30 bg-ink px-3 py-2.5 font-mono text-[11px] text-fog">
          {suggestion.before}
        </pre>
      </div>

      <div>
        <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-signal-green">
          Change it to
        </div>
        <pre className="overflow-x-auto rounded border border-signal-green/30 bg-ink px-3 py-2.5 font-mono text-[11px] text-paper">
          {suggestion.after}
        </pre>
      </div>

      <div className="rounded border border-amber/30 bg-amber/5 p-3">
        <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-amber">Before you paste this</div>
        <p className="text-xs leading-relaxed text-fog">{suggestion.note}</p>
      </div>
    </div>
  );
}

function GenericExample({ generic }) {
  return (
    <div className="mt-4 grid gap-2 md:grid-cols-2">
      <pre className="overflow-x-auto rounded border border-signal-red/30 bg-ink px-3 py-2 font-mono text-[11px] text-fog">
        {generic.vulnerable}
      </pre>
      <pre className="overflow-x-auto rounded border border-signal-green/30 bg-ink px-3 py-2 font-mono text-[11px] text-fog">
        {generic.secure}
      </pre>
    </div>
  );
}

function TriageActions({ finding }) {
  const [label, setLabel] = useState(finding.final_label);
  const [saving, setSaving] = useState(false);

  async function decide(value) {
    setSaving(true);
    const previous = label;
    setLabel(value);

    try {
      await axios.post(`/api/findings/${finding.id}/triage`, { corrected_label: value });
    } catch {
      setLabel(previous);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-hairline bg-panel p-4">
      <div className="text-sm text-fog">
        {label ? (
          <>
            Recorded as{' '}
            <span className={label === 'true_positive' ? 'text-signal-red' : 'text-signal-green'}>
              {label.replace('_', ' ')}
            </span>
          </>
        ) : (
          'Is this a real issue?'
        )}
      </div>

      <div className="flex items-center gap-2">
        <Link href="/triage" className="rounded border border-hairline px-3 py-1.5 text-xs text-fog hover:text-paper">
          Back to queue
        </Link>
        <button
          disabled={saving}
          onClick={() => decide('true_positive')}
          className="rounded border border-signal-red/40 px-3 py-1.5 text-xs font-medium text-signal-red hover:bg-signal-red/10 disabled:opacity-50"
        >
          True positive
        </button>
        <button
          disabled={saving}
          onClick={() => decide('false_positive')}
          className="rounded border border-signal-green/40 px-3 py-1.5 text-xs font-medium text-signal-green hover:bg-signal-green/10 disabled:opacity-50"
        >
          False positive
        </button>
      </div>
    </div>
  );
}
