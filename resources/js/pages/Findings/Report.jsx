import { Link, router } from '@inertiajs/react';
import { useState } from 'react';
import axios from 'axios';
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
export default function FindingReport({ finding, location, what, why, how, code }) {
  return (
    <AppLayout title="Finding report">
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
              Reference ↗
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

        <Section step="3" label="How" title="How to fix it">
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
