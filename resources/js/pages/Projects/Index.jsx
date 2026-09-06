import { useState } from 'react';
import { Link, useForm, usePage } from '@inertiajs/react';
import AppLayout from '../../layouts/AppLayout';

/**
 * What the scanner is pointed at.
 *
 * Each project expands to show its top-level directory tree with the excluded
 * folders struck through, because a directory that was skipped by config looks
 * exactly like a directory with no findings unless you say so explicitly.
 */
export default function ProjectsIndex({ projects, excludedByConfig, localScanEnabled }) {
  const totals = projects.reduce(
    (acc, p) => ({
      findings: acc.findings + p.findings.total,
      pending: acc.pending + p.findings.pending,
      truePositive: acc.truePositive + p.findings.true_positive,
      files: acc.files + (p.target.included_files ?? 0),
    }),
    { findings: 0, pending: 0, truePositive: 0, files: 0 }
  );

  return (
    <AppLayout title="Projects">
      <div className="grid grid-cols-4 gap-px overflow-hidden rounded-lg border border-hairline bg-hairline">
        <Stat label="Projects" value={projects.length} />
        <Stat label="PHP files in scope" value={totals.files.toLocaleString()} />
        <Stat label="Findings" value={totals.findings} />
        <Stat label="Confirmed real" value={totals.truePositive} tone="text-signal-red" />
      </div>

      <NewTokenReveal />

      <AddProject localScanEnabled={localScanEnabled} />

      <div className="mt-6 space-y-3">
        {projects.map((project) => (
          <ProjectCard key={project.id} project={project} localScanEnabled={localScanEnabled} />
        ))}
      </div>

      <div className="mt-6 rounded-lg border border-hairline bg-panel/50 p-4">
        <div className="kicker mb-2">Always excluded</div>
        <div className="flex flex-wrap gap-1.5">
          {excludedByConfig.map((dir) => (
            <span key={dir} className="rounded bg-ink px-2 py-0.5 font-mono text-[11px] text-fog/70">
              {dir}
            </span>
          ))}
        </div>
        <p className="mt-2 text-[11px] text-fog/70">
          Configured in <span className="font-mono">config/sast.php</span> under{' '}
          <span className="font-mono">scanner.exclude_directories</span>.
        </p>
      </div>
    </AppLayout>
  );
}

/**
 * The only moment a freshly issued token is readable — the database keeps
 * nothing but its SHA-256 hash.
 *
 * The setup shown deliberately puts the token in an environment variable
 * rather than inline on the command, because a credential typed as an
 * argument lands in PowerShell history and in CI logs.
 */
function NewTokenReveal() {
  const { props } = usePage();
  const issued = props.flash?.ingestToken;
  const [copied, setCopied] = useState(false);

  if (!issued) return null;

  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://your-installation';

  return (
    <div className="mt-6 rounded-lg border border-amber/40 bg-amber/5 p-5">
      <div className="kicker mb-1 text-amber">Upload token for {issued.project}</div>
      <p className="mb-3 text-xs text-fog">
        Copy it now — only its hash is stored, so it cannot be shown again. Regenerating replaces it.
      </p>

      <div className="flex items-center gap-2">
        <code className="flex-1 select-all overflow-x-auto rounded border border-hairline bg-ink px-3 py-2 font-mono text-[11px] text-paper">
          {issued.token}
        </code>
        <button
          onClick={() => {
            navigator.clipboard?.writeText(issued.token);
            setCopied(true);
          }}
          className="shrink-0 rounded border border-amber/40 px-3 py-2 text-xs text-amber hover:bg-amber/10"
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>

      <div className="mt-4">
        <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-fog">PowerShell</div>
        <pre className="overflow-x-auto rounded border border-hairline bg-ink px-3 py-2.5 font-mono text-[11px] text-fog">
{`$env:SAST_ENDPOINT = "${origin}"
$env:SAST_INGEST_TOKEN = "<paste it here>"

php artisan sast:push . --yes`}
        </pre>
        <p className="mt-2 text-[11px] text-fog/70">
          Set it as an environment variable rather than passing <span className="font-mono">--token</span> inline —
          a credential typed as an argument is recorded in PowerShell history and in CI logs.
        </p>
      </div>
    </div>
  );
}

/**
 * Registering a project used to mean dropping into tinker. Pointing the
 * scanner at code is the first thing anyone does, so it belongs here.
 */
function AddProject({ localScanEnabled }) {
  const [open, setOpen] = useState(false);
  const { data, setData, post, processing, errors, reset } = useForm({
    name: '',
    source_path: '',
    vcs_repo_slug: '',
  });

  function submit(event) {
    event.preventDefault();
    post('/projects', { preserveScroll: true, onSuccess: () => { reset(); setOpen(false); } });
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="mt-6 w-full rounded-lg border border-dashed border-hairline py-3 text-sm text-fog hover:border-amber/50 hover:text-amber"
      >
        + Add a project to scan
      </button>
    );
  }

  return (
    <form onSubmit={submit} className="mt-6 rounded-lg border border-hairline bg-panel p-5">
      <div className="kicker mb-3">New project</div>

      <div className="grid gap-4 md:grid-cols-2">
        <Field label="Name" error={errors.name}>
          <input
            value={data.name}
            onChange={(e) => setData('name', e.target.value)}
            placeholder="Checkout API"
            className="w-full rounded-md border border-hairline bg-ink px-3 py-2 text-sm text-paper"
            required
          />
        </Field>

        <Field
          label="Source path"
          error={errors.source_path}
          hint={localScanEnabled ? 'Absolute path on this machine' : 'Local scanning is disabled on this installation'}
        >
          <input
            value={data.source_path}
            onChange={(e) => setData('source_path', e.target.value)}
            placeholder="C:\PHP\Mito\my-project"
            className="w-full rounded-md border border-hairline bg-ink px-3 py-2 font-mono text-xs text-paper"
          />
        </Field>
      </div>

      <div className="mt-4">
        <Field label="Repository slug" error={errors.vcs_repo_slug} hint="Optional — lets a hosted deployment clone it instead">
          <input
            value={data.vcs_repo_slug}
            onChange={(e) => setData('vcs_repo_slug', e.target.value)}
            placeholder="acme/checkout-api"
            className="w-full rounded-md border border-hairline bg-ink px-3 py-2 font-mono text-xs text-paper md:w-1/2"
          />
        </Field>
      </div>

      <div className="mt-5 flex justify-end gap-2">
        <button
          type="button"
          onClick={() => { reset(); setOpen(false); }}
          className="rounded-md border border-hairline px-4 py-2 text-sm text-fog hover:text-paper"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={processing}
          className="rounded-md bg-amber px-4 py-2 text-sm font-semibold uppercase tracking-wide text-ink hover:bg-amber/90 disabled:opacity-50"
        >
          {processing ? 'Saving…' : 'Add project'}
        </button>
      </div>
    </form>
  );
}

function Field({ label, hint, error, children }) {
  return (
    <div>
      <label className="mb-1.5 block text-sm font-medium text-fog">{label}</label>
      {children}
      {hint && !error && <p className="mt-1 text-[11px] text-fog/60">{hint}</p>}
      {error && <p className="mt-1 text-xs text-signal-red">{error}</p>}
    </div>
  );
}

function Stat({ label, value, tone }) {
  return (
    <div className="bg-panel px-4 py-3">
      <div className="kicker">{label}</div>
      <div className={`mt-1 font-display text-2xl font-semibold tabular-nums ${tone ?? 'text-paper'}`}>{value}</div>
    </div>
  );
}

function ProjectCard({ project, localScanEnabled }) {
  const [open, setOpen] = useState(false);
  const { target, findings } = project;
  const progress = findings.total ? Math.round((findings.labelled / findings.total) * 100) : 0;

  return (
    <div className="overflow-hidden rounded-lg border border-hairline bg-panel">
      <button onClick={() => setOpen((v) => !v)} className="flex w-full items-center gap-4 px-5 py-4 text-left">
        <span className={`h-2 w-2 shrink-0 rounded-full ${target.readable ? 'bg-signal-green' : 'bg-signal-red'}`} />

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-display font-semibold text-paper">{project.name}</span>
            {findings.true_positive > 0 && (
              <span className="rounded bg-signal-red/15 px-1.5 py-0.5 font-mono text-[10px] text-signal-red">
                {findings.true_positive} real
              </span>
            )}
          </div>
          <div className="mt-0.5 truncate font-mono text-[11px] text-fog">
            {project.source_path ?? 'no source path — cannot be scanned locally'}
          </div>
        </div>

        <div className="hidden shrink-0 gap-6 font-mono text-[11px] text-fog md:flex">
          <Metric label="files" value={target.included_files ?? 0} />
          <Metric label="findings" value={findings.total} />
          <Metric label="pending" value={findings.pending} tone={findings.pending ? 'text-amber' : undefined} />
          <Metric label="labelled" value={`${progress}%`} />
        </div>

        <ScanNowButton project={project} enabled={localScanEnabled && target.readable} />

        <span className="shrink-0 text-fog">{open ? '▾' : '▸'}</span>
      </button>

      {open && <FolderTree project={project} />}
    </div>
  );
}

/**
 * Read the code and land on the results. The scan runs inline, so this is a
 * genuine wait rather than a fire-and-forget — worth saying so on the button.
 */
function ScanNowButton({ project, enabled }) {
  const { post, processing } = useForm();

  function run(event) {
    event.stopPropagation();
    post(`/projects/${project.id}/scan`, { preserveScroll: true });
  }

  if (!enabled) {
    return (
      <span
        className="shrink-0 rounded border border-hairline px-3 py-1.5 text-xs text-fog/40"
        title="Needs a readable source path, and local scanning enabled"
      >
        Scan now
      </span>
    );
  }

  return (
    <button
      onClick={run}
      disabled={processing}
      className="shrink-0 rounded border border-amber/40 px-3 py-1.5 text-xs font-medium text-amber hover:bg-amber/10 disabled:opacity-50"
    >
      {processing ? 'Scanning…' : 'Scan now'}
    </button>
  );
}

function Metric({ label, value, tone }) {
  return (
    <div className="text-right">
      <div className={`tabular-nums ${tone ?? 'text-paper'}`}>{value}</div>
      <div className="text-[10px] uppercase tracking-wider text-fog/60">{label}</div>
    </div>
  );
}

function FolderTree({ project }) {
  const { target } = project;

  if (!target.readable) {
    return (
      <div className="border-t border-hairline px-5 py-4 text-xs text-signal-red">
        Source path is missing or unreadable, so this project cannot be scanned from this machine.
        {project.vcs_repo_slug && (
          <span className="text-fog"> A repository slug is set ({project.vcs_repo_slug}), so enabling git cloning would let a hosted deployment fetch it instead.</span>
        )}
      </div>
    );
  }

  return (
    <div className="border-t border-hairline px-5 py-4">
      <div className="kicker mb-2">Directory tree in scope</div>

      <div className="font-mono text-[11px]">
        <div className="text-fog">{target.root}</div>

        {target.directories.map((dir, i) => {
          const last = i === target.directories.length - 1;
          return (
            <div key={dir.name} className="flex items-center gap-2">
              <span className="text-fog/40">{last ? '└─' : '├─'}</span>
              {dir.included ? (
                <>
                  <span className="text-paper">{dir.name}/</span>
                  <span className="text-fog/50">{dir.php_files} php</span>
                </>
              ) : (
                <>
                  <span className="text-fog/40 line-through">{dir.name}/</span>
                  <span className="text-fog/40">excluded</span>
                </>
              )}
            </div>
          );
        })}
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <Link
          href={`/triage?project=${project.id}`}
          className="rounded border border-hairline px-3 py-1.5 text-xs text-fog hover:border-amber/50 hover:text-amber"
        >
          Triage this project ({project.findings.pending} pending)
        </Link>
        <code className="rounded bg-ink px-2 py-1 font-mono text-[11px] text-fog">
          php artisan sast:scan &quot;{project.name}&quot; --sync
        </code>
      </div>

      <IngestToken project={project} />
    </div>
  );
}

/**
 * Upload credential for CI and the CLI.
 *
 * Scoped to this one project and write-only: it can push a report and do
 * nothing else. Only the hash is stored, so the plaintext appears exactly
 * once, at the moment it is issued.
 */
function IngestToken({ project }) {
  const { post, delete: destroy, processing } = useForm();
  const token = project.ingest_token;

  return (
    <div className="mt-4 border-t border-hairline pt-4">
      <div className="mb-2 flex items-center justify-between">
        <div className="kicker">Upload token — for CI and the CLI</div>

        {token.exists ? (
          <div className="flex items-center gap-2">
            <button
              onClick={() => post(`/projects/${project.id}/token`)}
              disabled={processing}
              className="rounded border border-hairline px-2.5 py-1 text-[11px] text-fog hover:text-paper disabled:opacity-50"
            >
              Regenerate
            </button>
            <button
              onClick={() => {
                if (window.confirm('Revoke this token? Any CI job using it will start failing.')) {
                  destroy(`/projects/${project.id}/token`);
                }
              }}
              disabled={processing}
              className="rounded border border-signal-red/40 px-2.5 py-1 text-[11px] text-signal-red hover:bg-signal-red/10 disabled:opacity-50"
            >
              Revoke
            </button>
          </div>
        ) : (
          <button
            onClick={() => post(`/projects/${project.id}/token`)}
            disabled={processing}
            className="rounded border border-amber/40 px-2.5 py-1 text-[11px] text-amber hover:bg-amber/10 disabled:opacity-50"
          >
            Generate token
          </button>
        )}
      </div>

      {token.exists ? (
        <div className="font-mono text-[11px] text-fog">
          <span className={token.expired ? 'text-signal-red line-through' : 'text-paper'}>{token.hint}…</span>
          <span className="ml-3 text-fog/60">
            issued {token.created_at ? new Date(token.created_at).toLocaleDateString() : '—'}
          </span>
          <span className="ml-3 text-fog/60">
            {token.last_used_at ? `last used ${new Date(token.last_used_at).toLocaleString()}` : 'never used'}
          </span>
          {token.expires_at && (
            <span className={`ml-3 ${token.expired ? 'text-signal-red' : 'text-fog/60'}`}>
              {token.expired ? 'expired' : 'expires'} {new Date(token.expires_at).toLocaleDateString()}
            </span>
          )}
          {token.expired && (
            <div className="mt-1 text-signal-red">
              Uploads using this token are being rejected. Regenerate to restore CI.
            </div>
          )}
        </div>
      ) : (
        <p className="text-[11px] text-fog/70">
          No token issued. Generate one to push scans from a build agent or another machine.
        </p>
      )}
    </div>
  );
}
