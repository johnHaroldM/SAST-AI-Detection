import { useForm } from '@inertiajs/react';
import AppLayout from '../../layouts/AppLayout';

export default function ScanUpload({ projects }) {
  const { data, setData, post, processing, errors, reset } = useForm({
    project_id: projects[0]?.id ?? '',
    source: 'sarif',
    commit_sha: '',
    branch: 'main',
    report: null,
  });

  function submit(event) {
    event.preventDefault();

    // Posts to the Inertia route (scans.store), not the JSON API — the SPA
    // needs a redirect-with-flash response, and Inertia errors out on the
    // 202 JSON body that /api/scans returns.
    post('/scans', {
      forceFormData: true,
      preserveScroll: true,
      onSuccess: () => reset('report', 'commit_sha'),
    });
  }

  return (
    <AppLayout title="Upload scan report">
      <div className="max-w-2xl rounded-lg border border-hairline bg-panel p-6">
        <p className="text-sm text-fog mb-6">
          Upload a SARIF, Semgrep, SonarQube, Bandit, or PHPCS report to feed the model with new findings.
        </p>

        {projects.length === 0 && (
          <p className="mb-6 rounded-md border border-amber/40 bg-amber/10 px-3 py-2 text-sm text-amber">
            No projects exist yet — create one before uploading a report.
          </p>
        )}

        <form onSubmit={submit} className="space-y-5">
          <div>
            <label className="mb-2 block text-sm font-medium text-fog">Project</label>
            <select
              value={data.project_id}
              onChange={(event) => setData('project_id', event.target.value)}
              className="w-full rounded-md border border-hairline bg-ink px-3 py-2 text-sm text-paper"
              required
            >
              {projects.map((project) => (
                <option key={project.id} value={project.id}>
                  {project.name}
                </option>
              ))}
            </select>
            <FieldError message={errors.project_id} />
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="mb-2 block text-sm font-medium text-fog">Source</label>
              <select
                value={data.source}
                onChange={(event) => setData('source', event.target.value)}
                className="w-full rounded-md border border-hairline bg-ink px-3 py-2 text-sm text-paper"
              >
                <option value="sarif">SARIF</option>
                <option value="semgrep">Semgrep</option>
                <option value="sonarqube">SonarQube</option>
                <option value="bandit">Bandit</option>
                <option value="phpcs">PHPCS</option>
              </select>
              <FieldError message={errors.source} />
            </div>

            <div>
              <label className="mb-2 block text-sm font-medium text-fog">Branch</label>
              <input
                type="text"
                value={data.branch}
                onChange={(event) => setData('branch', event.target.value)}
                className="w-full rounded-md border border-hairline bg-ink px-3 py-2 text-sm text-paper"
                placeholder="main"
                required
              />
              <FieldError message={errors.branch} />
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="mb-2 block text-sm font-medium text-fog">Commit SHA</label>
              <input
                type="text"
                value={data.commit_sha}
                onChange={(event) => setData('commit_sha', event.target.value)}
                className="w-full rounded-md border border-hairline bg-ink px-3 py-2 font-mono text-sm text-paper"
                placeholder="e.g. 0123456789abcdef0123456789abcdef01234567"
                maxLength={40}
                required
              />
              <FieldError message={errors.commit_sha} />
            </div>

            <div>
              <label className="mb-2 block text-sm font-medium text-fog">Report file</label>
              <input
                type="file"
                accept=".json,.sarif"
                onChange={(event) => setData('report', event.target.files?.[0] ?? null)}
                className="w-full rounded-md border border-hairline bg-ink px-3 py-2 text-sm text-paper"
                required
              />
              <FieldError message={errors.report} />
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 pt-4">
            <button
              type="submit"
              disabled={processing || projects.length === 0}
              className="inline-flex items-center justify-center rounded-md bg-amber px-4 py-2 text-sm font-semibold uppercase tracking-wide text-ink hover:bg-amber/90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {processing ? 'Uploading…' : 'Upload report'}
            </button>
          </div>
        </form>
      </div>
    </AppLayout>
  );
}

function FieldError({ message }) {
  if (!message) return null;

  return <p className="mt-1.5 text-xs text-signal-red">{message}</p>;
}
