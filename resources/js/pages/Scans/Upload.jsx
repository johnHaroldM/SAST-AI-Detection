import { useState } from 'react';
import { router } from '@inertiajs/react';
import AppLayout from '../../Layouts/AppLayout';

export default function ScanUpload({ projects }) {
  const [projectId, setProjectId] = useState(projects[0]?.id ?? '');
  const [source, setSource] = useState('sarif');
  const [commitSha, setCommitSha] = useState('');
  const [branch, setBranch] = useState('main');
  const [report, setReport] = useState(null);

  function submit(event) {
    event.preventDefault();

    if (!report) return;

    const formData = new FormData();
    formData.append('project_id', projectId);
    formData.append('source', source);
    formData.append('commit_sha', commitSha);
    formData.append('branch', branch);
    formData.append('report', report);

    router.post('/api/scans', formData, {
      forceFormData: true,
      preserveScroll: true,
      onSuccess: () => {
        setReport(null);
      },
    });
  }

  return (
    <AppLayout title="Upload scan report">
      <div className="max-w-2xl rounded-lg border border-hairline bg-panel p-6">
        <p className="text-sm text-fog mb-6">
          Upload a SARIF, Semgrep, SonarQube, Bandit, or PHPCS report to feed the model with new findings.
        </p>

        <form onSubmit={submit} className="space-y-5">
          <div>
            <label className="mb-2 block text-sm font-medium text-fog">Project</label>
            <select
              value={projectId}
              onChange={(event) => setProjectId(event.target.value)}
              className="w-full rounded-md border border-hairline bg-ink px-3 py-2 text-sm text-paper"
              required
            >
              {projects.map((project) => (
                <option key={project.id} value={project.id}>
                  {project.name}
                </option>
              ))}
            </select>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="mb-2 block text-sm font-medium text-fog">Source</label>
              <select
                value={source}
                onChange={(event) => setSource(event.target.value)}
                className="w-full rounded-md border border-hairline bg-ink px-3 py-2 text-sm text-paper"
              >
                <option value="sarif">SARIF</option>
                <option value="semgrep">Semgrep</option>
                <option value="sonarqube">SonarQube</option>
                <option value="bandit">Bandit</option>
                <option value="phpcs">PHPCS</option>
              </select>
            </div>

            <div>
              <label className="mb-2 block text-sm font-medium text-fog">Branch</label>
              <input
                type="text"
                value={branch}
                onChange={(event) => setBranch(event.target.value)}
                className="w-full rounded-md border border-hairline bg-ink px-3 py-2 text-sm text-paper"
                placeholder="main"
                required
              />
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="mb-2 block text-sm font-medium text-fog">Commit SHA</label>
              <input
                type="text"
                value={commitSha}
                onChange={(event) => setCommitSha(event.target.value)}
                className="w-full rounded-md border border-hairline bg-ink px-3 py-2 text-sm text-paper"
                placeholder="e.g. 0123456789abcdef0123456789abcdef01234567"
                maxLength={40}
                required
              />
            </div>

            <div>
              <label className="mb-2 block text-sm font-medium text-fog">Report file</label>
              <input
                type="file"
                accept=".json,.sarif"
                onChange={(event) => setReport(event.target.files?.[0] ?? null)}
                className="w-full rounded-md border border-hairline bg-ink px-3 py-2 text-sm text-paper"
                required
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 pt-4">
            <button
              type="submit"
              className="inline-flex items-center justify-center rounded-md bg-amber px-4 py-2 text-sm font-semibold uppercase tracking-wide text-ink hover:bg-amber/90"
            >
              Upload report
            </button>
          </div>
        </form>
      </div>
    </AppLayout>
  );
}
