import { Link } from '@inertiajs/react';
import AppLayout from '../../layouts/AppLayout';

/**
 * props.scans: paginated list of scans from ScanDashboardController@index,
 * each with the same findings counts loaded by ScanController::show()
 * (total, true_positive_count, false_positive_count, pending_triage_count).
 */
export default function ScansIndex({ scans }) {
  return (
    <AppLayout title="Scans">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between mb-5">
        <p className="text-sm text-fog max-w-lg">
          Every SAST report your pipeline uploads lands here. Findings are AST-enriched and
          scored automatically — open a scan to review what the model flagged.
        </p>
        <Link
          href="/scans/upload"
          className="inline-flex items-center justify-center rounded-md bg-amber px-4 py-2 text-sm font-semibold uppercase tracking-wide text-ink hover:bg-amber/90"
        >
          Upload scan
        </Link>
      </div>

      {scans.data.length === 0 ? (
        <EmptyState />
      ) : (
        <div className="border border-hairline rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-panel text-left text-fog kicker">
                <th className="px-4 py-2.5 font-medium">Commit</th>
                <th className="px-4 py-2.5 font-medium">Branch</th>
                <th className="px-4 py-2.5 font-medium">Source</th>
                <th className="px-4 py-2.5 font-medium text-right">Findings</th>
                <th className="px-4 py-2.5 font-medium text-right">Pending triage</th>
                <th className="px-4 py-2.5 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {scans.data.map((scan) => (
                <tr key={scan.id} className="border-t border-hairline hover:bg-panel/50">
                  <td className="px-4 py-3">
                    <Link href={`/scans/${scan.id}`} className="font-mono text-xs text-paper hover:text-amber">
                      {scan.commit_sha.slice(0, 7)}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-fog">{scan.branch}</td>
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs text-fog uppercase">{scan.source}</span>
                  </td>
                  <td className="px-4 py-3 text-right font-mono tabular-nums">{scan.total_findings}</td>
                  <td className="px-4 py-3 text-right font-mono tabular-nums">
                    {scan.pending_triage_count > 0 ? (
                      <span className="text-amber">{scan.pending_triage_count}</span>
                    ) : (
                      <span className="text-fog">0</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <StatusPill status={scan.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </AppLayout>
  );
}

function StatusPill({ status }) {
  const styles = {
    complete: 'text-signal-green',
    scoring: 'text-amber',
    parsing: 'text-amber',
    uploaded: 'text-fog',
    failed: 'text-signal-red',
  };
  return <span className={`font-mono text-xs ${styles[status] ?? 'text-fog'}`}>{status}</span>;
}

function EmptyState() {
  return (
    <div className="border border-dashed border-hairline rounded-lg py-16 text-center">
      <div className="font-display text-lg mb-1">No scans yet</div>
      <p className="text-sm text-fog max-w-sm mx-auto">
        Upload a SARIF, Semgrep, SonarQube, Bandit, or PHPCS report via <code className="font-mono text-xs text-paper">POST /api/scans</code> to get started.
      </p>
    </div>
  );
}
