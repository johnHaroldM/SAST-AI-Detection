import AppLayout from '../../layouts/AppLayout';

const ACTION_STYLES = {
  suppress: { label: 'Suppress', tone: 'text-signal-red border-signal-red/40 bg-signal-red/10' },
  review_config: { label: 'Review config', tone: 'text-amber border-amber/40 bg-amber/10' },
};

/**
 * props.rules: from RuleController::noisy() — rules with ≥20 samples and a
 * historical_fp_rate that crossed the review (>70%) or suppress (>85%)
 * threshold, per Rule::recalculateFpRate().
 */
export default function NoisyRules({ rules }) {
  return (
    <AppLayout title="Noisy rules">
      <p className="text-sm text-fog max-w-lg mb-6">
        Rules here are producing enough confirmed false positives that the fix belongs in your
        scanner config, not in the triage queue. Ranked by historical FP rate, minimum 20 samples.
      </p>

      {rules.length === 0 ? (
        <div className="border border-dashed border-hairline rounded-lg py-14 text-center text-sm text-fog">
          No rules have crossed the noise threshold yet.
        </div>
      ) : (
        <div className="border border-hairline rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-panel text-left text-fog kicker">
                <th className="px-4 py-2.5 font-medium">Rule</th>
                <th className="px-4 py-2.5 font-medium">CWE</th>
                <th className="px-4 py-2.5 font-medium text-right">Sample size</th>
                <th className="px-4 py-2.5 font-medium text-right">FP rate</th>
                <th className="px-4 py-2.5 font-medium">Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => {
                const action = ACTION_STYLES[rule.recommended_action];
                return (
                  <tr key={rule.id} className="border-t border-hairline">
                    <td className="px-4 py-3">
                      <div className="font-mono text-xs text-paper">{rule.external_id}</div>
                      {rule.description && (
                        <div className="text-xs text-fog mt-0.5 max-w-md truncate">{rule.description}</div>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-fog">
                      {rule.cwe_id ? `CWE-${rule.cwe_id}` : '—'}
                    </td>
                    <td className="px-4 py-3 text-right font-mono tabular-nums text-fog">
                      {rule.total_seen}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <FpRateBar rate={rule.historical_fp_rate} />
                    </td>
                    <td className="px-4 py-3">
                      {action && (
                        <span className={`inline-flex px-2 py-0.5 rounded border text-xs font-medium ${action.tone}`}>
                          {action.label}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </AppLayout>
  );
}

function FpRateBar({ rate }) {
  const pct = Math.round(rate * 100);
  return (
    <div className="flex items-center justify-end gap-2">
      <div className="w-20 h-1.5 rounded-full bg-panel-raised overflow-hidden">
        <div className="h-full bg-signal-red" style={{ width: `${pct}%` }} />
      </div>
      <span className="font-mono text-xs tabular-nums w-9 text-right">{pct}%</span>
    </div>
  );
}
