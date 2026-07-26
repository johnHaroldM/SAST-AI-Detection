const SEVERITY_STYLES = {
  CRITICAL: 'text-sev-critical border-sev-critical/40 bg-sev-critical/10',
  HIGH: 'text-sev-high border-sev-high/40 bg-sev-high/10',
  MEDIUM: 'text-sev-medium border-sev-medium/40 bg-sev-medium/10',
  LOW: 'text-sev-low border-sev-low/40 bg-sev-low/10',
};

export default function SeverityBadge({ severity }) {
  const style = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.MEDIUM;

  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded border font-mono text-[10px] uppercase tracking-wide ${style}`}>
      {severity}
    </span>
  );
}
