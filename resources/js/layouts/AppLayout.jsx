import { Link, usePage } from '@inertiajs/react';

const NAV_ITEMS = [
  { label: 'Projects', href: '/projects', icon: FolderIcon },
  { label: 'Scans', href: '/scans', icon: ScanIcon },
  { label: 'Triage queue', href: '/triage', icon: TriageIcon },
  { label: 'Upload scan', href: '/scans/upload', icon: UploadIcon },
  { label: 'Noisy rules', href: '/rules/noisy', icon: RuleIcon },
  { label: 'Model', href: '/model', icon: ModelIcon },
];

/**
 * Shared shell for the triage dashboard: fixed dark sidebar + main content
 * well. Every Inertia page in resources/js/pages renders inside this.
 */
export default function AppLayout({ children, title }) {
  const { url, props } = usePage();
  const { flash = {}, modelTrained = false } = props;

  return (
    <div className="min-h-screen bg-ink text-paper flex">
      <aside className="w-60 shrink-0 border-r border-hairline bg-panel/60 flex flex-col">
        <div className="px-5 py-6 border-b border-hairline">
          <div className="kicker mb-1">SAST Triage Engine</div>
          <div className="font-display font-semibold text-lg tracking-tight">
            Signal<span className="text-amber">/</span>Bench
          </div>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV_ITEMS.map((item) => {
            const active = url === item.href || (item.href !== '/scans' && url.startsWith(item.href));
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  active
                    ? 'bg-panel-raised text-paper'
                    : 'text-fog hover:text-paper hover:bg-panel-raised/60'
                }`}
              >
                <item.icon active={active} />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <Link href="/model" className="px-5 py-4 border-t border-hairline block hover:bg-panel-raised/40">
          <div className="kicker">Model status</div>
          <div className="mt-1.5 flex items-center gap-1.5 text-xs text-fog">
            <span
              className={`h-1.5 w-1.5 rounded-full ${modelTrained ? 'bg-signal-green' : 'bg-amber'}`}
            />
            {modelTrained ? 'RandomForest · live' : 'Untrained · collecting labels'}
          </div>
        </Link>
      </aside>

      <main className="flex-1 min-w-0">
        {title && (
          <header className="border-b border-hairline px-8 py-5">
            <h1 className="font-display font-semibold text-xl tracking-tight">{title}</h1>
          </header>
        )}
        <div className="px-8 py-6">
          {flash.success && (
            <div className="mb-5 rounded-md border border-signal-green/40 bg-signal-green/10 px-4 py-2.5 text-sm text-signal-green">
              {flash.success}
            </div>
          )}
          {flash.error && (
            <div className="mb-5 rounded-md border border-signal-red/40 bg-signal-red/10 px-4 py-2.5 text-sm text-signal-red">
              {flash.error}
            </div>
          )}
          {children}
        </div>
      </main>
    </div>
  );
}

function ScanIcon({ active }) {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path
        d="M2 4.5C2 3.67 2.67 3 3.5 3h5L10 4.5h2.5c.83 0 1.5.67 1.5 1.5v6c0 .83-.67 1.5-1.5 1.5h-9C2.67 13.5 2 12.83 2 12V4.5Z"
        stroke={active ? '#EDEFF4' : '#8B93A7'}
        strokeWidth="1.3"
      />
    </svg>
  );
}

function UploadIcon({ active }) {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M8 2v6m0 0l-3-3m3 3l3-3" stroke={active ? '#EDEFF4' : '#8B93A7'} strokeWidth="1.3" strokeLinecap="round" />
      <path d="M4 12h8" stroke={active ? '#EDEFF4' : '#8B93A7'} strokeWidth="1.3" strokeLinecap="round" />
    </svg>
  );
}

function RuleIcon({ active }) {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M4 2v12M4 5h8M4 9h6" stroke={active ? '#EDEFF4' : '#8B93A7'} strokeWidth="1.3" strokeLinecap="round" />
    </svg>
  );
}

function FolderIcon({ active }) {
  const stroke = active ? '#EDEFF4' : '#8B93A7';

  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path
        d="M2 4.2c0-.66.54-1.2 1.2-1.2h3l1.4 1.6h5.2c.66 0 1.2.54 1.2 1.2v6c0 .66-.54 1.2-1.2 1.2H3.2c-.66 0-1.2-.54-1.2-1.2V4.2Z"
        stroke={stroke}
        strokeWidth="1.3"
      />
    </svg>
  );
}

function TriageIcon({ active }) {
  const stroke = active ? '#EDEFF4' : '#8B93A7';

  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M2.5 4h11M2.5 8h7M2.5 12h4" stroke={stroke} strokeWidth="1.3" strokeLinecap="round" />
      <path d="M11.5 10.5l1.4 1.4 2.4-2.6" stroke={stroke} strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ModelIcon({ active }) {
  const stroke = active ? '#EDEFF4' : '#8B93A7';

  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <circle cx="4" cy="4" r="1.6" stroke={stroke} strokeWidth="1.3" />
      <circle cx="4" cy="12" r="1.6" stroke={stroke} strokeWidth="1.3" />
      <circle cx="12" cy="8" r="1.6" stroke={stroke} strokeWidth="1.3" />
      <path d="M5.4 4.9 10.6 7.3M5.4 11.1 10.6 8.7" stroke={stroke} strokeWidth="1.3" strokeLinecap="round" />
    </svg>
  );
}
