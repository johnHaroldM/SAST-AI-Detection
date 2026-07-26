import { Link, usePage } from '@inertiajs/react';

const NAV_ITEMS = [
  { label: 'Scans', href: '/scans', icon: ScanIcon },
  { label: 'Upload scan', href: '/scans/upload', icon: UploadIcon },
  { label: 'Noisy rules', href: '/rules/noisy', icon: RuleIcon },
];

/**
 * Shared shell for the triage dashboard: fixed dark sidebar + main content
 * well. Every Inertia page in resources/js/Pages renders inside this.
 */
export default function AppLayout({ children, title }) {
  const { url } = usePage();

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

        <div className="px-5 py-4 border-t border-hairline">
          <div className="kicker">Model status</div>
          <div className="mt-1.5 flex items-center gap-1.5 text-xs text-fog">
            <span className="h-1.5 w-1.5 rounded-full bg-signal-green" />
            RandomForest · live
          </div>
        </div>
      </aside>

      <main className="flex-1 min-w-0">
        {title && (
          <header className="border-b border-hairline px-8 py-5">
            <h1 className="font-display font-semibold text-xl tracking-tight">{title}</h1>
          </header>
        )}
        <div className="px-8 py-6">{children}</div>
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
