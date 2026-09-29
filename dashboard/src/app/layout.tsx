import type { Metadata } from 'next';
import Link from 'next/link';
import { Suspense } from 'react';
import './globals.css';
import { CostTile } from '@/components/CostTile';
import { ProviderDropdown } from '@/components/ProviderDropdown';

// The header renders live DB-backed data (cost tile, provider setting) on every page,
// so nothing under this layout should be statically prerendered at build time.
export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'SOC Alert Triage Copilot',
  description: 'Triage queue, alert detail, briefs, and cost tracking for the Jev/Tier-2 pipeline.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="sticky top-0 z-10 flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-slate-900 px-6 py-3">
          <Link href="/queue" className="text-lg font-semibold text-white">
            SOC Triage Copilot
          </Link>
          <div className="flex flex-wrap items-center gap-4">
            <Suspense fallback={<div className="text-xs text-slate-400">Loading cost…</div>}>
              <CostTile />
            </Suspense>
            <Suspense fallback={<div className="text-xs text-slate-400">Loading…</div>}>
              <ProviderDropdown />
            </Suspense>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-6 py-6">{children}</main>
      </body>
    </html>
  );
}
