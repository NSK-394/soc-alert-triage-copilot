import Link from 'next/link';
import { getQueue } from '@/lib/queries';
import { SeverityChip } from '@/components/SeverityChip';
import { FeedbackButtons } from '@/components/FeedbackButtons';
import { formatConfidence, formatDateTime } from '@/lib/format';

export const dynamic = 'force-dynamic';

export default async function QueuePage() {
  const rows = await getQueue();

  return (
    <div>
      <h1 className="mb-1 text-2xl font-semibold">Triage queue</h1>
      <p className="mb-4 text-sm text-slate-500">
        Alerts routed to <code>queued</code> by the policy engine, sorted critical-first.
      </p>

      {rows.length === 0 ? (
        <div className="rounded-md border border-dashed border-slate-300 p-8 text-center text-slate-500">
          No queued alerts right now.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-md border border-slate-200">
          <table className="w-full min-w-[860px] border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-100 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Verdict</th>
                <th className="px-3 py-2">Confidence</th>
                <th className="px-3 py-2">Category</th>
                <th className="px-3 py-2">Source</th>
                <th className="px-3 py-2">Ingested</th>
                <th className="px-3 py-2">Feedback</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} className="border-b border-slate-100 last:border-0 hover:bg-slate-50">
                  <td className="px-3 py-2">
                    <SeverityChip severity={row.severity} />
                  </td>
                  <td className="px-3 py-2">
                    <Link href={`/alerts/${row.id}`} className="font-medium text-blue-700 hover:underline">
                      {row.triage_verdict ?? 'no decision yet'}
                    </Link>
                    <div className="text-xs text-slate-400">{row.reason ?? ''}</div>
                  </td>
                  <td className="px-3 py-2">{formatConfidence(row.confidence_margin)}</td>
                  <td className="px-3 py-2 text-slate-600">{row.attack_category ?? 'n/a'}</td>
                  <td className="px-3 py-2 text-slate-600">{row.source}</td>
                  <td className="px-3 py-2 text-slate-500">{formatDateTime(row.ingested_at)}</td>
                  <td className="px-3 py-2">
                    <FeedbackButtons alertId={row.id} triageVerdict={row.triage_verdict} compact />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
