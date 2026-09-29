import Link from 'next/link';
import { notFound } from 'next/navigation';
import { getAlert, getLatestBrief, getLatestJevDecision, getLatestPolicyOutcome } from '@/lib/queries';
import { isUuid, formatConfidence, formatDateTime } from '@/lib/format';
import { SeverityChip } from '@/components/SeverityChip';
import { JsonView } from '@/components/JsonView';
import { FeedbackButtons } from '@/components/FeedbackButtons';

export const dynamic = 'force-dynamic';

export default async function AlertDetailPage({ params }: { params: { id: string } }) {
  // Input hygiene: alert ids come from the URL path. Validate they're syntactically a
  // UUID before ever touching a query, and return a clean 404 rather than passing raw
  // path input through.
  if (!isUuid(params.id)) {
    notFound();
  }

  const alert = await getAlert(params.id);
  if (!alert) {
    notFound();
  }

  const [decision, policy, brief] = await Promise.all([
    getLatestJevDecision(alert.id),
    getLatestPolicyOutcome(alert.id),
    getLatestBrief(alert.id),
  ]);

  return (
    <div className="space-y-6">
      <div>
        <Link href="/queue" className="text-sm text-blue-700 hover:underline">
          &larr; Back to queue
        </Link>
        <div className="mt-1 flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold">Alert {alert.id}</h1>
          {decision && <SeverityChip severity={decision.severity} />}
        </div>
        <p className="text-sm text-slate-500">
          {alert.source} &middot; ingested {formatDateTime(alert.ingested_at)}
          {alert.incident_id ? ` · incident ${alert.incident_id}` : ''}
          {alert.external_id ? ` · external id ${alert.external_id}` : ''}
        </p>
      </div>

      <section className="rounded-md border border-slate-200 p-4">
        <h2 className="mb-2 text-lg font-medium">Normalized state</h2>
        <JsonView data={alert.normalized} />
      </section>

      <section className="rounded-md border border-slate-200 p-4">
        <h2 className="mb-2 text-lg font-medium">Jev decision</h2>
        {decision ? (
          <div className="space-y-3">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
              <div>
                <dt className="text-xs uppercase text-slate-500">Verdict</dt>
                <dd className="font-medium">{decision.triage_verdict}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase text-slate-500">Severity</dt>
                <dd><SeverityChip severity={decision.severity} /></dd>
              </div>
              <div>
                <dt className="text-xs uppercase text-slate-500">Confidence margin</dt>
                <dd className="font-medium">{formatConfidence(decision.confidence_margin)}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase text-slate-500">Attack category</dt>
                <dd className="font-medium">{decision.attack_category ?? 'n/a'}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase text-slate-500">FP probability</dt>
                <dd className="font-medium">{formatConfidence(decision.is_false_positive_prob)}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase text-slate-500">Needs more context</dt>
                <dd className="font-medium">{formatConfidence(decision.needs_more_context_prob)}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase text-slate-500">Business impact if true</dt>
                <dd className="font-medium">{decision.business_impact_if_true ?? 'n/a'}</dd>
              </div>
              <div>
                <dt className="text-xs uppercase text-slate-500">Latency</dt>
                <dd className="font-medium">{decision.latency_ms != null ? `${decision.latency_ms} ms` : 'n/a'}</dd>
              </div>
            </dl>
            <div>
              <div className="mb-1 text-xs uppercase text-slate-500">Raw response</div>
              <JsonView data={decision.raw_response} />
            </div>
          </div>
        ) : (
          <p className="text-sm text-slate-500">No Jev decision recorded yet.</p>
        )}
      </section>

      <section className="rounded-md border border-slate-200 p-4">
        <h2 className="mb-2 text-lg font-medium">Policy decision</h2>
        {policy ? (
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
            <div>
              <dt className="text-xs uppercase text-slate-500">Action</dt>
              <dd className="font-medium capitalize">{policy.action.replace('_', ' ')}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase text-slate-500">Rule version</dt>
              <dd className="font-medium">{policy.rule_version}</dd>
            </div>
            <div className="col-span-2">
              <dt className="text-xs uppercase text-slate-500">Reason</dt>
              <dd className="font-medium">{policy.reason ?? 'n/a'}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase text-slate-500">Shadow mode</dt>
              <dd className="font-medium">{policy.shadow_mode ? 'yes' : 'no'}</dd>
            </div>
          </dl>
        ) : (
          <p className="text-sm text-slate-500">No policy outcome recorded yet.</p>
        )}
      </section>

      <section className="rounded-md border border-slate-200 p-4">
        <h2 className="mb-2 text-lg font-medium">Tier-2 brief</h2>
        {brief ? (
          <Link href={`/alerts/${alert.id}/brief`} className="text-sm text-blue-700 hover:underline">
            View brief (generated by {brief.provider_model}) &rarr;
          </Link>
        ) : (
          <p className="text-sm text-slate-500">No brief has been generated for this alert.</p>
        )}
      </section>

      <section className="rounded-md border border-slate-200 p-4">
        <h2 className="mb-2 text-lg font-medium">Analyst feedback</h2>
        <FeedbackButtons alertId={alert.id} triageVerdict={decision?.triage_verdict ?? null} includeNotes />
      </section>
    </div>
  );
}
