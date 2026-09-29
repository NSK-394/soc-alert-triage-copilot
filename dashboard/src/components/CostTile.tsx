import { getCostSummary } from '@/lib/queries';
import { formatUsd } from '@/lib/format';

/**
 * Live "cost per 1,000 alerts" tile, queried server-side on every request (no
 * websockets needed — a fresh server-rendered value per page load satisfies "live").
 * Splits Jev spend vs. Tier-2 spend per docs/architecture.md §9.
 */
export async function CostTile() {
  const { perCallType, totalAlerts } = await getCostSummary();

  const jev = perCallType.find((r) => r.call_type === 'jev');
  const tier2 = perCallType.find((r) => r.call_type === 'tier2');
  const totalCost = perCallType.reduce((sum, r) => sum + parseFloat(r.total_cost_usd), 0);

  const per1000 = (costUsd: number) => (totalAlerts > 0 ? (costUsd / totalAlerts) * 1000 : 0);

  return (
    <div className="flex items-center gap-4 rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-sm">
      <div>
        <div className="text-[11px] uppercase tracking-wide text-slate-400">Cost / 1,000 alerts</div>
        <div className="text-lg font-semibold text-white">
          {totalAlerts > 0 ? formatUsd(per1000(totalCost), 2) : 'n/a'}
        </div>
      </div>
      <div className="h-8 w-px bg-slate-700" />
      <div className="flex gap-3 text-xs text-slate-300">
        <div>
          <span className="text-slate-500">Jev</span>{' '}
          {totalAlerts > 0 ? formatUsd(per1000(jev ? parseFloat(jev.total_cost_usd) : 0), 2) : 'n/a'}
        </div>
        <div>
          <span className="text-slate-500">Tier-2</span>{' '}
          {totalAlerts > 0
            ? formatUsd(per1000(tier2 ? parseFloat(tier2.total_cost_usd) : 0), 2)
            : 'n/a'}
        </div>
      </div>
    </div>
  );
}
