const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Validate that a URL path segment is syntactically a UUID before it ever reaches a query. */
export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  low: 2,
  informational: 1,
};

export function severityRank(severity: string | null | undefined): number {
  if (!severity) return 0;
  return SEVERITY_ORDER[severity] ?? 0;
}

export const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-300',
  high: 'bg-orange-100 text-orange-800 border-orange-300',
  low: 'bg-yellow-100 text-yellow-800 border-yellow-300',
  informational: 'bg-slate-100 text-slate-700 border-slate-300',
};

export function severityStyle(severity: string | null | undefined): string {
  if (!severity) return 'bg-slate-100 text-slate-500 border-slate-300';
  return SEVERITY_STYLES[severity] ?? 'bg-slate-100 text-slate-500 border-slate-300';
}

/** confidence_margin is stored 0-1; render it as a percentage-ish display value. */
export function formatConfidence(margin: string | number | null | undefined): string {
  if (margin === null || margin === undefined) return 'n/a';
  const n = typeof margin === 'string' ? parseFloat(margin) : margin;
  if (Number.isNaN(n)) return 'n/a';
  return `${(n * 100).toFixed(1)}%`;
}

export function formatUsd(value: string | number | null | undefined, digits = 4): string {
  if (value === null || value === undefined) return '$0';
  const n = typeof value === 'string' ? parseFloat(value) : value;
  if (Number.isNaN(n)) return '$0';
  return `$${n.toFixed(digits)}`;
}

export function formatDateTime(value: string | Date | null | undefined): string {
  if (!value) return 'n/a';
  const d = typeof value === 'string' ? new Date(value) : value;
  return d.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}
