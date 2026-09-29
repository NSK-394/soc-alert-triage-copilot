import { severityStyle } from '@/lib/format';

export function SeverityChip({ severity }: { severity: string | null | undefined }) {
  return (
    <span
      className={`inline-block rounded-full border px-2.5 py-0.5 text-xs font-medium capitalize ${severityStyle(
        severity,
      )}`}
    >
      {severity ?? 'unknown'}
    </span>
  );
}
