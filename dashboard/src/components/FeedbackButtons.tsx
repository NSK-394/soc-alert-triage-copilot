import { submitFeedback } from '@/app/actions/feedback';

/**
 * Correct/incorrect feedback pair, used on both the queue list and alert detail.
 * Writes to the `feedback` table (the same table the benchmark report reads from).
 * analyst_verdict is the alert's current jev_decisions.triage_verdict, copied over;
 * correct is set directly by which button was pressed. Works with plain HTML form
 * submission (no client JS required) via the Server Action passed as `action`.
 */
export function FeedbackButtons({
  alertId,
  triageVerdict,
  compact = false,
  includeNotes = false,
}: {
  alertId: string;
  triageVerdict: string | null;
  compact?: boolean;
  includeNotes?: boolean;
}) {
  return (
    <form action={submitFeedback} className="flex flex-wrap items-center gap-2">
      <input type="hidden" name="alertId" value={alertId} />
      <input type="hidden" name="triageVerdict" value={triageVerdict ?? ''} />
      {includeNotes && (
        <input
          type="text"
          name="notes"
          placeholder="Notes (optional)"
          className="rounded border border-slate-300 px-2 py-1 text-xs"
        />
      )}
      <button
        type="submit"
        name="correct"
        value="true"
        className={`rounded border border-green-600 bg-green-50 text-green-700 hover:bg-green-100 ${
          compact ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm'
        }`}
      >
        Correct
      </button>
      <button
        type="submit"
        name="correct"
        value="false"
        className={`rounded border border-red-600 bg-red-50 text-red-700 hover:bg-red-100 ${
          compact ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm'
        }`}
      >
        Incorrect
      </button>
    </form>
  );
}
