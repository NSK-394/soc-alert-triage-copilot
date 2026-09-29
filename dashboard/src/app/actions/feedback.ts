'use server';

import { revalidatePath } from 'next/cache';
import { insertFeedback } from '@/lib/queries';
import { isUuid } from '@/lib/format';

/**
 * Analyst feedback buttons (queue list + alert detail) both post here.
 * Simplest defensible choice per spec: correct/incorrect buttons directly set
 * correct=true/false and copy the alert's current triage_verdict into analyst_verdict.
 * A free-text notes field is included as a nice-to-have.
 */
export async function submitFeedback(formData: FormData) {
  const alertId = formData.get('alertId');
  const triageVerdict = formData.get('triageVerdict');
  const correctValue = formData.get('correct');
  const notes = formData.get('notes');

  if (typeof alertId !== 'string' || !isUuid(alertId)) {
    throw new Error('Invalid alert id');
  }
  if (correctValue !== 'true' && correctValue !== 'false') {
    throw new Error('Invalid feedback value');
  }

  const analystVerdict = typeof triageVerdict === 'string' && triageVerdict.length > 0
    ? triageVerdict
    : 'unknown';

  await insertFeedback({
    alertId,
    analystVerdict,
    correct: correctValue === 'true',
    notes: typeof notes === 'string' && notes.trim().length > 0 ? notes.trim() : null,
  });

  revalidatePath('/queue');
  revalidatePath(`/alerts/${alertId}`);
}
