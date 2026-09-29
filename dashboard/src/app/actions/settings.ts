'use server';

import { revalidatePath } from 'next/cache';
import { setTier2ModelSetting } from '@/lib/queries';
import { TIER2_MODELS, type Tier2Model } from '@/lib/types';

/**
 * Global provider dropdown (header): upserts settings.tier2_model.
 * No other backend wiring here — tier2-worker (owned by a parallel agent) is what
 * reads this key later; this action only writes it.
 */
export async function updateTier2Model(formData: FormData) {
  const model = formData.get('model');
  if (typeof model !== 'string' || !(TIER2_MODELS as readonly string[]).includes(model)) {
    throw new Error('Invalid model');
  }
  await setTier2ModelSetting(model as Tier2Model);
  revalidatePath('/', 'layout');
}
