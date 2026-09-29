import { updateTier2Model } from '@/app/actions/settings';
import { getTier2ModelSetting } from '@/lib/queries';
import { ProviderDropdownForm } from './ProviderDropdownForm';
import type { Tier2Model } from '@/lib/types';

/**
 * Global Tier-2 provider dropdown (header, visible everywhere). Nice-to-have per
 * docs/architecture.md §9 ("a later iteration adds a dropdown..."), included since it's
 * cheap given the settings table already exists. Writes settings.tier2_model via upsert;
 * tier2-worker (a parallel agent's service) is what reads it later. No other wiring here.
 */
export async function ProviderDropdown() {
  const current = ((await getTier2ModelSetting()) ?? 'luna') as Tier2Model;
  return <ProviderDropdownForm current={current} action={updateTier2Model} />;
}
