'use client';

import { TIER2_MODELS, type Tier2Model } from '@/lib/types';

export function ProviderDropdownForm({
  current,
  action,
}: {
  current: Tier2Model;
  action: (formData: FormData) => void | Promise<void>;
}) {
  return (
    <form action={action} className="flex items-center gap-2 text-sm text-slate-300">
      <label htmlFor="tier2-model" className="text-xs uppercase tracking-wide text-slate-400">
        Tier-2 model
      </label>
      <select
        id="tier2-model"
        name="model"
        defaultValue={current}
        onChange={(e) => e.currentTarget.form?.requestSubmit()}
        className="rounded border border-slate-600 bg-slate-900 px-2 py-1 text-white capitalize"
      >
        {TIER2_MODELS.map((model) => (
          <option key={model} value={model} className="capitalize">
            {model}
          </option>
        ))}
      </select>
    </form>
  );
}
