export function JsonView({ data }: { data: unknown }) {
  return (
    <pre className="max-h-[32rem] overflow-auto rounded-md bg-slate-950 p-3 text-xs text-slate-100">
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}
