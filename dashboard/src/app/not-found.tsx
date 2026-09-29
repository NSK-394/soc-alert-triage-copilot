import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="rounded-md border border-dashed border-slate-300 p-8 text-center">
      <h1 className="text-xl font-semibold">Not found</h1>
      <p className="mt-2 text-sm text-slate-500">
        That alert doesn&apos;t exist, or the id in the URL wasn&apos;t valid.
      </p>
      <Link href="/queue" className="mt-4 inline-block text-sm text-blue-700 hover:underline">
        Back to queue
      </Link>
    </div>
  );
}
