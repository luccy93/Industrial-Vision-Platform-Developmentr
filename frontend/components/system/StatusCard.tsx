export function StatusCard({ label, status }: { label: string; status: string }) {
  const healthy = /ok|up|healthy|ready|enabled/i.test(status);
  return (
    <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2">
      <span className="text-sm text-slate-300">{label}</span>
      <span
        className={`rounded-full px-2 py-0.5 text-xs ${
          healthy ? "bg-emerald-500/15 text-emerald-300" : "bg-amber-500/15 text-amber-300"
        }`}
      >
        {status}
      </span>
    </div>
  );
}
