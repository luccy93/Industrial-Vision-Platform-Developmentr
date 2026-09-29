import { ReactNode } from "react";

export function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <h2 className="mb-2 text-sm font-semibold text-slate-200">{title}</h2>
      <div className="text-sm text-slate-300">{children}</div>
    </div>
  );
}
