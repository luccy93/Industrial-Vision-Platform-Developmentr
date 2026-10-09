import type { ReactNode } from "react";
import type { SectionState } from "../../types";

const SECTION_STYLE: Record<SectionState, string> = {
  ok: "bg-emerald-500/15 text-emerald-300",
  degraded: "bg-amber-500/15 text-amber-300",
  unavailable: "bg-slate-500/15 text-slate-400",
};

export function SectionBadge({ state, label }: { state: SectionState; label?: string }) {
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-xs font-medium ${SECTION_STYLE[state]}`}
      aria-label={`section status: ${state}`}
    >
      {label ?? state}
    </span>
  );
}

/** Severity text with an explicit glyph — never color alone. */
export function StateText({ level, text }: { level: string; text?: string }) {
  const glyph =
    level === "CRITICAL" || level === "P0"
      ? "⬢"
      : level === "HIGH" || level === "P1"
        ? "▲"
        : level === "MEDIUM" || level === "P2"
          ? "●"
          : "○";
  return (
    <span>
      <span aria-hidden="true">{glyph} </span>
      {text ?? level}
    </span>
  );
}

export function DataState({
  state,
  emptyText,
  error,
  children,
}: {
  state: "loading" | "ready" | "empty" | "error" | "stale";
  emptyText: string;
  error?: string | null;
  children?: ReactNode;
}) {
  if (state === "loading") {
    return <p className="text-sm text-slate-400" role="status">Loading…</p>;
  }
  if (state === "error") {
    return (
      <p className="text-sm text-amber-300" role="alert">
        Unavailable{error ? ` (${error})` : ""} — showing nothing rather than stale data.
      </p>
    );
  }
  if (state === "empty") {
    return <p className="text-sm text-slate-400">{emptyText}</p>;
  }
  return (
    <div>
      {state === "stale" && (
        <p className="mb-2 text-xs text-amber-300" role="status">
          Stale — last successful refresh is older than expected.
        </p>
      )}
      {children}
    </div>
  );
}

export function FreshnessBadge({ ageMs, staleAfterMs }: { ageMs: number | null; staleAfterMs: number }) {
  if (ageMs === null) {
    return <span className="text-xs text-slate-500">age unknown</span>;
  }
  const seconds = Math.floor(ageMs / 1000);
  const stale = ageMs > staleAfterMs;
  const label = seconds < 60 ? `${seconds}s ago` : `${Math.floor(seconds / 60)}m ago`;
  return (
    <span className={`text-xs ${stale ? "text-amber-300" : "text-slate-500"}`} title={stale ? "stale" : "fresh"}>
      {stale ? "stale · " : ""}
      {label}
    </span>
  );
}
