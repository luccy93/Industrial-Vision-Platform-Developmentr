"use client";

import { useAuth } from "../auth/AuthProvider";

export function Header() {
  const { user, logout } = useAuth();
  return (
    <header className="flex items-center justify-between border-b border-slate-800 bg-slate-900/40 px-6 py-3">
      <h1 className="text-sm font-semibold">Platform Shell — V01 Foundation</h1>
      <span className="flex items-center gap-3">
        {user && (
          <span className="text-xs text-slate-300">
            {user.email} · {user.role}
          </span>
        )}
        {user && (
          <button
            type="button"
            onClick={() => void logout()}
            className="rounded-lg border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800"
          >
            Sign out
          </button>
        )}
        <span className="rounded-full bg-emerald-500/15 px-3 py-1 text-xs text-emerald-300">
          System Operational (foundation)
        </span>
      </span>
    </header>
  );
}
