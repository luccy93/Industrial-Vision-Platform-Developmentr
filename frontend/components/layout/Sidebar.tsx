"use client";

import Link from "next/link";
import { NAV_ITEMS } from "@/types";
import { useAuth } from "../auth/AuthProvider";

export function Sidebar() {
  const { user } = useAuth();
  const visible = NAV_ITEMS.filter((item) => {
    if (!item.roles) return true;
    if (!user) return true; // Unknown identity: show all; backend enforces.
    return item.roles.includes(user.role);
  });
  return (
    <aside className="w-60 shrink-0 border-r border-slate-800 bg-slate-900/60 p-4">
      <div className="mb-6">
        <p className="text-sm font-bold tracking-wide">Industrial AI Vision</p>
        <p className="text-xs text-slate-400">Safety Intelligence Platform · V01</p>
      </div>
      <nav className="space-y-1">
        {visible.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className="block rounded-lg px-3 py-2 text-sm hover:bg-slate-800"
          >
            <span className="font-medium">{item.label}</span>
            <span className="block text-xs text-slate-400">{item.note}</span>
          </Link>
        ))}
      </nav>
      <div className="mt-6 rounded-lg bg-slate-800/60 p-3 text-xs text-slate-300">
        Cameras, incidents, analytics arrive in later volumes.
      </div>
    </aside>
  );
}
