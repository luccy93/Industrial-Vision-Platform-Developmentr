"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useAuth } from "../../components/auth/AuthProvider";
import {
  createUser,
  fetchUsers,
  patchUser,
  revokeUserSessions,
} from "../../lib/auth/client";
import type { AuthUser } from "../../types";

export default function UsersPage() {
  const { isAdmin, user: me } = useAuth();
  const [users, setUsers] = useState<AuthUser[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("VIEWER");

  const refresh = useCallback(async () => {
    try {
      const body = await fetchUsers(1, 50);
      setUsers(body.users);
      setTotal(body.total);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load users.");
    }
  }, []);

  useEffect(() => {
    if (isAdmin) void refresh();
  }, [isAdmin, refresh]);

  async function onCreate(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    try {
      const { user } = await createUser({ email: email.trim(), password, role });
      setEmail("");
      setPassword("");
      setNotice(`Created ${user.email}; they must change their password at first login.`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "User creation failed.");
    }
  }

  async function act(id: string, fn: () => Promise<unknown>, done: string) {
    setError(null);
    setNotice(null);
    try {
      await fn();
      setNotice(done);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Operation failed.");
    }
  }

  if (!isAdmin) {
    return (
      <div className="space-y-4">
        <h1 className="text-lg font-bold">Users</h1>
        <p role="alert" className="text-sm text-amber-300">
          Administrators only. Your role does not permit user management.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-lg font-bold">Users</h1>
          <p className="text-sm text-slate-400">
            {total} identities. New accounts sign in with a forced password change.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void refresh()}
          className="rounded-lg border border-slate-700 px-3 py-1.5 text-sm hover:bg-slate-800"
        >
          Refresh
        </button>
      </div>
      {error && (
        <p role="alert" className="text-sm text-red-300">
          {error}
        </p>
      )}
      {notice && <p className="text-sm text-emerald-300">{notice}</p>}
      <form
        onSubmit={onCreate}
        className="grid gap-3 rounded-xl border border-slate-800 bg-slate-900/60 p-4 md:grid-cols-4"
      >
        <div>
          <label htmlFor="new-email" className="mb-1 block text-sm text-slate-300">
            Email
          </label>
          <input
            id="new-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 outline-none focus:border-sky-500"
          />
        </div>
        <div>
          <label htmlFor="new-password" className="mb-1 block text-sm text-slate-300">
            Initial password (15+ chars)
          </label>
          <input
            id="new-password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 outline-none focus:border-sky-500"
          />
        </div>
        <div>
          <label htmlFor="new-role" className="mb-1 block text-sm text-slate-300">
            Role
          </label>
          <select
            id="new-role"
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 outline-none focus:border-sky-500"
          >
            <option value="VIEWER">VIEWER</option>
            <option value="OPERATOR">OPERATOR</option>
            <option value="ADMIN">ADMIN</option>
          </select>
        </div>
        <div className="flex items-end">
          <button
            type="submit"
            className="rounded-lg bg-sky-600 px-4 py-1.5 font-semibold text-white hover:bg-sky-500"
          >
            Create user
          </button>
        </div>
      </form>
      <ul className="space-y-2">
        {users.map((u) => (
          <li
            key={u.id}
            className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2"
          >
            <span className="font-medium text-slate-200">{u.email}</span>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-300">{u.role}</span>
            {!u.is_active && (
              <span className="rounded bg-red-500/15 px-2 py-0.5 text-xs text-red-300">inactive</span>
            )}
            {u.must_change_password && (
              <span className="rounded bg-amber-500/15 px-2 py-0.5 text-xs text-amber-300">
                password change required
              </span>
            )}
            {me?.id !== u.id && (
              <span className="ml-auto flex flex-wrap gap-1">
                <select
                  aria-label={`Role for ${u.email}`}
                  value={u.role}
                  onChange={(e) =>
                    void act(u.id, () => patchUser(u.id, { role: e.target.value }), `Role updated for ${u.email}.`)
                  }
                  className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs"
                >
                  <option value="VIEWER">VIEWER</option>
                  <option value="OPERATOR">OPERATOR</option>
                  <option value="ADMIN">ADMIN</option>
                </select>
                <button
                  type="button"
                  onClick={() =>
                    void act(
                      u.id,
                      () => patchUser(u.id, { is_active: !u.is_active }),
                      `${u.email} ${u.is_active ? "deactivated" : "reactivated"}.`
                    )
                  }
                  className="rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800"
                >
                  {u.is_active ? "Deactivate" : "Reactivate"}
                </button>
                <button
                  type="button"
                  onClick={() =>
                    void act(u.id, () => revokeUserSessions(u.id), `Sessions revoked for ${u.email}.`)
                  }
                  className="rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800"
                >
                  Revoke sessions
                </button>
              </span>
            )}
          </li>
        ))}
      </ul>
      {users.length === 0 && !error && (
        <p className="text-sm text-slate-400">No user records returned.</p>
      )}
    </div>
  );
}
