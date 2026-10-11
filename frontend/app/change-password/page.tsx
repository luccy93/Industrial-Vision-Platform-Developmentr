"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../components/auth/AuthProvider";

export default function ChangePasswordPage() {
  const router = useRouter();
  const { changePassword, loading, user } = useAuth();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (newPassword !== confirm) {
      setError("New passwords do not match.");
      return;
    }
    if (newPassword.length < 15) {
      setError("New password must be at least 15 characters.");
      return;
    }
    try {
      await changePassword(currentPassword, newPassword);
      router.push("/dashboard");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Password change failed.");
    }
  }

  return (
    <div className="mx-auto flex min-h-[70vh] max-w-md flex-col justify-center">
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-8">
        <p className="text-xs font-semibold uppercase tracking-widest text-sky-400">
          Industrial AI Vision
        </p>
        <h1 className="mt-2 text-2xl font-bold text-slate-100">Change password</h1>
        <p className="mt-1 text-sm text-slate-400">
          {user?.must_change_password
            ? "Your administrator requires a password change before you continue."
            : "Passwords must be 15–128 characters. Other sessions are signed out."}
        </p>
        <form onSubmit={onSubmit} className="mt-6 space-y-4" noValidate>
          <div>
            <label htmlFor="cp-current" className="mb-1 block text-sm font-medium text-slate-300">
              Current password
            </label>
            <input
              id="cp-current"
              type="password"
              autoComplete="current-password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500"
            />
          </div>
          <div>
            <label htmlFor="cp-new" className="mb-1 block text-sm font-medium text-slate-300">
              New password
            </label>
            <input
              id="cp-new"
              type="password"
              autoComplete="new-password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500"
            />
          </div>
          <div>
            <label htmlFor="cp-confirm" className="mb-1 block text-sm font-medium text-slate-300">
              Confirm new password
            </label>
            <input
              id="cp-confirm"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500"
            />
          </div>
          {error && (
            <p role="alert" className="text-sm text-red-300">
              {error}
            </p>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-sky-600 px-4 py-2 font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {loading ? "Updating…" : "Update password"}
          </button>
        </form>
      </div>
    </div>
  );
}
