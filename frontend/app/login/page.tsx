"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../components/auth/AuthProvider";

function safeNext(value: string | null): string {
  if (value && value.startsWith("/") && !value.startsWith("//")) return value;
  return "/dashboard";
}

export default function LoginPage() {
  const router = useRouter();
  const { login, loading } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setFieldError(null);
    setSubmitError(null);
    if (!email.trim() || !password) {
      setFieldError("Email and password are required.");
      return;
    }
    try {
      const { mustChangePassword } = await login(email.trim(), password);
      const params = new URLSearchParams(window.location.search);
      if (mustChangePassword) {
        router.push("/change-password");
      } else {
        router.push(safeNext(params.get("next")));
      }
    } catch (e) {
      setSubmitError(e instanceof Error ? e.message : "Login failed.");
    }
  }

  return (
    <div className="mx-auto flex min-h-[70vh] max-w-md flex-col justify-center">
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-8">
        <p className="text-xs font-semibold uppercase tracking-widest text-sky-400">
          Industrial AI Vision
        </p>
        <h1 className="mt-2 text-2xl font-bold text-slate-100">Sign in</h1>
        <p className="mt-1 text-sm text-slate-400">
          Authenticated access to operations, analytics, incidents, and notifications.
        </p>
        <form onSubmit={onSubmit} className="mt-6 space-y-4" noValidate>
          <div>
            <label htmlFor="login-email" className="mb-1 block text-sm font-medium text-slate-300">
              Email
            </label>
            <input
              id="login-email"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500"
            />
          </div>
          <div>
            <label htmlFor="login-password" className="mb-1 block text-sm font-medium text-slate-300">
              Password
            </label>
            <input
              id="login-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500"
            />
          </div>
          {fieldError && (
            <p role="alert" className="text-sm text-amber-300">
              {fieldError}
            </p>
          )}
          {submitError && (
            <p role="alert" className="text-sm text-red-300">
              {submitError}
            </p>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-sky-600 px-4 py-2 font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {loading ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
