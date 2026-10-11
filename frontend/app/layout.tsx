import type { Metadata } from "next";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import "../styles/globals.css";
import { AuthProvider } from "../components/auth/AuthProvider";
import { Header } from "../components/layout/Header";
import { Sidebar } from "../components/layout/Sidebar";
import { getSessionUser, safeNext } from "../lib/auth/dal";

export const metadata: Metadata = {
  title: "Industrial AI Vision Platform — V01",
  description: "Foundation shell for industrial safety intelligence."
};

const PUBLIC_PATHS = new Set(["/", "/login"]);

/**
 * Server-side route gate (V16). The middleware already redirects
 * cookie-less browsers; this layer re-verifies the session against
 * FastAPI /me (no-store) so direct URL access without a *valid*
 * session cannot render protected shells. Backend stays authoritative.
 */
export default async function RootLayout({ children }: { children: React.ReactNode }) {
  let pathname = "/";
  try {
    pathname = headers().get("x-pathname") ?? "/";
  } catch {
    pathname = "/";
  }
  let initialUser = null;
  try {
    initialUser = await getSessionUser();
  } catch {
    initialUser = null;
  }
  if (!PUBLIC_PATHS.has(pathname)) {
    if (!initialUser) {
      redirect(`/login?next=${encodeURIComponent(safeNext(pathname))}`);
    } else if (initialUser.must_change_password && pathname !== "/change-password") {
      redirect("/change-password");
    } else if ((pathname === "/users" || pathname.startsWith("/users/")) && initialUser.role !== "ADMIN") {
      redirect("/dashboard");
    }
  }
  return (
    <html lang="en">
      <body>
        <AuthProvider initialUser={initialUser}>
          <div className="flex min-h-screen">
            <Sidebar />
            <div className="flex min-w-0 flex-1 flex-col">
              <Header />
              <main className="flex-1 p-6">{children}</main>
            </div>
          </div>
        </AuthProvider>
      </body>
    </html>
  );
}
