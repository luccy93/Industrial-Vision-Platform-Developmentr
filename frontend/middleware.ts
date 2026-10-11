import { NextResponse, type NextRequest } from "next/server";

/**
 * Fast redirect layer only (V16) — presence of the session cookie decides
 * navigation, never authorization. FastAPI enforces every data decision;
 * the root layout re-verifies the session server-side via the DAL.
 */

const SESSION_COOKIE = "ivp_session";
const PUBLIC_PATHS = new Set(["/", "/login"]);

function safeNext(value: string | null): string {
  if (value && value.startsWith("/") && !value.startsWith("//")) return value;
  return "/dashboard";
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const response = NextResponse.next();
  response.headers.set("x-pathname", pathname);
  const hasSession = request.cookies.has(SESSION_COOKIE);

  if (pathname === "/login") {
    if (hasSession) {
      const url = request.nextUrl.clone();
      const next = request.nextUrl.searchParams.get("next");
      url.pathname = safeNext(next);
      url.search = "";
      return NextResponse.redirect(url);
    }
    return response;
  }
  if (PUBLIC_PATHS.has(pathname)) return response;
  if (!hasSession) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    url.searchParams.set("next", safeNext(pathname));
    return NextResponse.redirect(url);
  }
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
