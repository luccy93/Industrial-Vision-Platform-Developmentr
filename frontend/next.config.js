// Browser-facing API/WS origins are baked at build time (same values the app
// uses for fetch/socket connections). They become the CSP `connect-src`.
const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";

function httpOrigin(value) {
  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
}

function wsOrigin(value) {
  try {
    const parsed = new URL(value);
    parsed.protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
    return parsed.origin;
  } catch {
    return "";
  }
}

// Two-stage CSP rollout (V20): report-only by default, promote to enforcing
// with CSP_ENFORCE=true once violations are reviewed in a real deployment.
const cspReportOnly = process.env.CSP_ENFORCE !== "true";
const cspHeaderName = cspReportOnly
  ? "Content-Security-Policy-Report-Only"
  : "Content-Security-Policy";

const connectSrc = ["'self'", httpOrigin(API_URL), wsOrigin(WS_URL)]
  .filter(Boolean)
  .join(" ");

const contentSecurityPolicy = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self'",
  `connect-src ${connectSrc}`,
  "upgrade-insecure-requests",
].join("; ");

const securityHeaders = [
  { key: cspHeaderName, value: contentSecurityPolicy },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "X-Permitted-Cross-Domain-Policies", value: "none" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
  },
];

// HSTS is opt-in: only enable once the deployment terminates HTTPS for the
// frontend (and all subdomains if includeSubDomains is added). Defaults off
// so plain-HTTP local development is never pinned to HTTPS by the browser.
if (process.env.HSTS_ENABLED === "true") {
  securityHeaders.push({
    key: "Strict-Transport-Security",
    value: "max-age=31536000",
  });
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: "standalone",
  poweredByHeader: false,
  async headers() {
    return [{ source: "/(.*)", headers: securityHeaders }];
  },
};

module.exports = nextConfig;
