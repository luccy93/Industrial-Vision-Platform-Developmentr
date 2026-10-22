# syntax=docker/dockerfile:1

# Industrial Vision Platform — frontend production image.
#
# Uses the project's own Next.js standalone output (next.config.js sets
# output: "standalone"): the runner carries only server.js + pruned
# static assets, no devDependencies, no source. NEXT_PUBLIC_* values bake
# at build time — pass them as build args (dev defaults below); production
# deployments set the public browser-facing URLs explicitly.

ARG NODE_BASE=node:20-alpine
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ARG NEXT_PUBLIC_WS_URL=ws://localhost:8000
# V20 security-header build switches (report-only CSP by default; HSTS off
# until the deployment confirms HTTPS termination).
ARG CSP_ENFORCE=false
ARG HSTS_ENABLED=false

FROM ${NODE_BASE} AS deps
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

FROM ${NODE_BASE} AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY frontend ./
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_PUBLIC_WS_URL=${NEXT_PUBLIC_WS_URL} \
    CSP_ENFORCE=${CSP_ENFORCE} \
    HSTS_ENABLED=${HSTS_ENABLED}
RUN npm run build

FROM ${NODE_BASE} AS runner
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0
# V21 image-scan hardening: pick up base-image package fixes, then drop the
# bundled npm/corepack CLI. The runner only executes `node server.js`, so the
# CLI (and its transitive dependency tree) is unused attack surface.
RUN apk upgrade --no-cache \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --from=builder --chown=appuser:appgroup /app/.next/standalone ./
COPY --from=builder --chown=appuser:appgroup /app/.next/static ./.next/static
USER appuser
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["node", "-e", "fetch('http://localhost:3000/').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

CMD ["node", "server.js"]
