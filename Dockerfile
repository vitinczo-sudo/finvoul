# ══════════════════════════════════════════════
# FinVault — Dockerfile (multi-stage)
# ══════════════════════════════════════════════

# ── Stage 1: deps
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# ── Stage 2: production
FROM node:20-alpine AS runner
WORKDIR /app

# Segurança: usuário não-root
RUN addgroup --system --gid 1001 finvault && \
    adduser  --system --uid 1001 finvault

COPY --from=deps --chown=finvault:finvault /app/node_modules ./node_modules
COPY --chown=finvault:finvault . .

# Gerar chaves RSA se não existirem (dev only — prod usa env vars)
RUN mkdir -p keys && \
    if [ ! -f keys/private.pem ]; then \
      apk add --no-cache openssl && \
      openssl genrsa -out keys/private.pem 4096 && \
      openssl rsa -in keys/private.pem -pubout -out keys/public.pem && \
      chmod 600 keys/private.pem; \
    fi

USER finvault

ENV NODE_ENV=production
EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:3001/health || exit 1

CMD ["node", "server.js"]
