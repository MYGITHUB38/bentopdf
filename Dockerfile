# Global variable declaration:
# Build to serve under Subdirectory BASE_URL if provided, eg: "ARG BASE_URL=/pdf/", otherwise leave blank: "ARG BASE_URL="
ARG BASE_URL=

# Build stage
FROM public.ecr.aws/docker/library/node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
COPY vendor ./vendor
ENV HUSKY=0
RUN npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 60000 && \
    npm config set fetch-retry-maxtimeout 300000 && \
    npm config set fetch-timeout 600000 && \
    npm ci
COPY . .

# Build without type checking (vite build only)
# Pass SIMPLE_MODE environment variable if provided
ARG SIMPLE_MODE=false
ENV SIMPLE_MODE=$SIMPLE_MODE
ARG DISABLE_GITHUB_STARS=false
ENV DISABLE_GITHUB_STARS=$DISABLE_GITHUB_STARS
ARG COMPRESSION_MODE=all
ENV COMPRESSION_MODE=$COMPRESSION_MODE

# global arg to local arg - BASE_URL is read from env by vite.config.ts
ARG BASE_URL
ENV BASE_URL=$BASE_URL

# WASM module URLs (pre-configured defaults)
# Override these for air-gapped or self-hosted WASM deployments
ARG VITE_WASM_PYMUPDF_URL
ARG VITE_WASM_GS_URL
ARG VITE_WASM_CPDF_URL
ENV VITE_WASM_PYMUPDF_URL=$VITE_WASM_PYMUPDF_URL
ENV VITE_WASM_GS_URL=$VITE_WASM_GS_URL
ENV VITE_WASM_CPDF_URL=$VITE_WASM_CPDF_URL

# OCR asset URLs (optional, used for self-hosted or air-gapped OCR)
ARG VITE_TESSERACT_WORKER_URL
ARG VITE_TESSERACT_CORE_URL
ARG VITE_TESSERACT_LANG_URL
ARG VITE_TESSERACT_AVAILABLE_LANGUAGES
ARG VITE_OCR_FONT_BASE_URL
ENV VITE_TESSERACT_WORKER_URL=$VITE_TESSERACT_WORKER_URL
ENV VITE_TESSERACT_CORE_URL=$VITE_TESSERACT_CORE_URL
ENV VITE_TESSERACT_LANG_URL=$VITE_TESSERACT_LANG_URL
ENV VITE_TESSERACT_AVAILABLE_LANGUAGES=$VITE_TESSERACT_AVAILABLE_LANGUAGES
ENV VITE_OCR_FONT_BASE_URL=$VITE_OCR_FONT_BASE_URL

# Default UI language (e.g. en, fr, de, es, zh, ar)
ARG VITE_DEFAULT_LANGUAGE
ENV VITE_DEFAULT_LANGUAGE=$VITE_DEFAULT_LANGUAGE

# Custom branding (e.g. VITE_BRAND_NAME=MyCompany VITE_BRAND_LOGO=my-logo.svg)
ARG VITE_BRAND_NAME
ARG VITE_BRAND_LOGO
ARG VITE_FOOTER_TEXT
ENV VITE_BRAND_NAME=$VITE_BRAND_NAME
ENV VITE_BRAND_LOGO=$VITE_BRAND_LOGO
ENV VITE_FOOTER_TEXT=$VITE_FOOTER_TEXT
# Google Drive integration (all three are PUBLIC by design: Vite inlines them
# into the browser bundle). Never pass an OAuth client secret here.
ARG VITE_GOOGLE_CLIENT_ID
ARG VITE_GOOGLE_API_KEY
ARG VITE_GOOGLE_APP_ID
ENV VITE_GOOGLE_CLIENT_ID=$VITE_GOOGLE_CLIENT_ID
ENV VITE_GOOGLE_API_KEY=$VITE_GOOGLE_API_KEY
ENV VITE_GOOGLE_APP_ID=$VITE_GOOGLE_APP_ID

# AGPL-3.0 art. 13: a modified version offered over a network must point to ITS
# OWN sources. Set this to your fork when you deploy a modified build.
ARG VITE_SOURCE_URL
ENV VITE_SOURCE_URL=$VITE_SOURCE_URL

ARG DISABLE_TOOLS
ENV DISABLE_TOOLS=$DISABLE_TOOLS

# Public-facing canonical site URL. Defaults to the official site so self-hosters
# consolidate SEO signals back to bentopdf.com. Override with --build-arg
# SITE_URL=https://your-domain.example to claim canonical for your own deployment.
ARG SITE_URL=https://www.bentopdf.com
ENV SITE_URL=$SITE_URL

# Heap ceiling for every node process of the build. Lower it on a small or
# resource-capped host: the full build peaks hard and an abrupt host-level kill
# leaves no OOM trace to diagnose.
ARG NODE_HEAP_MB=3072
ENV NODE_OPTIONS="--max-old-space-size=${NODE_HEAP_MB}"

# Which npm script builds the site.
#   build:with-docs (default) = full site + 2800 static i18n pages + VitePress docs
#   build:selfhost            = app, blog, sitemap and security headers only;
#                               drops the i18n page pre-render and the docs site,
#                               which are SEO furniture for a private instance
#                               (the UI is translated at runtime from
#                               public/locales/*.json either way).
ARG BUILD_TARGET=build:with-docs

RUN --mount=type=secret,id=VITE_CORS_PROXY_URL,required=false \
    --mount=type=secret,id=VITE_CORS_PROXY_SECRET,required=false \
    VITE_CORS_PROXY_URL=$(cat /run/secrets/VITE_CORS_PROXY_URL 2>/dev/null || echo "") \
    VITE_CORS_PROXY_SECRET=$(cat /run/secrets/VITE_CORS_PROXY_SECRET 2>/dev/null || echo "") \
    npm run "$BUILD_TARGET"

# Production stage
FROM quay.io/nginx/nginx-unprivileged:alpine-slim

LABEL org.opencontainers.image.source="https://github.com/alam00000/bentopdf"
LABEL org.opencontainers.image.url="https://github.com/alam00000/bentopdf"

# global arg to local arg
ARG BASE_URL

# Set this to "true" to disable Nginx listening on IPv6
ENV DISABLE_IPV6=false
ENV PORT=8080

USER root
RUN apk upgrade --no-cache
USER nginx

COPY --chown=nginx:nginx --from=builder /app/dist /usr/share/nginx/html${BASE_URL%/}
COPY --chown=nginx:nginx nginx.conf /etc/nginx/nginx.conf
COPY --chown=nginx:nginx --from=builder /app/security-headers.conf /etc/nginx/security-headers.conf
COPY --chown=nginx:nginx --from=builder /app/security-headers-docs.conf /etc/nginx/security-headers-docs.conf
COPY --chown=nginx:nginx --from=builder /app/security-headers-isolated.conf /etc/nginx/security-headers-isolated.conf
COPY --chown=nginx:nginx --from=builder /app/nginx-isolated-location.conf /etc/nginx/nginx-isolated-location.conf
COPY --chown=nginx:nginx --chmod=755 nginx-ipv6.sh /docker-entrypoint.d/99-disable-ipv6.sh
COPY --chown=nginx:nginx --chmod=755 nginx-noindex.sh /docker-entrypoint.d/98-noindex.sh
RUN mkdir -p /etc/nginx/tmp && chown -R nginx:nginx /etc/nginx/tmp

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
