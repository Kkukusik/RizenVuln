FROM node:22-bookworm-slim AS frontend
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY frontend/ ./
RUN npm run build

FROM rust:1.100-slim-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY apps/ apps/
COPY crates/ crates/
COPY migrations/ migrations/
COPY docs/openapi.json docs/openapi.json
RUN cargo build --locked --release --bin rizenvuln-api

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* && groupadd -g 10001 rizen && useradd -u 10001 -g rizen -M -s /usr/sbin/nologin rizen
COPY --from=builder /build/target/release/rizenvuln-api /usr/local/bin/rizenvuln-api
COPY --from=frontend /build/frontend/dist/ /app/frontend/
ENV FRONTEND_DIR=/app/frontend
WORKDIR /app
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD curl -fsS http://127.0.0.1:8080/health/ready || exit 1
ENTRYPOINT ["rizenvuln-api"]
