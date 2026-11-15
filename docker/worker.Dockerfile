FROM ghcr.io/aquasecurity/trivy:0.76.2 AS trivy
FROM rust:1.100-slim-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY apps/ apps/
COPY crates/ crates/
COPY migrations/ migrations/
COPY docs/openapi.json docs/openapi.json
RUN cargo build --locked --release --bin rizenvuln-worker
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && groupadd -g 10001 rizen && useradd -u 10001 -g rizen -M -s /usr/sbin/nologin rizen && mkdir -p /var/cache/trivy && chown 10001:10001 /var/cache/trivy
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /build/target/release/rizenvuln-worker /usr/local/bin/rizenvuln-worker
WORKDIR /app
USER 10001:10001
ENTRYPOINT ["rizenvuln-worker"]
