# Build with: docker build -f deploy/Dockerfile -t tokencrumb-mcp-proxy .
FROM rust:1.88-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock README.md ./
COPY crates ./crates
COPY tools ./tools
COPY vendor/biscuit-auth ./vendor/biscuit-auth
RUN cargo build --release --locked -p tokencrumb-mcp-proxy --bin tokencrumb

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /data && chown 10001:10001 /data
COPY --from=build /src/target/release/tokencrumb /usr/local/bin/tokencrumb
COPY LICENSE /usr/share/doc/tokencrumb/LICENSE
COPY NOTICE /usr/share/doc/tokencrumb/NOTICE
COPY vendor/biscuit-auth/LICENSE /usr/share/doc/tokencrumb/biscuit-auth/LICENSE
COPY vendor/biscuit-auth/README.md /usr/share/doc/tokencrumb/biscuit-auth/README.md
USER 10001
WORKDIR /data
EXPOSE 9443
ENTRYPOINT ["tokencrumb"]
CMD ["--help"]
