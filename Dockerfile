FROM docker.io/library/debian:trixie-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl minisign tar xz-utils ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ARG MINISIGN_PUBKEY="RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U"
ARG ZIG_VERSION="0.16.0"
ARG ZIG_DL_BASE="https://ziglang.org/download"

WORKDIR /tmp/

RUN ARCH=$(uname -m) && \
    ZIG_DL_URL="${ZIG_DL_BASE}/${ZIG_VERSION}/zig-${ARCH}-linux-${ZIG_VERSION}.tar.xz" && \
    curl -fSL "$ZIG_DL_URL" -o zig.tar.xz && \
    curl -fSL "$ZIG_DL_URL.minisig" -o zig.tar.xz.minisig

RUN  minisign -Vm zig.tar.xz -P "${MINISIGN_PUBKEY}" -x zig.tar.xz.minisig

RUN mkdir -p /opt/builder/ && \
    tar -xf zig.tar.xz -C /opt/builder/ --strip-components=1 && \
    rm /tmp/zig.tar.xz /tmp/zig.tar.xz.minisig

WORKDIR /opt/app/

COPY ./src/ /opt/app/src/
COPY ./build.zig /opt/app/build.zig
COPY ./build.zig.zon /opt/app/build.zig.zon
COPY ./LICENSE /opt/app/LICENSE
COPY ./README.md /opt/app/README.md

RUN /opt/builder/zig build --release=safe

FROM gcr.io/distroless/cc-debian13:latest

COPY --from=builder /opt/app/zig-out/bin/vlmzsd /usr/bin/vlmzsd
COPY --from=builder /opt/app/zig-out/bin/vlmzs /usr/bin/vlmzs
COPY --from=builder /opt/app/LICENSE /usr/share/doc/vlmzsd/copyright
COPY --from=builder /opt/app/README.md /usr/share/doc/vlmzsd/README.md

EXPOSE 1688/tcp

ENTRYPOINT ["/usr/bin/vlmzsd"]

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD [ "/usr/bin/vlmzs", "localhost:1688" ]
