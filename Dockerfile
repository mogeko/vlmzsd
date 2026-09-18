FROM docker.io/library/debian:trixie-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl minisign tar xz-utils ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
ARG MINISIGN_PUBKEY="RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U"
ARG ZIG_VERSION="0.16.0"

WORKDIR /tmp/

RUN <<EOF
    case "${TARGETARCH}" in
        amd64)    ZIG_PKG="zig-x86_64-linux-${ZIG_VERSION}"      ;;
        arm64)    ZIG_PKG="zig-aarch64-linux-${ZIG_VERSION}"     ;;
        arm)      ZIG_PKG="zig-arm-linux-${ZIG_VERSION}"         ;;
        riscv64)  ZIG_PKG="zig-riscv64-linux-${ZIG_VERSION}"     ;;
        ppc64le)  ZIG_PKG="zig-powerpc64le-linux-${ZIG_VERSION}" ;;
        386)      ZIG_PKG="zig-x86-linux-${ZIG_VERSION}"         ;;
        loong64)  ZIG_PKG="zig-loongarch64-linux-${ZIG_VERSION}" ;;
        s390x)    ZIG_PKG="zig-s390x-linux-${ZIG_VERSION}"       ;;
        *) echo   "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;;
    esac
    ZIG_DL_URL="https://ziglang.org/download/${ZIG_VERSION}/${ZIG_PKG}.tar.xz"
    curl -fSL "${ZIG_DL_URL}" -o zig.tar.xz
    curl -fSL "${ZIG_DL_URL}.minisig" -o zig.tar.xz.minisig
EOF

RUN minisign -Vm zig.tar.xz -P "${MINISIGN_PUBKEY}" -x zig.tar.xz.minisig

RUN mkdir -p /opt/toolchain/ && \
    tar -xf zig.tar.xz -C /opt/toolchain/ --strip-components=1 && \
    rm /tmp/zig.tar.xz /tmp/zig.tar.xz.minisig

ENV PATH="/opt/toolchain:${PATH}"

WORKDIR /opt/app/

COPY ./src/ /opt/app/src/
COPY ./build.zig /opt/app/build.zig
COPY ./build.zig.zon /opt/app/build.zig.zon
COPY ./LICENSE /opt/app/LICENSE
COPY ./README.md /opt/app/README.md

RUN zig build vlmzsd vlmzs --release=safe -Dcpu=baseline -Dno-embedded-data

FROM gcr.io/distroless/base-nossl-debian13:latest

COPY --from=builder /opt/app/zig-out/bin/vlmzsd /usr/bin/vlmzsd
COPY --from=builder /opt/app/zig-out/bin/vlmzs /usr/bin/vlmzs
COPY --from=builder /opt/app/src/vlmcsd.kmd /usr/share/vlmzsd/data.kmd
COPY --from=builder /opt/app/LICENSE /usr/share/doc/vlmzsd/copyright
COPY --from=builder /opt/app/README.md /usr/share/doc/vlmzsd/README.md

# Set the port for vlmzsd to listen on
ENV VLMZSD_PORT="1688"
# Suppress debug logs from loopback (localhost) clients
ENV VLMZSD_QUIET_LOOPBACK="true"
# Set the default log level to verbose
ENV VLMZSD_VERBOSE="true"

EXPOSE 1688/tcp

ENTRYPOINT ["/usr/bin/vlmzsd"]

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD [ "/usr/bin/vlmzs", "localhost:1688" ]
