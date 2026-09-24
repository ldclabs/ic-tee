# base image, pinned by digest for reproducible enclave measurements (PCRs)
FROM rust:slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS builder

RUN apt-get update \
    && apt-get install -y gcc g++ libc6-dev pkg-config libssl-dev wget

# working directory
WORKDIR /app

# supervisord to manage programs
RUN wget -qO supervisord.tar.gz https://github.com/ochinchina/supervisord/releases/download/v0.7.3/supervisord_0.7.3_Linux_64-bit.tar.gz \
    && echo "f0308bab9c781be06ae59c4588226a5a4b7576ae7e5ea07b9dc86edc0b998de0  supervisord.tar.gz" | sha256sum -c - \
    && tar xzf supervisord.tar.gz \
    && mv supervisord_0.7.3_Linux_64-bit/supervisord ./ \
    && rm -rf supervisord_0.7.3_Linux_64-bit supervisord.tar.gz \
    && chmod +x supervisord

# dnsproxy to provide DNS services inside the enclave
RUN wget -qO dnsproxy.tar.gz https://github.com/AdguardTeam/dnsproxy/releases/download/v0.76.1/dnsproxy-linux-amd64-v0.76.1.tar.gz \
    && echo "6780f844d14fc1b05cbaaa419d90b827756cda667dc13598b1a8fac521224bf5  dnsproxy.tar.gz" | sha256sum -c - \
    && tar xzf dnsproxy.tar.gz \
    && mv linux-amd64/dnsproxy ./ \
    && rm -rf linux-amd64 dnsproxy.tar.gz \
    && chmod +x dnsproxy

WORKDIR /build
COPY src ./src
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --locked -p ic_tee_nitro_gateway -p ic_tee_daemon

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS runtime

# install dependency tools
RUN apt-get update \
    && apt-get install -y net-tools iptables iproute2 ca-certificates tzdata openssl \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app /app/
# working directory
WORKDIR /app

# supervisord config
COPY nitro_enclave/supervisord.conf /etc/supervisord.conf
# setup.sh script that will act as entrypoint
COPY nitro_enclave/setup.sh ./
RUN chmod +x setup.sh

COPY --from=builder /build/target/release/ic_tee_daemon ./ic_tee_daemon
# your custom setup goes here
COPY --from=builder /build/target/release/ic_tee_nitro_gateway ./ic_tee_nitro_gateway

# entry point
ENTRYPOINT [ "/app/setup.sh" ]
