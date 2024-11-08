# base image
FROM --platform=amd64 rust:slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y gcc g++ libc6-dev pkg-config libssl-dev

WORKDIR /src
COPY src ./src
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --locked -p ic_tee_nitro_gateway

FROM debian:bookworm-slim AS runtime

# install dependency tools
RUN apt-get update \
    && apt-get install -y net-tools iptables iproute2 wget ca-certificates tzdata curl openssl \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# working directory
WORKDIR /app

# supervisord to manage programs
RUN wget -O supervisord http://public.artifacts.marlin.pro/projects/enclaves/supervisord_master_linux_amd64
RUN chmod +x supervisord

# transparent proxy component inside the enclave to enable outgoing connections
RUN wget -O ip-to-vsock-transparent http://public.artifacts.marlin.pro/projects/enclaves/ip-to-vsock-transparent_v1.0.0_linux_amd64
RUN chmod +x ip-to-vsock-transparent

# proxy to expose attestation server outside the enclave
RUN wget -O vsock-to-ip http://public.artifacts.marlin.pro/projects/enclaves/vsock-to-ip_v1.0.0_linux_amd64
RUN chmod +x vsock-to-ip

# dnsproxy to provide DNS services inside the enclave
RUN wget -O dnsproxy http://public.artifacts.marlin.pro/projects/enclaves/dnsproxy_v0.72.0_linux_amd64
RUN chmod +x dnsproxy

# supervisord config
COPY nitro_enclave/supervisord.conf /etc/supervisord.conf

# setup.sh script that will act as entrypoint
COPY nitro_enclave/setup.sh ./
RUN chmod +x setup.sh

# your custom setup goes here
COPY --from=builder /src/target/release/ic_tee_nitro_gateway ./ic_tee_nitro_gateway

# entry point
ENTRYPOINT [ "/app/setup.sh" ]