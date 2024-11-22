# base image
FROM --platform=linux/amd64 rust:slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y gcc g++ libc6-dev pkg-config libssl-dev

WORKDIR /src
COPY src ./src
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --locked -p ic_tee_nitro_gateway

FROM --platform=linux/amd64 gcr.io/distroless/cc-debian12:debug AS runtime

# working directory
WORKDIR /app

# supervisord to manage programs
RUN wget -O supervisord http://public.artifacts.marlin.pro/projects/enclaves/supervisord_master_linux_arm64
RUN chmod +x supervisord

# transparent proxy component inside the enclave to enable outgoing connections
RUN wget -O ip-to-vsock-transparent http://public.artifacts.marlin.pro/projects/enclaves/ip-to-vsock-transparent_v1.0.0_linux_arm64
RUN chmod +x ip-to-vsock-transparent

# proxy to expose attestation server outside the enclave
RUN wget -O vsock-to-ip http://public.artifacts.marlin.pro/projects/enclaves/vsock-to-ip_v1.0.0_linux_arm64
RUN chmod +x vsock-to-ip

# dnsproxy to provide DNS services inside the enclave
RUN wget -qO- https://github.com/AdguardTeam/dnsproxy/releases/download/v0.73.3/dnsproxy-linux-arm64-v0.73.3.tar.gz | tar xvz
RUN mv linux-arm64/dnsproxy ./ && chmod +x dnsproxy

# supervisord config
COPY nitro_enclave/supervisord.conf /etc/supervisord.conf

# setup.sh script that will act as entrypoint
COPY nitro_enclave/setup.sh ./
RUN chmod +x setup.sh

# your custom setup goes here
COPY --from=builder /src/target/release/ic_tee_nitro_gateway ./ic_tee_nitro_gateway

# entry point
ENTRYPOINT [ "/app/setup.sh" ]
