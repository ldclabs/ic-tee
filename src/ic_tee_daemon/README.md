# IC TEE Daemon

`ic_tee_daemon` is a daemon running in enclave, providing the following functions:

1. Forwards requests in enclave to the host.
2. Listens for requests from the host.

![IC TEE Daemon](../ic_tee_host_daemon/ic_tee_host_daemon.webp)

## Usage

```bash
ic_tee_daemon --outbound-vsock-addr 3:448 --outbound-listen-addr 127.0.0.1:448 --inbound-vsock-addr 8:443 --inbound-listen-addr 127.0.0.1:8443
```

## License
Copyright © 2024-2025 [LDC Labs](https://github.com/ldclabs).

This project is dual-licensed under the [MIT License](../../LICENSE-MIT) and [Apache License, Version 2.0](../../LICENSE-APACHE). You may use either license.
