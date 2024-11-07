# `ic_tee_nitro_gateway`
## Overview

`ic_tee_nitro_gateway` is a gateway service within an AWS Nitro enclave. It is launched inside the enclave through the ICP `ic_tee_identity` identity service and the IC-COSE configuration service, then forwards requests to the business application running in the enclave. The startup process is as follows:

1. **Generate attestation** for sign in, obtaining an identity via the ICP `ic_tee_identity` service to access other services on ICP. `ic_tee_identity` verifies the attestation and derives an identity, generating the same identity for identical enclave images.

2. **Switch to a fixed identity** obtained from the IC-COSE configuration service to avoid identity changes due to application upgrades. This enables consistent operations with a stable identity.

3. **Start the web service** using a TLS certificate obtained with the fixed identity from the IC-COSE configuration service. This web service receives requests and forwards them to the application running inside the enclave.

## Deploy
### Building and running AWS Nitro Enclave image

#### Setup host machine

https://docs.marlin.org/learn/oyster/core-concepts/networking/outgoing

Forward all traffic from vsock 3 (port 1200 in the enclave) to the internet.
```bash
wget -O vsock-to-ip-transparent http://public.artifacts.marlin.pro/projects/enclaves/vsock-to-ip-transparent_v1.0.0_linux_amd64
chmod +x vsock-to-ip-transparent
./vsock-to-ip-transparent --vsock-addr 3:1200
```

https://docs.marlin.org/learn/oyster/core-concepts/networking/incoming

Add iptables rules on the host machine to forward traffic on 443 from the internet to 127.0.0.1:1200.
```bash
sudo sh nitro_enclave/host_iptables-config.sh
```

Forward all traffic from 127.0.0.1:1200 to vsock 88.
```bash
wget -O port-to-vsock-transparent http://public.artifacts.marlin.pro/projects/enclaves/port-to-vsock-transparent_v1.0.0_linux_amd64
chmod +x port-to-vsock-transparent
./port-to-vsock-transparent --vsock 88 --ip-addr 127.0.0.1:1200
```

#### Build and run enclave

The following steps should be run in AWS Nitro-based instances.

https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html

Build the enclave image.
```bash
cargo install ic_tee_cli
sudo docker pull ghcr.io/ldclabs/ic_tee_nitro_gateway_enclave_amd64:latest
sudo nitro-cli build-enclave --docker-uri ghcr.io/ldclabs/ic_tee_nitro_gateway_enclave_amd64:latest --output-file ic_tee_nitro_gateway_enclave_amd64.eif
# Start building the Enclave Image...
# Using the locally available Docker image...
# Enclave Image successfully created.
# {
#   "Measurements": {
#     "HashAlgorithm": "Sha384 { ... }",
#     "PCR0": "929c88889044592565f259bbae65baddcf0c426bc171017375777d55161bb662ac0fb97de301d8d6c1026b62b6061098",
#     "PCR1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
#     "PCR2": "3f260bf23af9b00afe2b5c1debd0e26c987abf83378a0e5f99ae49cbdd711c020c1f23d84bc93ba184baddc842c6f21b"
#   }
# }
```

Calculate the ICP principal from the PCR0.
```bash
ic_tee_cli -c e7tgb-6aaaa-aaaap-akqfa-cai identity-derive --seed 929c88889044592565f259bbae65baddcf0c426bc171017375777d55161bb662ac0fb97de301d8d6c1026b62b6061098
# principal: 6y5sx-apnmh-blpp5-u7eyr-nnl2t-rflnm-7sw2q-ptbx3-iv47r-rsnun-eqe
```

Add the principal to the permament identity setting on IC-COSE service, so that the enclave can load permament identity after sign in with the principal.
```bash
dfx canister call ic_cose_canister setting_add_readers '(record {
  ns = "_";
  key = blob "\69\64\5f\65\64\32\35\35\31\39";
  subject = opt principal "fbi6t-ogdrt-s4de4-sxive-x4yid-xfrk2-e6jgf-jbnuh-rzxoj-qv2qa-zae";
  version = 1;
  user_owned = false;
}, vec{ principal "6y5sx-apnmh-blpp5-u7eyr-nnl2t-rflnm-7sw2q-ptbx3-iv47r-rsnun-eqe" })' --ic
```

Run the enclave.
```bash
sudo nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-cid 88 --eif-path ic_tee_nitro_gateway_enclave_amd64.eif
# Start allocating memory...
# Started enclave with enclave-cid: 88, memory: 512 MiB, cpu-ids: [1, 3]
# {
#   "EnclaveName": "ic_tee_nitro_gateway_enclave_amd64",
#   "EnclaveID": "i-056e1ab9a31cd77a0-enc193037029f7f152",
#   "ProcessID": 14424,
#   "EnclaveCID": 88,
#   "NumberOfCPUs": 2,
#   "CPUIDs": [
#     1,
#     3
#   ],
#   "MemoryMiB": 512
# }
```

```bash
sudo nitro-cli describe-enclaves
sudo nitro-cli terminate-enclave --enclave-id i-056e1ab9a31cd77a0-enc193037029f7f152
```

## License
Copyright © 2024 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-tee` is licensed under the MIT License. See [LICENSE](../../LICENSE-MIT) for the full license text.