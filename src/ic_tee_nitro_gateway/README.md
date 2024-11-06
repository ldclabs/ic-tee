# `ic_tee_nitro_gateway`
![License](https://img.shields.io/crates/l/ic_tee_nitro_gateway.svg)
[![Crates.io](https://img.shields.io/crates/d/ic_tee_nitro_gateway.svg)](https://crates.io/crates/ic_tee_nitro_gateway)
[![Test](https://github.com/ldclabs/ic-tee/actions/workflows/test.yml/badge.svg)](https://github.com/ldclabs/ic-tee/actions/workflows/test.yml)
[![Docs.rs](https://img.shields.io/docsrs/ic_tee_nitro_gateway?label=docs.rs)](https://docs.rs/ic_tee_nitro_gateway)
[![Latest Version](https://img.shields.io/crates/v/ic_tee_nitro_gateway.svg)](https://crates.io/crates/ic_tee_nitro_gateway)

## Overview
`ic_tee_nitro_gateway` is a gateway service in an AWS Nitro enclave.

## Deploy
### Building and running AWS Nitro Enclave image

#### Setup host machine

https://docs.marlin.org/learn/oyster/core-concepts/networking/outgoing

```bash
wget -O vsock-to-ip-transparent http://public.artifacts.marlin.pro/projects/enclaves/vsock-to-ip-transparent_v1.0.0_linux_amd64
chmod +x vsock-to-ip-transparent
./vsock-to-ip-transparent --vsock-addr 3:1200
```

https://docs.marlin.org/learn/oyster/core-concepts/networking/incoming

iptables rules:
```bash
# route local incoming packets on port 8080 to the transparent proxy
iptables -t nat -A OUTPUT -p tcp --dport 8080 -o lo -j REDIRECT --to-port 1200
iptables -t nat -A OUTPUT -p tcp --dport 8080 -d 127.0.0.1 -j REDIRECT --to-port 1200

# route incoming packets on port 443 to the transparent proxy
iptables -A PREROUTING -t nat -p tcp --dport 443 -i ens5 -j REDIRECT --to-port 1200
# route incoming packets on port 1025:65535 to the transparent proxy
# iptables -A PREROUTING -t nat -p tcp --dport 1025:65535 -i ens5 -j REDIRECT --to-port 1200
```

```bash
wget -O port-to-vsock-transparent http://public.artifacts.marlin.pro/projects/enclaves/port-to-vsock-transparent_v1.0.0_linux_amd64
chmod +x port-to-vsock-transparent
./port-to-vsock-transparent --vsock 88 --ip-addr 0.0.0.0:1200
```

#### Build and run enclave

The following steps should be run in AWS Nitro-based instances.

https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html

```bash
cargo install ic_tee_cli
sudo nitro-cli build-enclave --docker-uri ghcr.io/ldclabs/ic_tee_nitro_gateway_enclave_amd64:latest --output-file ic_tee_nitro_gateway_enclave_amd64.eif
# Start building the Enclave Image...
# Using the locally available Docker image...
# Enclave Image successfully created.
# {
#   "Measurements": {
#     "HashAlgorithm": "Sha384 { ... }",
#     "PCR0": "349166c4a015d98b39d6cd3c3a65a5c2ed11f4414687500dd0a7310f36b31d223d0f09662fa547d449e209bc3f2c15be",
#     "PCR1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
#     "PCR2": "7584fed461361c6e8c4f56e426f46e610b86ce8eae1cc407f221adf8f5a9053f452eefa3fbae5256e0b17e91ecd4cb3f"
#   }
# }
ic_tee_cli -c e7tgb-6aaaa-aaaap-akqfa-cai identity-derive --seed ecf476c4d2682dc2f57773085058ee0e36b720d623b5cd6e8dc04388342a4ee9df8150b1e3dd9b5e11cbac02153e9faf
# principal: yn7la-zcbb2-vnt52-dixn7-u6djx-mlrnd-vux2u-6llr3-v5xdd-2vi6h-oqe
sudo nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-cid 88 --eif-path ic_tee_nitro_gateway_enclave_amd64.eif
# Start allocating memory...
# Started enclave with enclave-cid: 88, memory: 512 MiB, cpu-ids: [1, 3]
# {
#   "EnclaveName": "ic_tee_nitro_gateway_enclave_amd64",
#   "EnclaveID": "i-056e1ab9a31cd77a0-enc192fc732d6e4e41",
#   "ProcessID": 14424,
#   "EnclaveCID": 88,
#   "NumberOfCPUs": 2,
#   "CPUIDs": [
#     1,
#     3
#   ],
#   "MemoryMiB": 512
# }
sudo nitro-cli describe-enclaves
sudo nitro-cli terminate-enclave --enclave-id i-056e1ab9a31cd77a0-enc192fce92cafbc6f
```


## License
Copyright © 2024 [LDC Labs](https://github.com/ldclabs).

`ldclabs/ic-tee` is licensed under the MIT License. See [LICENSE](../../LICENSE-MIT) for the full license text.