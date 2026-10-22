# STM32H723ZG X9.146 Hybrid Post-Quantum TLS

Research implementation accompanying the paper:
**"Post-Quantum Cryptography Performance on Embedded Hardware: Analysis of X9.146 Hybrid Certificates"**

---

## What this project does

This firmware runs a TLS 1.3 server on an STM32H723ZG microcontroller (Arm Cortex-M7, 550 MHz) that uses **hybrid post-quantum certificates** — every certificate in the chain carries two independent signatures:

| Signature | Algorithm | Purpose |
|---|---|---|
| Primary | ML-DSA-87 (CRYSTALS-Dilithium) | Post-quantum security |
| Alternative | ECDSA P-256 | Classical fallback (X9.146) |

A client that understands post-quantum cryptography verifies both. A legacy client verifies only the ECDSA chain and connects normally. This is the **X9.146 hybrid certificate** approach — defined by the ANSI X9 standard — and it allows a smooth migration to post-quantum security without breaking existing clients.

---

## What is wolfSSL?

[wolfSSL](https://www.wolfssl.com) is an open-source TLS library designed for embedded and constrained devices. It is the only embedded TLS library with native support for:
- **ML-DSA** (post-quantum digital signatures, formerly CRYSTALS-Dilithium)
- **ML-KEM** (post-quantum key encapsulation, formerly CRYSTALS-Kyber)
- **X9.146 dual-algorithm certificates** (hybrid classical + post-quantum)

This project uses wolfSSL 5.8.0 via the STM32CubeIDE I-CUBE-wolfSSL middleware pack.

---

## Hardware

| Component | Details |
|---|---|
| Board | STM32 Nucleo-H723ZG |
| MCU | STM32H723ZG — Arm Cortex-M7, up to 550 MHz |
| Flash | 1 MB |
| RAM | 564 KB |
| Network | On-board LAN8742 Ethernet PHY via lwIP |

---

## Repository structure

```
Core/Src/main.c                        TLS server + wolfCrypt benchmark harness
Core/Inc/certs_pqc.h                   Embedded X9.146 certificate chain (C array)
wolfSSL/wolfSSL.I-CUBE-wolfSSL_conf.h  wolfSSL build configuration
tools/gen_pq_chain_wolfssl.c           PC-side X9.146 cert chain generator
tools/build_wolfssl_gen.sh             Build script for the cert generator
Drivers/                               STM32 HAL + CMSIS (ST-generated)
Middlewares/Third_Party/LwIP/          lwIP TCP/IP stack (ST-generated)
Middlewares/Third_Party/wolfSSL/       wolfSSL 5.8.0 source (I-CUBE pack)
```

---

## Build configurations

The firmware supports two compile-time modes controlled by defines in `Core/Src/main.c`:

| Define | Value | Effect |
|---|---|---|
| `RUN_WOLFCRYPT_BENCH` | `1` | Run primitive benchmarks instead of TLS server |
| `RUN_WOLFCRYPT_BENCH` | `0` | Normal TLS server mode |
| `BENCH_CLOCK_272` | `1` | Clock at 272 MHz (benchmark comparison) |
| `BENCH_CLOCK_272` | `0` | Clock at 550 MHz (normal operation) |

The wolfSSL math backend is controlled in `wolfSSL/wolfSSL.I-CUBE-wolfSSL_conf.h`:

| Setting | Value | Effect |
|---|---|---|
| `WOLF_CONF_MATH` | `4` | SP math + Cortex-M7 assembly (optimised) |
| `WOLF_CONF_MATH` | `6` | Generic C math (unoptimised baseline) |
| `WOLF_CONF_ARMASM` | `1` | Thumb2 inline ASM for SHA3/SHAKE/AES (optimised) |
| `WOLF_CONF_ARMASM` | `0` | Pure C (unoptimised baseline) |

---

## Benchmark results (wolfCrypt primitives, ms)

All results measured on STM32H723ZG. **Opt** = MATH=4 + ARMASM=1. **Unopt** = MATH=6 + ARMASM=0.

### ML-KEM (key encapsulation)

| Operation | 272 MHz Unopt | 272 MHz Opt | 550 MHz Unopt | 550 MHz Opt |
|---|---|---|---|---|
| ML-KEM-512 KeyGen | 1.390 | 1.022 | 0.688 | 0.506 |
| ML-KEM-512 Encap | 1.482 | 1.012 | 0.733 | 0.501 |
| ML-KEM-512 Decap | 2.014 | 1.362 | 0.997 | 0.674 |
| ML-KEM-768 KeyGen | 2.298 | 1.645 | 1.136 | 0.813 |
| ML-KEM-768 Encap | 2.515 | 1.693 | 1.244 | 0.838 |
| ML-KEM-768 Decap | 3.263 | 2.178 | 1.615 | 1.078 |
| ML-KEM-1024 KeyGen | 3.778 | 2.660 | 1.866 | 1.316 |
| ML-KEM-1024 Encap | 4.044 | 2.716 | 2.000 | 1.343 |
| ML-KEM-1024 Decap | 5.005 | 3.333 | 2.475 | 1.650 |

### ML-DSA (digital signatures)

| Operation | 272 MHz Unopt | 272 MHz Opt | 550 MHz Unopt | 550 MHz Opt |
|---|---|---|---|---|
| ML-DSA-44 KeyGen | 5.522 | 4.218 | 2.731 | 2.085 |
| ML-DSA-44 Sign | 15.703 | 12.268 | 6.959 | 6.060 |
| ML-DSA-44 Verify | 5.849 | 4.586 | 2.890 | 2.265 |
| ML-DSA-65 KeyGen | 9.625 | 7.348 | 4.759 | 3.630 |
| ML-DSA-65 Sign | 24.643 | 23.727 | 11.733 | 10.020 |
| ML-DSA-65 Verify | 9.843 | 7.659 | 4.869 | 3.788 |
| ML-DSA-87 KeyGen | 16.565 | 12.563 | 8.194 | 6.210 |
| ML-DSA-87 Sign | 32.156 | 25.225 | 13.917 | 12.662 |
| ML-DSA-87 Verify | 16.983 | 13.115 | 8.400 | 6.487 |

### ECC P-256 and classical algorithms

| Operation | 272 MHz Unopt | 272 MHz Opt | 550 MHz Unopt | 550 MHz Opt |
|---|---|---|---|---|
| ECC KeyGen | 30.588 | 1.815 | 15.132 | 0.898 |
| ECDHE | 30.529 | 4.016 | 15.103 | 1.984 |
| ECDSA Sign | 33.733 | 3.389 | 16.683 | 1.676 |
| ECDSA Verify | 61.444 | 6.134 | 30.353 | 3.033 |
| RSA-2048 Public | 5.403 | 3.452 | 2.674 | 1.708 |
| RSA-2048 Private | 316.750 | 129.000 | 156.625 | 63.813 |
| DH-2048 KeyGen | 130.125 | 59.706 | 64.375 | 29.500 |
| DH-2048 Agree | 130.250 | 59.667 | 64.312 | 29.500 |

---

## Generating the certificate chain

The X9.146 dual-algorithm certificate chain is generated on a PC using `tools/gen_pq_chain_wolfssl.c`. Requires wolfSSL built with dual-algorithm cert support — see `tools/build_wolfssl_gen.sh` for the exact configure flags.

```bash
PQ_LEVEL=5  # 2=ML-DSA-44, 3=ML-DSA-65, 5=ML-DSA-87
./tools/build_wolfssl_gen.sh
```

This produces `Core/Inc/certs_pqc.h` which is embedded directly into the firmware.

---

## Importing into STM32CubeIDE

1. File → Import → General → Existing Projects into Workspace
2. Select `D:\STM32CubeIDE\workspace_1.19.0\TLS_X9`
3. Build → Project → TLS_X9
