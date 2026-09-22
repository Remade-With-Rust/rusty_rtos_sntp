# rusty_rtos_sntp-core

[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/remade-with-rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network)
[![crates.io](https://img.shields.io/crates/v/rusty_rtos_sntp-core.svg)](https://crates.io/crates/rusty_rtos_sntp-core)
[![docs.rs](https://docs.rs/rusty_rtos_sntp-core/badge.svg)](https://docs.rs/rusty_rtos_sntp-core)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

The pure `no_std` core of [`rusty_rtos_sntp`](https://github.com/Remade-With-Rust/rusty_rtos_sntp): an SNTPv4
client, the Kairos remake of coreSNTP. No CPU, no allocator, no operating
system. `#![forbid(unsafe_code)]`.

- **Proven against the C**: **160 trace lines agree with `core_sntp_serializer.c`**
  across 75 calls, both halves of the library.
- **The hardest defect here is dated.** SNTP's seconds field wraps on
  **7 February 2036**, and a client that gets that wrong does not fail on the
  day — it fails quietly, years later, on a device already in the field. Both
  sides of the wrap are in the trace.

## Conformance

```sh
cargo test -p rusty_rtos_sntp-core
```

The C arm is generated once and checked in, so the diff needs no C toolchain.

## Part of Remade With Rust

This crate is part of **[Kairos](https://github.com/Remade-With-Rust/kairos)** — FreeRTOS remade in memory-safe
Rust, as independent packages that expose the API a FreeRTOS developer already
knows and prove every scheduling decision against the C kernel's own trace.

**Where this sits for Mata.** Kairos is the real-time layer on the device
itself, and [`rusty_rtos_mqtt`](https://crates.io/crates/rusty_rtos_mqtt) is the way out of it.
Paired with the **MATA distributed cloud**, robotics and sensor data has two
routes — read it on the machine, or reach it through the cloud — with the same
memory-safe crates at both ends.

The family:
[`rusty_rtos_core`](https://crates.io/crates/rusty_rtos_core) (the shared vocabulary),
[`rusty_rtos_kernel`](https://crates.io/crates/rusty_rtos_kernel) (the scheduler),
[`rusty_rtos_port`](https://crates.io/crates/rusty_rtos_port) (the architecture seam),
[`rusty_rtos_heap`](https://crates.io/crates/rusty_rtos_heap) (the allocators),
[`rusty_rtos_json`](https://crates.io/crates/rusty_rtos_json) (coreJSON),
[`rusty_rtos_sntp`](https://crates.io/crates/rusty_rtos_sntp) (coreSNTP),
[`rusty_rtos_mqtt`](https://crates.io/crates/rusty_rtos_mqtt) (coreMQTT),
[`rusty_rtos_backoff`](https://crates.io/crates/rusty_rtos_backoff) (backoffAlgorithm),
[`rusty_rtos-capi`](https://crates.io/crates/rusty_rtos-capi) (the C ABI) and
[`rusty_rtos_demo`](https://crates.io/crates/rusty_rtos_demo) (the conformance corpus).
All ten are on crates.io. Also check out
the rest of **[github.com/remade-with-rust](https://github.com/remade-with-rust)**.

## About Mata Network

<!-- ORG BOILERPLATE — keep identical across repos -->

**[Mata Network](https://www.mata.network/)** builds sovereign, self-hostable
privacy infrastructure — *"stop sacrificing your privacy for convenience"*:
wallet & identity, a password manager, a contact manager, and a browser
extension that stops your information leaking as you browse.

**Remade With Rust** is our open-source home for the permissively-licensed
building blocks that work depends on — including
[remade_ffmpeg_rs](https://github.com/Remade-With-Rust/remade_ffmpeg_rs) (the
FFmpeg alternative) and [FFAI](https://github.com/Remade-With-Rust/FFAI) (the
AI media toolkit).

→ **[www.mata.network](https://www.mata.network/)**

<!-- /ORG BOILERPLATE -->

## License

MIT OR Apache-2.0, at your option. FreeRTOS is MIT-licensed by Amazon.com, Inc.
or its affiliates; this crate remakes its API and behaviour from the published
sources and links no FreeRTOS code.
