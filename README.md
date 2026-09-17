# rusty_rtos_sntp

[![crates.io](https://img.shields.io/crates/v/rusty_rtos_sntp.svg)](https://crates.io/crates/rusty_rtos_sntp)
[![docs.rs](https://docs.rs/rusty_rtos_sntp/badge.svg)](https://docs.rs/rusty_rtos_sntp)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A `no_std` SNTPv4 packet codec and clock arithmetic, the Kairos remake of
coreSNTP. MIT OR Apache-2.0.

**K7's third library**, and the first one whose hardest defect is dated: SNTP's
seconds field wraps on **7 February 2036**, and a client that gets that wrong is
correct until then and silently wrong afterwards.

- **Proven**: `core_sntp_serializer.c` — the packet codec, the response
  validation, the clock-offset arithmetic across the era wrap, the poll-interval
  calculation and the UNIX time conversion. Diffed against the C as a 160-line
  trace, call for call.
- **Integer arithmetic, on purpose.** coreSNTP targets parts with no
  floating-point unit, where an `f64` divide is a soft-float call on the receive
  path of every poll. It is also what makes this differentiable at all: two
  floating-point implementations agree to within an epsilon, and "within an
  epsilon" is not something a byte-for-byte trace can assert.
- **Zero allocation**, `forbid(unsafe)`, and a no-panic gate — a time client is
  fed over UDP, which is connectionless, so anything that can guess a port can
  deliver 48 bytes of its choosing.

**Known gaps.** `core_sntp_client.c` — the state machine that drives a UDP
transport and an authentication interface — is **not written**. This crate
builds and reads packets; it does not own a socket. That is the next milestone.

- This package's plan: [docs/plans/rusty_rtos_sntp.md](https://github.com/Remade-With-Rust/rusty_rtos_sntp/blob/main/docs/plans/rusty_rtos_sntp.md)
- Every number: [docs/LEDGER.md](https://github.com/Remade-With-Rust/rusty_rtos_sntp/blob/main/docs/LEDGER.md)
- The family plan: Kairos [`docs/plans/rtos-mission.md`](https://github.com/Remade-With-Rust/kairos/blob/main/docs/plans/rtos-mission.md)

**Claims discipline:** this README makes no performance or capability claim that
is not backed by a test, a benchmark ledger entry, or a kill test recorded in
the plan. "Scaffold" means scaffold. "Sim only" means the sim port; "builds, not
flashed" means no chip has run it.


Part of **Kairos**, the Remade-With-Rust programme that rebuilds the FreeRTOS
portfolio in memory-safe Rust, as independent packages that expose the API a
FreeRTOS developer already knows and prove every scheduling decision against
the C kernel's own trace.

## Status

**The serializer is built and proven; the client state machine is not.** 160
trace lines agree with `core_sntp_serializer.c` at the pinned v2.0.0, including
the 2036 era wrap. 14 tests. Nothing has run on a chip.

## What it is

- A pure-Rust remake of the corresponding FreeRTOS component. Same job, same
  names, same semantics, new code, permissive licence, `forbid(unsafe)` in
  the core.
- Arch-agnostic: the core crate is `no_std` (+ `alloc`) and knows nothing about
  a CPU, an allocator or an operating system. Ports and backends are thin,
  feature-gated WRAP crates.

## What it is not

- Not a fork of FreeRTOS and not a binding to it. The C kernel is the
  **oracle** this package is measured against, never a dependency.
- Not a rewrite of a radio blob, a ROM or a vendor driver. Where silicon must
  be touched, a port crate **wraps** `cortex-m-rt` / `riscv-rt` / `esp-hal`
  and says so.

## Conformance

**160 trace lines agree with `core_sntp_serializer.c`**, compiled verbatim from
the pinned checkout (v2.0.0 at `50f5f96`).

```sh
cargo test -p rusty_rtos_sntp-core
```

The C arm's trace is checked in, so this diffs with no C toolchain. Fetch the
oracle itself with `kairos oracle fetch --lib coreSNTP`.

**The trace carries its own inputs.** Every answer line is preceded by an `in`
line holding everything the call needs, packet bytes included — so the Rust arm
replays the workload rather than keeping a second copy of the C's case tables.
That is a change from `backoff`, where both arms held the table: two tables
drift, and nothing catches two arms agreeing about a workload that is not the
one the driver documents.

**The era wrap is the point.** An SNTP timestamp counts seconds from 1900 in 32
bits, so it runs out in 2036. A client and a server can then sit either side of
the wrap and disagree by ~136 years on a naive subtraction. The C computes the
difference three ways — same era, server an era ahead, client an era ahead — and
keeps whichever has the smallest absolute value, assuming the two clocks are
within 68 years of each other. The differential carries cases on both sides of
the wrap, at the exact half-era tie, and one where the *send* leg crosses an era
boundary while the *receive* leg does not.

**Poison-proven on six behaviours**, each caught:

* the half-an-era **tie**, where the library assumes the server is ahead;
* the **fraction-to-millisecond divisor**, which is deliberately not exact —
  `0xFFFFFFFF` must give 999 ms, never 1000;
* the **order of the two guards** in `Sntp_SerializeRequest`: a call that is
  both too small and zero gets `BufferTooSmall`, because size is checked first;
* the **replay-protection shift**, `randomNumber >> 16`, which gives up ~15
  microseconds of the timestamp to make a request hard to predict;
* the **poll interval rounding**, which floors to a power of two because a
  shorter interval is more accurate than asked for and a longer one is not;
* the **leap indicator's bit position**, bits 6-7 of the first byte.

**Two poisons did not fire, and both are properties rather than gaps.**

The UNIX era split can use `>` or `>=` with no observable difference, because
the two era constants sum to **exactly 2³²** — so at the one second where the
comparison differs, the era-0 subtraction and the era-1 wrapping addition give
the same answer. That is *why* the era-1 formula is a plain wrapping add.

The `<=` in the three-way era comparison can be a `<` with no observable
difference either, because its equality cases are exactly the half-era tie,
which the special case above has already returned on. Both are now pinned by
unit tests, because an accidental property nobody checks is one edit away from
being false.

## The no-panic gate

A time client is fed by strangers, and worse than most: SNTP runs over UDP,
which is connectionless, so anything on the path — or anything that can guess a
port — can deliver 48 bytes of its choosing. The library's validation exists to
reject those, and every one of those checks runs on bytes an attacker picked.

| test | what it feeds in |
|---|---|
| arbitrary bytes | every length 0..96, 64 samples each, with random request and receive times |
| packet-shaped noise | 40,000 full-size packets, half forced to "server" mode and half echoing the request, so validation is passed and the arithmetic is actually reached |
| the era arithmetic | all 10,000 combinations of ten extreme second values across the four round-trip timestamps, with maximal fractions |
| every truncation | a well-formed packet cut at every offset |
| every single-byte corruption | all 48 positions × 12 interesting bytes |
| every buffer size | serializing into 0..96 bytes, 32 samples each |
| every poll interval | both `u16` axes swept in full against a spread of the other |
| every timestamp | 100,000 random conversions plus a 2,000-wide window around the era boundary |

**The round trip is the property that spans both halves.**
`Sntp_SerializeRequest` **mutates** the timestamp it is given — it ORs random
bits into the fractions — and a server echoes that mutated value back in the
originate field. A client that remembered the value it passed *in* rather than
the value it got *back* would reject every genuine response, and would pass
every test that exercised the two functions separately. A standing test builds a
request, constructs the response a server would send, and requires it to be
accepted.

**Poisoned four ways.** Making the request timestamp read-only, and removing the
buffer-size guard, are both caught. Indexing the field reader and the packet
writer unchecked are **not** — the entry points check the length once and every
field offset lies inside those 48 bytes, so like `rusty_rtos_json`'s byte reader
these bounds are defence in depth rather than load-bearing. That is the third
time this family has measured that same shape, and it is kept rather than
removed because the property holds only while every caller is right.

## Using it

```rust
use rusty_rtos_sntp::{Timestamp, Verdict, serialize_request, deserialize_response};

// The caller owns the clock and the randomness, exactly as in the C.
let mut request = Timestamp::new(now_in_sntp_seconds, now_fractions);
let mut packet = [0u8; rusty_rtos_sntp::PACKET_BASE_SIZE];
serialize_request(&mut request, some_random_u32, &mut packet)?;
// ... send `packet` over UDP, and KEEP `request`: it was modified.

let received = Timestamp::new(rx_seconds, rx_fractions);
match deserialize_response(&request, &received, &reply)? {
    Verdict::Accepted(a) => {
        // a.clock_offset_ms is how far this clock is behind the server.
        // a.leap_second says whether to expect a 61- or 59-second minute,
        // and AlarmServerNotSynchronized says not to trust the time at all.
    }
    Verdict::Rejected(r) => {
        // A Kiss-o'-Death is a VALID response that refuses, so it is a
        // verdict and not an error. r.kind says whether to change server or
        // to back off -- which is what rusty_rtos_backoff is for.
    }
}
```

A Kiss-o'-Death with a `RATE` code pairs directly with
[`rusty_rtos_backoff`](https://crates.io/crates/rusty_rtos_backoff), and that
pairing is why `backoff` was built first.

## Performance

No rows. Nothing here has been benchmarked and nothing has run on a chip. The
ledger carries this crate's **counts**, because a count is a number and belongs
there with its method.

## Portability

Builds `no_std` with no default features on `thumbv7em-none-eabihf` and
`riscv32imac-unknown-none-elf` (both verified), and CI holds it to
`thumbv8m.main-none-eabihf` and `riscv32imafc-unknown-none-elf` as well. A build
claim, not a behaviour claim.

## Layout

```text
crates/rusty_rtos_sntp          facade: re-exports + prelude; the crate you depend on
crates/rusty_rtos_sntp-core     no_std (+ alloc); forbid(unsafe); types, traits, algorithms
firmware/                per-chip example projects, excluded from the workspace
docs/plans/              this package's plan and its hardening audit
docs/LEDGER.md           every number, with its method line
```

## Build

```sh
cargo test --workspace                                   # host: the tests
cargo check -p rusty_rtos_sntp-core --no-default-features \
  --target thumbv7em-none-eabihf                         # Cortex-M4F class, no alloc
cargo check -p rusty_rtos_sntp-core --no-default-features --features alloc \
  --target riscv32imac-unknown-none-elf                  # ESP32-C6 class, with alloc
```

CI holds the core to `thumbv7em-none-eabihf`, `thumbv8m.main-none-eabihf`,
`riscv32imac-unknown-none-elf` and `riscv32imafc-unknown-none-elf`, with and
without `alloc`, plus `cargo deny check`. Firmware examples (Xtensa needs the
esp toolchain; Cortex-M and RISC-V work on stable) are built from their own
directories under `firmware/`.

## License

MIT OR Apache-2.0, at your option. FreeRTOS is MIT-licensed by Amazon.com,
Inc. or its affiliates; this crate remakes its API and behaviour from the
published sources and links no FreeRTOS code.

---

<!-- HARDENING-TABLE:BEGIN generated by use-protection-please — edit docs/plans/use-protection-please.md, not this block -->
## Hardening status

**Tier** critical-path · **Audited** unrecorded (survey) · **v1.0.0 gates** 6/16 · [Full checklist](docs/plans/use-protection-please.md)

`████░░░░░░░░░░░░░░░░` **22%** &nbsp;·&nbsp; 8 Completed · 0 Scheduled · 28 Incomplete · 19 N/A

| Phase | ✅ Completed | 🗓 Scheduled | ⬜ Incomplete | · N/A |
|---|--:|--:|--:|--:|
| 0 — Threat modeling | 0 | 0 | 2 | 0 |
| 1 — Toolchain | 2 | 0 | 2 | 0 |
| 2 — Supply chain | 2 | 0 | 6 | 0 |
| 3 — Code level | 3 | 0 | 4 | 0 |
| 4 — Static analysis | 0 | 0 | 1 | 0 |
| 5 — Dynamic analysis | 0 | 0 | 3 | 0 |
| 6 — Fuzzing and properties | 0 | 0 | 4 | 0 |
| 7 — Formal verification | 0 | 0 | 1 | 0 |
| 8 — Build and binary | 0 | 0 | 1 | 1 |
| 9 — Runtime privilege | 0 | 0 | 0 | 1 |
| 10 — Cryptography | 0 | 0 | 0 | 3 |
| 11 — CI/CD, release, and operations | 1 | 0 | 4 | 0 |
| 12 — Compliance controls | 0 | 0 | 0 | 14 |
| **Total** | **8** | **0** | **28** | **19** |

**Architect** — [Tim Almond](https://github.com/Ttimmahlax) — accountable for this unit's security design; rendered
<!-- HARDENING-TABLE:END -->
