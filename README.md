# rusty_rtos_sntp

[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/remade-with-rust)
[![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network)
[![crates.io](https://img.shields.io/crates/v/rusty_rtos_sntp.svg)](https://crates.io/crates/rusty_rtos_sntp)
[![docs.rs](https://docs.rs/rusty_rtos_sntp/badge.svg)](https://docs.rs/rusty_rtos_sntp)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A `no_std` SNTPv4 client, the Kairos remake of coreSNTP. MIT OR Apache-2.0.

**K7's third library**, and the first one whose hardest defect is dated: SNTP's
seconds field wraps on **7 February 2036**, and a client that gets that wrong is
correct until then and silently wrong afterwards.

- **Proven, the serializer**: the packet codec, the response validation, the
  clock-offset arithmetic across the era wrap, the poll-interval calculation and
  the UNIX time conversion. Diffed against the C as a 160-line trace, 75 calls.
- **Proven, the client**: `Sntp_Init`, `Sntp_SendTimeRequest` and
  `Sntp_ReceiveTimeResponse` over a UDP transport, diffed **callback for
  callback** across 23 scenarios as a 549-line trace — every clock read, every
  datagram, every rotation, and the context state after each one.
- **Integer arithmetic, on purpose.** coreSNTP targets parts with no
  floating-point unit, where an `f64` divide is a soft-float call on the receive
  path of every poll. It is also what makes this differentiable at all: two
  floating-point implementations agree to within an epsilon, and "within an
  epsilon" is not something a byte-for-byte trace can assert.
- **Zero allocation**, `forbid(unsafe)`, and a no-panic gate — a time client is
  fed over UDP, which is connectionless, so anything that can guess a port can
  deliver 48 bytes of its choosing.

**Known gaps.** None in coreSNTP's surface. This crate does not own a socket
and never will — it takes a transport, as the C does, so an application that
already has one can hand it over. `rusty_rtos_tcp` will be able to supply it.

**Two defects were found in the C while building this**, both reproduced
faithfully rather than fixed, both written up for filing. See
[The client](#the-client).

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

**Both halves are built and proven.** 160 trace lines agree with
`core_sntp_serializer.c` and 549 more with `core_sntp_client.c`, at the pinned
v2.0.0 — including the 2036 era wrap and the full callback sequence of 23 client
scenarios. 22 tests. Nothing has run on a chip.

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

## The client

**549 trace lines across 23 scenarios agree with `core_sntp_client.c`**,
callback for callback.

```sh
cargo test -p rusty_rtos_sntp-core --test client
```

The serializer is a pure function: give it bytes, compare bytes. The client is a
**state machine over five callbacks** — resolve a name, read the clock, adjust
the clock, send a datagram, receive one — and its observable behaviour is not
only what it returns but *which callbacks it calls, in what order, with what
arguments*. A transcription that produced the right status while reading the
clock a different number of times would be a different library, and a
differential that only checked statuses would bless it. So every callback is
scripted and logged on both sides, and the context state is printed after every
action, because where a state machine leaves itself is part of what it did.

```rust
use rusty_rtos_sntp::{Client, Reception, ServerInfo};

let servers = [ServerInfo::new("0.pool.ntp.org"), ServerInfo::new("1.pool.ntp.org")];
let mut buffer = [0u8; 48];
let mut client = Client::new(&servers, &mut buffer, 5_000)?;

client.send_time_request(&mut host, random_u32, 1_000)?;

match client.receive_time_response(&mut host, 1_000)? {
    Reception::Synchronised => {}          // the clock was adjusted
    Reception::NothingYet   => {}          // call again
    Reception::Rejected     => {}          // already rotated to the next server
    Reception::TimedOut     => {}          // already rotated
}
```

`host` implements `SntpHost`: five methods where the C takes five function
pointers and two opaque user contexts. One `&mut self` says the same thing.
Authentication stays a separate optional trait, because *configured* and *not
configured* behave differently — see below.

**A context that cannot be uninitialised.** The C's `validateContext` runs on
every call and can return `SntpErrorContextNotInitialized`, because a
`SntpContext_t` is a struct the caller allocates and might never have passed to
`Sntp_Init`. `Client::new` is the only way to obtain a `Client`, so that status
has no Rust equivalent and is in no error type here.

**Poison-proven on nine behaviours, all caught:** the server rotation wrapping
rather than stopping, the Kiss-o'-Death replay rule in both directions, DNS
being re-resolved on every request rather than cached, the response timeout
being checked before the block time, a partial send being accepted, the packet
size surviving a failed authentication, the retry window being opened by its own
clock read, and — see below — "fixing" the C's arithmetic.

### The replay-protection asymmetry

After a response it can use, the client clears its stored request timestamp, so
a replayed request's later response cannot be serviced twice. After a
**Kiss-o'-Death** it clears it *only when authentication is configured*.

Without authentication anyone can forge a rejection, and clearing on a forged one
would make the genuine response fail its originate check — turning a spoofed
packet into a denial of service. It is one `if` in the C and it is the most
security-relevant line in the file, so it has its own test: two scenarios that
must disagree.

### Two defects found in the C

Both are transcribed **exactly as they are**, because a differential whose arm
"fixes" its oracle is measuring two different libraries. Both are written up in
`kairos-upstream/drafts/coresntp-elapsed-time-underflow.md` for the owner to
file.

1. **`calculateElapsedTimeMs` underflows when the clock steps backwards.** Two
   readings in the same second with the newer one earlier make it subtract on a
   `uint64_t` that is still zero: half a second backwards gives
   `0 - 499` = 1.8 × 10¹⁹ ms. Every caller compares that against a timeout, so
   the client reports a response timeout for a request that has not timed out
   and rotates away from a working server. A clock stepping backwards is not
   contrived — it is what a host does when *this library* hands it a negative
   offset. Our transcription uses an explicit `wrapping_sub`, and a poison
   confirms that making it saturate **fails** the differential.

2. **The retry loops can spin for ever.** Both exit only when a deadline
   computed from the host's own clock is met, so a clock that does not make
   progress means the call never returns. An *oscillating* clock is the
   realistic trigger: elapsed times alternate rather than accumulate, and
   neither deadline is ever reached. `blockTimeMs` is documented as the maximum
   block time and does not bound it. **Our own gate found this by hanging**, and
   the bound is now enforced from inside the test host so the next one fails by
   name instead.

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
| **a hostile host** | 39 seeds x 40 rounds of send-and-receive against a transport that lies about how much it moved (including more than it was given), a DNS that fails one time in eight, and a clock whose fractions are random |
| **a hostile authenticator** | the same, plus codes of `u16::MAX` and of exactly the spare buffer |
| **every buffer size** | 0..96, each driven through a full round |
| **a clock running backwards** | half a second back on every reading, then recovering |
| **rotation** | three servers, seven timeouts, asserting the walk wraps |

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

## Part of Remade With Rust

This crate is part of **[Kairos](https://github.com/Remade-With-Rust/kairos)** —
FreeRTOS remade in memory-safe Rust, as independent packages that expose the API
a FreeRTOS developer already knows and prove every scheduling decision against
the C kernel's own trace. `rusty_rtos_sntp` is one of the K7 libraries: the
SNTPv4 client, proven against coreSNTP.

**Where this sits for Mata.** Kairos is the real-time layer on the device
itself, and [`rusty_rtos_mqtt`](https://github.com/Remade-With-Rust/rusty_rtos_mqtt) is the way out of it.
Paired with the **MATA distributed cloud**, robotics and sensor data has two
routes — read it on the machine, or reach it through the cloud — with the same
memory-safe crates at both ends.

The family:
[`rusty_rtos_core`](https://crates.io/crates/rusty_rtos_core) (the shared vocabulary),
[`rusty_rtos_kernel`](https://crates.io/crates/rusty_rtos_kernel) (the scheduler),
[`rusty_rtos_port`](https://crates.io/crates/rusty_rtos_port) (the architecture seam),
[`rusty_rtos_heap`](https://crates.io/crates/rusty_rtos_heap) (the allocators),
[`rusty_rtos_json`](https://github.com/Remade-With-Rust/rusty_rtos_json) (coreJSON),
[`rusty_rtos_sntp`](https://github.com/Remade-With-Rust/rusty_rtos_sntp) (coreSNTP),
[`rusty_rtos_mqtt`](https://github.com/Remade-With-Rust/rusty_rtos_mqtt) (coreMQTT),
[`rusty_rtos_backoff`](https://github.com/Remade-With-Rust/rusty_rtos_backoff) (backoffAlgorithm),
[`rusty_rtos-capi`](https://github.com/Remade-With-Rust/rusty_rtos-capi) (the C ABI) and
[`rusty_rtos_demo`](https://github.com/Remade-With-Rust/rusty_rtos_demo) (the conformance corpus).
The last six are on GitHub and not yet on crates.io. Also check out
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

MIT OR Apache-2.0, at your option. FreeRTOS is MIT-licensed by Amazon.com,
Inc. or its affiliates; this crate remakes its API and behaviour from the
published sources and links no FreeRTOS code.

---

<!-- HARDENING-TABLE:BEGIN generated by use-protection-please — edit docs/plans/use-protection-please.md, not this block -->
## Hardening status

**Tier** critical-path · **Audited** unrecorded (survey) · **v1.0.0 gates** 6/16 · [Full checklist](https://github.com/Remade-With-Rust/rusty_rtos_sntp/blob/main/docs/plans/use-protection-please.md)

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
