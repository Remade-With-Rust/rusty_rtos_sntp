# rusty_rtos_sntp — package plan

**One sentence:** coreSNTP remade in Rust — the SNTPv4 packet codec and its
clock arithmetic (done, and diffed against the C across the 2036 era wrap)
and the client state machine (not written), integer-only, zero allocation,
no_std, forbid(unsafe).

Family plan: Kairos `docs/plans/rtos-mission.md` (umbrella repo) — its §2.1
names what this package remakes, wraps and never touches; its §6 carries the
phase this package's kill test belongs to. This file obeys that one.

Written 2026-09-16. Status: **the serializer is built and proven** — 160 trace
lines agree with `core_sntp_serializer.c` at the pinned v2.0.0, including both
sides of the 2036 era wrap; the client state machine is not written.

---

## 1. What it is, what it is not

**Is:** the Rust remake of the FreeRTOS component named above, exposing the
names a FreeRTOS developer already knows, with the C original as the oracle.

**Is not:** a binding to the C code, a fork of it, or a place where a chip's
registers are touched (that is a port crate).

## 2. The laws this package encodes

1. The core is `no_std` (+ `alloc`), `forbid(unsafe)`, arch-agnostic.
2. Every parser that takes bytes from a wire, a store or a bus has a
   `tests/no_panic.rs` from the day it exists.
3. Every claim has a kill test or a ledger row; the README copies this plan
   and never upgrades it.
4. Feature ladder `std` ⊃ `alloc` ⊃ core-only; CI proves the two bare-metal
   rungs on four targets on every push.

## 3. The surface as built

`core_sntp_serializer.c`, whole. `core_sntp_client.c` is not started.

| ours | coreSNTP | note |
|---|---|---|
| `serialize_request(&mut Timestamp, u32, &mut [u8])` | `Sntp_SerializeRequest` | the timestamp is **in-out**, as in the C: random bits are OR-ed into its fractions |
| `deserialize_response(&Timestamp, &Timestamp, &[u8]) -> Result<Verdict, DeserializeError>` | `Sntp_DeserializeResponse` | a Kiss-o'-Death is a `Verdict`, not an error: the server answered, and the answer was no |
| `calculate_poll_interval(u16, u16) -> Result<u32, PollIntervalError>` | `Sntp_CalculatePollInterval` | floors to a power of two |
| `convert_to_unix_time(&Timestamp) -> (u32, u32)` | `Sntp_ConvertToUnixTime` | **cannot fail**: the C's only error is a NULL pointer, and there are none here |
| `Timestamp`, `LeapSecond`, `Accepted`, `Rejected`, `Rejection`, `Verdict` | `SntpTimestamp_t`, `SntpLeapSecondInfo_t`, `SntpResponseData_t` | a rejected response and an accepted one carry different fields, so they are different types |
| `SerializeError`, `DeserializeError`, `PollIntervalError` | `SntpStatus_t` | three enums, each holding only the variants its function can produce |

Integer arithmetic throughout, zero allocation, `forbid(unsafe)`. The core
builds with no default features on `thumbv7em-none-eabihf` and
`riscv32imac-unknown-none-elf`.

## 4. Roadmap

| Milestone | Adds | Driven by | Kill test |
|---|---|---|---|
| scaffold | the shape | K0 | a clean clone builds alone; CI green ✅ |
| **serializer** | the packet codec and its arithmetic | K7 | **160 trace lines agree with `core_sntp_serializer.c`, including both sides of the 2036 era wrap** ✅ |
| client | `Sntp_Init`, `Sntp_SendTimeRequest`, `Sntp_ReceiveTimeResponse` | K7 | a differential against `core_sntp_client.c` over a mock transport, which is how the C's own tests drive it |
| on a chip | the UDP seam over `rusty_rtos_tcp` | K7/K8 | a real server answers, and the offset is sane |

## 5. Deliberately absent

| Absent | Why |
|---|---|
| floating point | coreSNTP targets parts with no FPU, and the clock offset is computed on the receive path of every poll. It is also what makes this differentiable: two floating-point implementations agree to within an epsilon, and a byte-for-byte trace cannot assert "within an epsilon". |
| a socket | the C takes a transport interface and so will the client. A library that owns a socket cannot be used by an application that already has one. |
| NTS, and NTP's full clock discipline | this is **S**NTP: one server, one exchange, no filtering or falsetickering. The house `rusty_time` is where the full NTPv4 engine lives (§7). |
| a status for `convert_to_unix_time` | the C returns one only because all three parameters are pointers that could be NULL. With a reference and a returned tuple there is nothing left to refuse. |
| our own randomness | the caller supplies it, as the C does. The entropy source is the application's business, and keeping that boundary is what lets both arms be driven from one table. |

## 6. Risks

| Risk | Mitigation |
|---|---|
| **The hardest defect here is dated.** The seconds field wraps on 7 Feb 2036; a wrong era comparison is correct until then and silently wrong afterwards, and no amount of testing-against-today would find it. | The differential carries cases either side of the wrap, at the exact half-era tie from **both** directions, and one where the send leg crosses an era boundary while the receive leg does not. Poisoning the tie fails the run. |
| A response arrives over UDP, which is connectionless: anything that can guess a port can deliver 48 bytes of its choosing. | `tests/no_panic.rs` drives every entry point with arbitrary bytes, packet-shaped noise, every truncation and every single-byte corruption. The library's own validation — mode, zero timestamps, the echoed originate field — is what rejects them, and every one of those checks runs on attacker-chosen bytes. |
| `serialize_request` MUTATES its timestamp, and a client that stores the pre-call value would reject every genuine response. | A round-trip test builds a request, constructs the response a server would send, and requires it to be accepted. Making the timestamp read-only fails it. Nothing that exercised the two functions separately would. |
| The workload could agree with a C driver whose table has drifted from the one in the repository. | The trace carries its own inputs: every answer line is preceded by an `in` line holding the full call, packet bytes included. There is no second copy of the table to drift. |
| An unreached status makes the differential weaker than it looks. | A standing test fails if any of the eight statuses, or any of the four leap-second values, is never produced — and if no clock offset is ever negative or ever large enough to have crossed an era. |

## 7. Decision log

| Date | Decision |
|---|---|
| 2026-09-16 | Stamped from the Kairos template; obeys the family plan. |
| 2026-09-16 | **§5.5 settled, and the row that blocked it was stale.** The mission plan said `rusty_time-core` carried the `no-std` category without `#![no_std]`, measured 2026-09-09, and that until a `no_std` leaf landed this package was a coreSNTP remake. `rusty_time-core` **0.2.0 was published 2026-09-10** and builds clean on `thumbv7em-none-eabihf` with no default features, pulling in nothing else — measured, not assumed. So the blocker is gone. |
| 2026-09-16 | **This is still a coreSNTP remake, for a different reason than the one recorded.** `rusty_time-core` has a real NTPv4 codec (`NtpPacket::parse`, `to_bytes`), but its time arithmetic is `f64` — `NtpTimestamp::seconds_since` and `NtpShort::to_seconds` both return one. coreSNTP's clock offset is integer milliseconds with specific truncation, computed on the receive path of every poll on parts with no FPU. Sharing the codec alone would buy ~40 lines of byte shuffling and cost a dependency whose arithmetic this package cannot use. The two crates do different jobs at the same protocol: `rusty_time` is the NTPv4 engine, this is the coreSNTP API. |
| 2026-09-16 | **The trace carries its own inputs.** `backoff` kept the case table in both arms; that is a drift nothing catches, because two arms can agree perfectly about a workload that is not the one the driver documents. Here every answer line is preceded by an `in` line and the Rust arm replays it. Every later K7 differential does this. |
| 2026-09-16 | **Two poisons did not fire, and both are properties.** The UNIX era split can use `>` or `>=` because the two era constants sum to **exactly 2^32**, so the era-0 subtraction and the era-1 wrapping addition meet at the boundary — which is *why* the era-1 formula is a plain wrapping add. The `<=` in the three-way era comparison can be a `<` because its equality cases are exactly the half-era tie, which the special case has already returned on. Both are pinned by unit tests rather than left as coincidences. |
| 2026-09-16 | **The half-era tie is only observable from one side**, which a poison found. For a positive tie the general three-way comparison produces the same answer, so the special case earns its keep only when the client is half an era ahead — there it turns a -2^31 second answer into a +2^31 second one. A case was added for that side; without it the special case was untested. |
| 2026-09-16 | **`kairos new`'s template was emitting a `git =` dependency on `rusty_rtos_core`.** That is what `cargo publish` refuses, and it silently defeats the umbrella's `[patch.crates-io]` rows — a patch aimed at crates-io cannot reach a dependency resolved from a git URL, so this package was building against the PUBLISHED core while every sibling built against the local one. The v0.1.0 release pass removed these from the existing packages and missed the template. Fixed in both. |
