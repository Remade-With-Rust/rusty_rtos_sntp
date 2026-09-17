# rusty_rtos_sntp — the ledger

Every number this package claims, with the run that produced it. A row
without a method is not a number. Counters before clocks; an external oracle
before a self-metric; the method line names the machine, the pinning, the arm
order and the null-arm floor for anything timed.

## Conformance (2026-09-16) — the serializer

A count is a number and belongs here with its method, exactly as a timing
would. These are the numbers the README quotes.

| quantity | value | method |
|---|---|---|
| trace lines agreeing with the C | **160 / 160** | `cargo test -p rusty_rtos_sntp-core --test serializer`. C arm: `oracle/sntp_driver.c` driving `core_sntp_serializer.c` compiled verbatim from the pinned checkout (v2.0.0 at `50f5f96`), built with `-DSNTP_DO_NOT_USE_CUSTOM_CONFIG`, which is the library's own switch for its shipped defaults rather than a change to it. |
| calls compared | **75** | 14 `Sntp_SerializeRequest`, 30 `Sntp_DeserializeResponse`, 18 `Sntp_CalculatePollInterval`, 13 `Sntp_ConvertToUnixTime`. Each compares every observable the call produces — for a serialize that is the status, the MUTATED request timestamp and all 48 packet bytes. |
| ignored-field cases | **4** | one accepted response with poll, precision, root delay, root dispersion and the reference timestamp filled with `00`, `FF`, `5A` and `A5`. All four parse identically, which is what proves those fields are ignored rather than merely absent from every other case. |
| statuses reached | **8 of 8** | Success, BadParameter, BufferTooSmall, InvalidResponse, RejectedChangeServer, RejectedRetryWithBackoff, RejectedOtherCode, ZeroPollInterval. A standing test fails if any is never produced. |
| leap-second values reached | **4 of 4** | none, 61 seconds, 59 seconds, and the server-not-synchronised alarm. |
| era-wrap coverage | both sides, and the tie from both directions | the differential fails if no clock offset is ever negative, or if none is ever large enough to have crossed an era. |
| poison rows | **6 caught, 2 not** | caught: the half-era tie, the fraction divisor, the guard order, the replay-protection shift, the poll-interval rounding, the leap-indicator bit position. Not caught: the UNIX era split's `>=`, and the `<=` in the era comparison — both are properties, pinned by unit tests, see the plan's decision log. |

## Conformance (2026-09-16) — the client

The client is a state machine over five callbacks, so the differential compares
the CALLBACK SEQUENCE, not only the return values. A transcription that
returned the right status while reading the clock a different number of times
would be a different library.

| quantity | value | method |
|---|---|---|
| trace lines agreeing with the C | **549 / 549** | `cargo test -p rusty_rtos_sntp-core --test client`. C arm: `oracle/client_driver.c` driving `core_sntp_client.c` compiled verbatim from v2.0.0 at `50f5f96`, with scripted mocks for all five callbacks. Our arm replays the scenarios from the trace's own `cfg` lines, so there is no second copy of the C's tables. |
| scenarios | **23** | the happy path, DNS failure, send error / retry / timeout / partial, receive error / partial / block-time expiry / response timeout, Kiss-o'-Death with and without authentication, an originate field that does not echo, three authentication failures, two `Sntp_Init` refusals, rotation wrapping a list, and two clock-arithmetic edge cases. |
| distinct outcomes reached | **12** | Success, DnsFailure, NetworkFailure, SendTimeout, NoResponseReceived, ResponseTimeout, RejectedResponse, InvalidResponse, AuthFailure, ServerNotAuthenticated, BadParameter, BufferTooSmall. A standing test fails if any is never produced, and if any of the seven callbacks is never called. |
| poison rows | **9 caught, 0 missed** | rotation wrapping, the Kiss-o'-Death replay rule in both directions, DNS caching, deadline ordering, a partial send accepted, the packet size after a failed authentication, the retry window's own clock read, and "fixing" the C's arithmetic — which must FAIL, and does. |

**A poison found a real defect in the transcription.** The C never resets
`sntpPacketSize` in `Sntp_SendTimeRequest`, so a failed authentication leaves
the previous request's size in place; we had added a tidy reset. No scenario
sent two authenticated requests, so nothing caught it. One was added, it failed,
and the reset came out. That is the workload gap and the code defect found by
the same probe.

## Defects found in the C (2026-09-16)

Both are transcribed exactly rather than fixed, because a differential whose arm
"fixes" its oracle is measuring two different libraries. Draft for filing:
`kairos-upstream/drafts/coresntp-elapsed-time-underflow.md`.

| defect | evidence | our position |
|---|---|---|
| `calculateElapsedTimeMs` underflows when the clock steps backwards within one second | `0 - 499` on a `uint64_t` gives 18,446,744,073,709,551,117 ms; every caller compares it against a timeout, so a half-second backward step produces a spurious `SntpErrorResponseTimeout` and rotates away from a working server. Scenario `elapsed-time-fractions-go-backwards`. | reproduced with an explicit `wrapping_sub`; a poison confirms that making it saturate FAILS the differential, which is how we know the comparison is sensitive to that line |
| both retry loops can spin for ever | they exit only when a deadline computed from the host's own clock is met, so an oscillating clock (elapsed alternating 499 ms / 0 ms) never reaches either. `blockTimeMs` is documented as the maximum block time and does not bound it | **found by our own gate hanging.** Documented on `receive_time_response` where a caller will see it; the gate's bound now lives inside the test host so the next spin fails by name |

## The no-panic gate (2026-09-16)

An SNTP response arrives over **UDP**, which is connectionless: anything on the
path, or anything that can guess a port, can deliver 48 bytes of its choosing.
Every validation the library performs runs on bytes an attacker picked.

| quantity | value | method |
|---|---|---|
| deserialize calls with no panic | **56,769** | `cargo test -p rusty_rtos_sntp-core --test no_panic`: 6,144 arbitrary-byte calls (every length 0..96, 64 samples each) + 40,000 packet-shaped (half forced to server mode, half echoing the request, so validation is passed and the arithmetic is reached) + 10,000 era-arithmetic extremes (ten extreme second values across all four round-trip timestamps) + 49 truncations + 576 single-byte corruptions. |
| serialize calls | **3,072** | every buffer size 0..96, 32 samples each. |
| poll-interval calls | **1,048,576** | both `u16` axes swept in full against a spread of eight values of the other. Sweeping the full product is 4.3 billion; this reaches both refusals and every power-of-two answer. |
| unix conversions | **102,000** | 100,000 random plus a 2,000-wide window around the era boundary. |
| round-trip property | **2,000** | a request is serialized, the response a server would send is constructed from it, and it must be accepted. This is the only test that spans both entry points, and the only one that catches `serialize_request` being treated as read-only. |
| deliberate panics introduced in the serializer | **4, of which 2 caught** | caught: the read-only request timestamp (round trip), the removed buffer-size guard. Not caught: indexing the field reader and the packet writer unchecked — the entry points check the length once and every field offset lies inside those 48 bytes, so those bounds are defence in depth. Third time this family has measured that same shape. |
| client rounds against a hostile host | **3,120** | 39 seeds x 40 send-and-receive rounds against a transport that lies about how much it moved (including more than it was given), a DNS that fails one time in eight and a clock with random fractions; then the same again with an authenticator returning `u16::MAX` sizes. |
| client liveness | **asserted from inside the host** | both retry loops exit only on a clock deadline, so a spin does not panic, it hangs. The bound is enforced in the mock's own `tick`, which turns the next spin into a named failure with a call count. The first version asserted after the call returned and hung instead -- that is how the second C defect above was found. |

## The build fact (2026-09-16)

| gate | result |
|---|---|
| `cargo test -p rusty_rtos_sntp-core` | 22 passed, 0 failed (3 unit, 9 serializer no-panic, 2 serializer differential, 3 client differential, 5 client no-panic) |
| `cargo clippy --all-targets --all-features` under the workspace lint policy | clean, 0 warnings |
| `cargo build -p rusty_rtos_sntp --no-default-features --target thumbv7em-none-eabihf` | passes |
| `cargo build -p rusty_rtos_sntp --no-default-features --target riscv32imac-unknown-none-elf` | passes |

## Measurements that decided something (2026-09-16)

| question | measurement | what it decided |
|---|---|---|
| Is `rusty_time-core` usable as the SNTP engine? | 0.2.0 (published 2026-09-10) builds clean on `thumbv7em-none-eabihf` with no default features, pulling in nothing else. | The mission plan's blocking row was **stale**: the `no_std` leaf landed. |
| Should this package then WRAP it? | Its time arithmetic is `f64` — `NtpTimestamp::seconds_since` and `NtpShort::to_seconds` both return one. coreSNTP's clock offset is integer milliseconds with specific truncation, on parts with no FPU. | No. Sharing the codec alone buys ~40 lines of byte shuffling and costs a dependency whose arithmetic this package cannot use. |
| Do the two era constants really meet at the boundary? | `2_208_988_800 + 2_085_978_496 == 4_294_967_296 == 2^32`, and the boundary second gives 0 down either branch. | Why the era-1 formula is a plain wrapping add, and why a poison on `>=` vs `>` cannot fire. |

No speed number and no size number: nothing here has been benchmarked, and
nothing has run on a chip.
