//! The serializer against `core_sntp_serializer.c`, call for call.
//!
//! The C arm is `oracle/sntp_driver.c` driving `core_sntp_serializer.c`
//! compiled VERBATIM from the pinned checkout (v2.0.0 at `50f5f96`), and its
//! trace is checked in — so this runs in CI with no C toolchain, the same
//! arrangement the kernel corpus, the heap differentials, `backoff` and `json`
//! all use.
//!
//! # The trace carries its own inputs
//!
//! Every answer line is preceded by an `in` line holding everything the call
//! needs, packet bytes included. That is deliberate and it is a change from
//! `backoff`, where both arms kept a copy of the case table: two tables drift,
//! and nothing catches two arms agreeing about a workload that is not the one
//! the driver documents. Here the trace **is** the workload. The geometry line
//! and the per-kind counts are what stop it being edited quietly.
//!
//! # What is actually hard here
//!
//! An SNTP timestamp's seconds field wraps on 7 February 2036, so a client and
//! a server can sit either side of the wrap and disagree by ~136 years on a
//! naive subtraction. `safeTimeDifference` computes the difference three ways
//! and keeps the smallest absolute value. A transcription that gets the packet
//! layout perfect and that comparison wrong is right until 2036 and silently
//! wrong afterwards — which is exactly the kind of defect no amount of
//! testing-against-today would find, and exactly what a differential does.

// A test asserts; the workspace's deny-by-default is written for library code
// where a panic is a defect. This one parses a checked-in trace, so an
// out-of-range field means the trace and the parser have gone out of step --
// which should stop the run, and does.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fmt::Write as _;

use rusty_rtos_sntp_core::{
    DeserializeError, LeapSecond, PACKET_BASE_SIZE, PollIntervalError, Rejection, SerializeError,
    Timestamp, Verdict, calculate_poll_interval, convert_to_unix_time, deserialize_response,
    serialize_request,
};

/// The C driver's trace, generated once and checked in.
const TRACE: &str = include_str!("../../../oracle/sntp.trace");

/// The 0xAA fill the driver puts in a buffer before every call, so a byte the
/// library does NOT write shows up as junk rather than as a plausible zero.
const FILL: u8 = 0xAA;

/// The driver's buffer is always this big; `bufferSize` is what it CLAIMS.
const DRIVER_BUFFER: usize = PACKET_BASE_SIZE + 16;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd-length hex: {text:?}");
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let s = core::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(s, 16).expect("hex digit")
        })
        .collect()
}

fn u32_hex(text: &str) -> u32 {
    u32::from_str_radix(text, 16).unwrap_or_else(|e| panic!("bad hex {text:?}: {e}"))
}

const fn leap_name(l: LeapSecond) -> &'static str {
    match l {
        LeapSecond::None => "NoLeapSecond",
        LeapSecond::LastMinuteHas61Seconds => "Has61",
        LeapSecond::LastMinuteHas59Seconds => "Has59",
        LeapSecond::AlarmServerNotSynchronized => "Alarm",
    }
}

/// Our verdict, in the C's `SntpStatus_t` vocabulary.
///
/// Our types are richer than the C's single enum only in that they cannot
/// express the impossible variant; mapping back to its names is what makes the
/// two arms comparable at all.
fn deser_status(r: &Result<Verdict, DeserializeError>) -> &'static str {
    match r {
        Ok(Verdict::Accepted(_)) => "Success",
        Ok(Verdict::Rejected(rejected)) => match rejected.kind {
            Rejection::ChangeServer => "RejectedChangeServer",
            Rejection::RetryWithBackoff => "RejectedRetryWithBackoff",
            Rejection::Other => "RejectedOtherCode",
        },
        Err(DeserializeError::BadParameter) => "BadParameter",
        Err(DeserializeError::BufferTooSmall) => "BufferTooSmall",
        Err(DeserializeError::InvalidResponse) => "InvalidResponse",
    }
}

/// The parsed half of a deserialize line, which the driver prints only for the
/// four statuses where the C has actually populated its output struct.
fn deser_detail(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Accepted(a) => format!(
            " {:08x} {:08x} {} {:08x} {}",
            a.server_time.seconds,
            a.server_time.fractions,
            leap_name(a.leap_second),
            0u32,
            a.clock_offset_ms
        ),
        // On a Kiss-o'-Death the C zeroes the whole output struct and fills in
        // only the code, so server time is zero and the leap second reads as
        // "none" -- which is an artefact of the memset, not a claim about the
        // server, and is reproduced here rather than tidied.
        Verdict::Rejected(r) => format!(
            " {:08x} {:08x} {} {:08x} {}",
            0u32, 0u32, "NoLeapSecond", r.code, 0i64
        ),
    }
}

/// Replay the trace's inputs through our side and produce the same lines.
fn our_trace() -> String {
    let mut out = String::new();
    let mut lines = TRACE.lines().peekable();

    // The geometry line is a premise, not decoration: a trace from a different
    // driver would make every later comparison meaningless.
    let geometry = lines.next().expect("a geometry line");
    let _ = writeln!(out, "{geometry}");
    assert!(
        geometry.contains(&format!("base={PACKET_BASE_SIZE}")),
        "the two arms disagree about the packet size: {geometry:?}"
    );

    while let Some(line) = lines.next() {
        let f: Vec<&str> = line.split_whitespace().collect();

        if f.first() == Some(&"end") {
            let _ = writeln!(out, "end");
            continue;
        }

        // Only `in` lines drive anything; the `out` line that follows is what
        // we are about to reproduce, so it is consumed and discarded.
        assert_eq!(
            f.get(2),
            Some(&"in"),
            "expected an input line, got {line:?}"
        );
        let _ = writeln!(out, "{line}");
        let answered = lines.next().expect("an output line after every input");
        assert_eq!(
            answered.split_whitespace().nth(2),
            Some("out"),
            "expected an output line, got {answered:?}"
        );

        let kind = f[0];
        let index: usize = f[1].parse().expect("a case index");

        match kind {
            "serialize" => {
                let mut t = Timestamp::new(u32_hex(f[3]), u32_hex(f[4]));
                let random = u32_hex(f[5]);
                let size: usize = f[6].parse().expect("a buffer size");

                let mut buffer = [FILL; DRIVER_BUFFER];
                let claimed = buffer
                    .get_mut(..size)
                    .expect("the driver's buffer is big enough");
                let r = serialize_request(&mut t, random, claimed);

                let status = match r {
                    Ok(()) => "Success",
                    Err(SerializeError::BadParameter) => "BadParameter",
                    Err(SerializeError::BufferTooSmall) => "BufferTooSmall",
                };

                let _ = writeln!(
                    out,
                    "serialize {index} out {status} {:08x} {:08x} {}",
                    t.seconds,
                    t.fractions,
                    hex(buffer.get(..PACKET_BASE_SIZE).expect("48 bytes"))
                );
            }

            "deser" | "ignored" => {
                // `ignored` carries one extra leading field, the fill byte.
                let base = if kind == "ignored" { 4 } else { 3 };
                let request = Timestamp::new(u32_hex(f[base]), u32_hex(f[base + 1]));
                let rx = Timestamp::new(u32_hex(f[base + 2]), u32_hex(f[base + 3]));
                let size: usize = f[base + 4].parse().expect("a buffer size");
                let packet = unhex(f[base + 5]);

                let claimed = packet
                    .get(..size)
                    .expect("the driver's packet is big enough");
                let r = deserialize_response(&request, &rx, claimed);

                let status = deser_status(&r);
                let detail = match (&r, kind) {
                    // The driver prints the parsed struct only where the C has
                    // filled it in; `ignored` always reaches that point.
                    (Ok(v), _) => deser_detail(v),
                    (Err(_), _) => String::new(),
                };

                let _ = writeln!(out, "{kind} {index} out {status}{detail}");
            }

            "poll" => {
                let tolerance: u16 = f[3].parse().expect("a tolerance");
                let accuracy: u16 = f[4].parse().expect("an accuracy");

                match calculate_poll_interval(tolerance, accuracy) {
                    Ok(interval) => {
                        let _ = writeln!(out, "poll {index} out Success {interval}");
                    }
                    Err(PollIntervalError::BadParameter) => {
                        let _ = writeln!(out, "poll {index} out BadParameter");
                    }
                    Err(PollIntervalError::ZeroPollInterval) => {
                        let _ = writeln!(out, "poll {index} out ZeroPollInterval");
                    }
                }
            }

            "unix" => {
                let t = Timestamp::new(u32_hex(f[3]), u32_hex(f[4]));
                let (seconds, micros) = convert_to_unix_time(&t);
                // Ours cannot fail, so the C's status is always Success here.
                let _ = writeln!(out, "unix {index} out Success {seconds} {micros}");
            }

            other => panic!("unknown trace line kind {other:?}"),
        }
    }

    out
}

#[test]
fn our_serializer_matches_the_c_call_for_call() {
    let ours = our_trace();
    let mut theirs = TRACE.lines();
    let mut our_lines = ours.lines();
    let mut n = 0usize;

    loop {
        match (theirs.next(), our_lines.next()) {
            (None, None) => break,
            (Some(t), Some(o)) => assert_eq!(o, t, "line {n} diverged\n  the C: {t}\n  ours : {o}"),
            (Some(t), None) => panic!("our trace ran out at line {n}; the C still has {t:?}"),
            (None, Some(o)) => panic!("the C trace ran out at line {n}; we still have {o:?}"),
        }
        n = n.saturating_add(1);
    }

    assert_eq!(n, 160, "the trace should be 160 lines, not {n}");
}

/// The guard: the workload must reach every outcome each entry point has.
///
/// heap_4's guard fails on too few refusals, heap_1's on never exhausting,
/// heap_5's on an unvisited region, backoff's on an unvisited branch, json's
/// on a corpus that stops being mostly rejections and on an unreached query
/// outcome. This is the sixth shape, and it says the same thing: a
/// differential whose workload cannot fail is a differential about nothing.
#[test]
fn the_workload_reaches_every_outcome() {
    let mut seen: Vec<&str> = TRACE
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.get(2) == Some(&"out") {
                f.get(3).copied()
            } else {
                None
            }
        })
        .collect();
    seen.sort_unstable();
    seen.dedup();

    for required in [
        "Success",
        "BadParameter",
        "BufferTooSmall",
        "InvalidResponse",
        "RejectedChangeServer",
        "RejectedRetryWithBackoff",
        "RejectedOtherCode",
        "ZeroPollInterval",
    ] {
        assert!(
            seen.contains(&required),
            "the workload never produces {required}: it reaches only {seen:?}"
        );
    }

    // Every leap-second value must be produced, or three quarters of that
    // mapping is untested.
    for name in ["NoLeapSecond", "Has61", "Has59", "Alarm"] {
        assert!(
            TRACE.contains(name),
            "the workload never produces the leap indicator {name}"
        );
    }

    // And the era arithmetic must actually cross an era. A negative offset,
    // and one larger than a whole era's worth of milliseconds, are the two
    // signs the wrap was exercised rather than avoided.
    let offsets: Vec<i64> = TRACE
        .lines()
        .filter(|l| l.contains(" out Success "))
        .filter_map(|l| l.split_whitespace().last())
        .filter_map(|s| s.parse::<i64>().ok())
        .collect();

    assert!(
        offsets.iter().any(|o| *o < 0),
        "no negative clock offset: the client is never ahead of the server"
    );
    assert!(
        offsets.iter().any(|o| *o > 1_000_000_000),
        "no clock offset large enough to have crossed an NTP era"
    );
}
