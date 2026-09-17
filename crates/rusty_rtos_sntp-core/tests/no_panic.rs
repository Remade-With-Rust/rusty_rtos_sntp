//! K7's no-panic gate for the SNTP serializer.
//!
//! The crate forbids `unsafe` and denies `unwrap`, `expect` and `panic`, so a
//! panic is reachable only through arithmetic that overflows, an index out of
//! range, or a slice shorter than something assumed. The lints catch the
//! SHAPES; this goes after the reachability.
//!
//! **A time client is fed by strangers, and worse than most.** An SNTP response
//! arrives over UDP, which is connectionless — anything on the path, or anything
//! that can guess a port, can deliver 48 bytes of its choosing. The library's
//! own validation (mode, zero timestamps, the echoed originate field) exists to
//! reject those, and every one of those checks runs on bytes an attacker chose.
//! "Cannot panic on any input" is the security property, not tidiness.
//!
//! The differential next door compares ANSWERS over a chosen workload. This
//! asserts the weaker and more important thing over inputs nobody chose.

// A test asserts; the workspace's deny-by-default is written for library code
// where a panic is a defect.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rusty_rtos_sntp_core::{
    PACKET_BASE_SIZE, Timestamp, Verdict, calculate_poll_interval, convert_to_unix_time,
    deserialize_response, serialize_request,
};

/// An LCG, so the "random" inputs are the same on every machine and a failure
/// is reproducible from the seed alone.
struct Lcg(u32);

impl Lcg {
    const fn new(seed: u32) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        self.0
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 16) as u8
    }

    fn timestamp(&mut self) -> Timestamp {
        Timestamp::new(self.next(), self.next())
    }
}

/// A well-formed response, as a starting point for corruption.
fn good_packet() -> [u8; PACKET_BASE_SIZE] {
    let mut p = [0u8; PACKET_BASE_SIZE];
    p[0] = 0x24; // leap 0, version 4, mode 4 (server)
    p[1] = 1; // stratum 1
    p[24..28].copy_from_slice(&1000u32.to_be_bytes()); // originate seconds
    p[28..32].copy_from_slice(&7u32.to_be_bytes()); // originate fractions
    p[32..36].copy_from_slice(&1005u32.to_be_bytes()); // receive
    p[36..40].copy_from_slice(&1u32.to_be_bytes());
    p[40..44].copy_from_slice(&1006u32.to_be_bytes()); // transmit
    p[44..48].copy_from_slice(&1u32.to_be_bytes());
    p
}

const REQUEST: Timestamp = Timestamp::new(1000, 7);
const RX: Timestamp = Timestamp::new(1002, 0);

/// Bytes with no structure at all, at every length around the packet size.
#[test]
fn arbitrary_bytes_never_panic() {
    let mut rng = Lcg::new(1);

    for len in 0..96usize {
        for _ in 0..64 {
            let buf: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            let request = rng.timestamp();
            let rx = rng.timestamp();
            let _ = deserialize_response(&request, &rx, &buf);
        }
    }
}

/// Full-size packets of random bytes, with random request and receive times.
///
/// A packet-shaped input reaches far deeper than a short one: the length check
/// passes, the mode check sometimes passes, and then the era arithmetic runs on
/// whatever 64-bit values the bytes happen to encode. That arithmetic is where
/// an overflow would live.
#[test]
fn packet_shaped_noise_never_panics() {
    let mut rng = Lcg::new(2);

    for _ in 0..40_000 {
        let mut buf = [0u8; PACKET_BASE_SIZE];
        for b in &mut buf {
            *b = rng.byte();
        }

        // Half the time, force the mode bits to "server" so validation gets
        // past its first gate and the arithmetic is actually reached.
        if rng.next() % 2 == 0 {
            buf[0] = (buf[0] & !0x07) | 0x04;
        }

        let request = rng.timestamp();
        let rx = rng.timestamp();

        // And sometimes make the originate field echo the request, so the
        // packet passes validation entirely and the clock offset is computed.
        if rng.next() % 2 == 0 {
            buf[24..28].copy_from_slice(&request.seconds.to_be_bytes());
            buf[28..32].copy_from_slice(&request.fractions.to_be_bytes());
        }

        let _ = deserialize_response(&request, &rx, &buf);
    }
}

/// The extremes of the era arithmetic, exhaustively over the interesting bits.
///
/// `safeTimeDifference` multiplies a 32-bit seconds field by 1000 and then adds
/// and subtracts a whole era. With `u32::MAX` seconds on both sides that is
/// ~8.6e12, which fits in an `i64` — but only just enough that it is worth
/// proving rather than assuming.
#[test]
fn the_era_arithmetic_never_overflows() {
    const EXTREMES: [u32; 10] = [
        0,
        1,
        0x7FFF_FFFF,
        0x8000_0000,
        0x8000_0001,
        0xFFFF_FFFE,
        0xFFFF_FFFF,
        2_208_988_800,
        2_085_978_496,
        61_505_151,
    ];

    for server_rx in EXTREMES {
        for server_tx in EXTREMES {
            for client_tx in EXTREMES {
                for client_rx in EXTREMES {
                    let request = Timestamp::new(client_tx, u32::MAX);
                    let rx = Timestamp::new(client_rx, u32::MAX);

                    let mut p = [0u8; PACKET_BASE_SIZE];
                    p[0] = 0x24;
                    p[1] = 1;
                    p[24..28].copy_from_slice(&request.seconds.to_be_bytes());
                    p[28..32].copy_from_slice(&request.fractions.to_be_bytes());
                    p[32..36].copy_from_slice(&server_rx.to_be_bytes());
                    p[36..40].copy_from_slice(&u32::MAX.to_be_bytes());
                    p[40..44].copy_from_slice(&server_tx.to_be_bytes());
                    p[44..48].copy_from_slice(&u32::MAX.to_be_bytes());

                    let _ = deserialize_response(&request, &rx, &p);
                }
            }
        }
    }
}

/// Every truncation of a well-formed packet.
///
/// A scanner that reads one byte past its bound does it at the END of the
/// buffer, and a short UDP datagram is a thing an attacker can send for free.
#[test]
fn every_truncation_of_a_good_packet_is_safe() {
    let packet = good_packet();

    for cut in 0..=packet.len() {
        let Some(slice) = packet.get(..cut) else {
            continue;
        };
        let _ = deserialize_response(&REQUEST, &RX, slice);
    }
}

/// Every single-byte corruption of a well-formed packet.
#[test]
fn every_single_byte_corruption_is_safe() {
    let packet = good_packet();
    let interesting: &[u8] = &[
        0x00, 0x01, 0x03, 0x04, 0x07, 0x24, 0x7F, 0x80, 0xAA, 0xE4, 0xFE, 0xFF,
    ];

    for pos in 0..packet.len() {
        for &byte in interesting {
            let mut corrupted = packet;
            if let Some(slot) = corrupted.get_mut(pos) {
                *slot = byte;
            }
            let _ = deserialize_response(&REQUEST, &RX, &corrupted);
        }
    }
}

/// Serializing into every buffer size, with every kind of timestamp.
#[test]
fn serializing_into_any_buffer_is_safe() {
    let mut rng = Lcg::new(3);

    for size in 0..96usize {
        for _ in 0..32 {
            let mut buf = vec![0xAAu8; size];
            let mut t = rng.timestamp();
            let _ = serialize_request(&mut t, rng.next(), &mut buf);
        }
    }
}

/// The poll interval over every tolerance, and every accuracy.
///
/// Sweeping the full `u16` x `u16` product is 4.3 billion calls; sweeping each
/// axis in full against a spread of the other is 8 million, reaches both
/// refusals and every power-of-two answer, and runs in under a second.
#[test]
fn every_poll_interval_is_safe() {
    const SPREAD: [u16; 8] = [1, 2, 3, 32, 1000, 1024, 65534, 65535];

    for tolerance in 0..=u16::MAX {
        for accuracy in SPREAD {
            let _ = calculate_poll_interval(tolerance, accuracy);
        }
    }

    for accuracy in 0..=u16::MAX {
        for tolerance in SPREAD {
            let _ = calculate_poll_interval(tolerance, accuracy);
        }
    }
}

/// Converting every interesting SNTP time to UNIX time.
#[test]
fn converting_any_timestamp_is_safe() {
    let mut rng = Lcg::new(4);

    for _ in 0..100_000 {
        let t = rng.timestamp();
        let _ = convert_to_unix_time(&t);
    }

    // And the era boundary from both sides, exhaustively over a window.
    for delta in 0..1000u32 {
        let base = 2_208_988_800u32;
        let _ = convert_to_unix_time(&Timestamp::new(base.wrapping_sub(delta), u32::MAX));
        let _ = convert_to_unix_time(&Timestamp::new(base.wrapping_add(delta), u32::MAX));
    }
}

/// A request we serialize is a request we can validate the answer to.
///
/// This is the one property that spans both entry points, and it is the one a
/// real client depends on: `serialize_request` MUTATES the timestamp it is
/// given, and a server echoes that mutated value back. A client that remembered
/// the value it passed in, rather than the value it got back, would reject
/// every genuine response — and would pass every test that exercised the two
/// functions separately.
#[test]
fn a_serialized_request_round_trips_through_its_own_response() {
    let mut rng = Lcg::new(5);

    for _ in 0..2_000 {
        let mut request = Timestamp::new(rng.next() | 1, rng.next());
        let random = rng.next();

        let mut buf = [0u8; PACKET_BASE_SIZE];
        serialize_request(&mut request, random, &mut buf).expect("a non-zero timestamp");

        // The server copies our transmit timestamp into its originate field,
        // which is exactly bytes 40..48 of the request landing at 24..32.
        let mut response = [0u8; PACKET_BASE_SIZE];
        response[0] = 0x24;
        response[1] = 1;
        response[24..32].copy_from_slice(&buf[40..48]);
        response[32..36].copy_from_slice(&request.seconds.wrapping_add(1).to_be_bytes());
        response[36..40].copy_from_slice(&1u32.to_be_bytes());
        response[40..44].copy_from_slice(&request.seconds.wrapping_add(2).to_be_bytes());
        response[44..48].copy_from_slice(&1u32.to_be_bytes());

        let rx = Timestamp::new(request.seconds.wrapping_add(3), 0);

        match deserialize_response(&request, &rx, &response) {
            Ok(Verdict::Accepted(_)) => {}
            other => panic!("a response to our own request was refused: {other:?}"),
        }
    }
}
