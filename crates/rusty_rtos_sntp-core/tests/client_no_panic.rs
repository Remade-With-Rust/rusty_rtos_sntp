//! K7's no-panic and liveness gate for the SNTP client.
//!
//! The serializer's gate next door feeds it bytes. This feeds it a **hostile
//! host**: a transport that lies about how much it moved, a clock that jumps
//! backwards and forwards, a DNS that answers differently every time. All of
//! those are things a real system does — a transport under memory pressure, a
//! clock being disciplined by this very library, a name server behind a pool.
//!
//! # Liveness, not only safety
//!
//! Both of the client's loops retry until a deadline computed from the host's
//! own clock. A loop like that does not panic when it goes wrong; it **spins**,
//! and a spinning test is reported as "still running" rather than as a failure.
//! So the gate bounds the number of host calls and asserts the loops finish
//! within it — the same shape `rusty_rtos_json`'s iterator needed, for the same
//! reason.
//!
//! The one thing deliberately NOT asserted is termination under a clock that
//! does not make progress, because there is none. Both loops exit only when a
//! deadline computed from the host's clock is met, so a stopped or oscillating
//! clock makes them spin for ever -- in this arm and in the C. **The block time
//! is only as good as the clock**, which is not documented upstream and on a
//! device is a hung task rather than a late one. It is recorded in
//! `kairos-upstream/drafts/coresntp-elapsed-time-underflow.md` and stated here
//! rather than tested, because a test for it could only hang.
//!
//! This gate found that by hanging. The bound is now enforced from INSIDE the
//! host, so the next one fails by name instead.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use rusty_rtos_sntp_core::{
    AuthError, Authenticator, Client, LeapSecond, NetworkError, PACKET_BASE_SIZE, Reception,
    ServerInfo, SntpHost, Timestamp,
};

struct Lcg(u32);

impl Lcg {
    const fn new(seed: u32) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        self.0
    }
}

/// A host that answers every call from a pseudo-random stream, and counts them.
///
/// `budget` is the liveness bound: once the client has made this many calls the
/// host starts advancing the clock hard, so a loop that is making progress
/// finishes and one that is not is caught by the assertion at the call site.
struct HostileHost {
    rng: Lcg,
    calls: usize,
    budget: usize,
    clock: Timestamp,
    advance: bool,
}

impl HostileHost {
    fn new(seed: u32, budget: usize, advance: bool) -> Self {
        Self {
            rng: Lcg::new(seed),
            calls: 0,
            budget,
            clock: Timestamp::new(1000, 0),
            advance,
        }
    }

    fn tick(&mut self) {
        self.calls += 1;

        // The bound is enforced HERE, not after the call returns. A retry loop
        // that never returns never reaches an assertion placed after it -- it
        // hangs, and a hang is reported as "still running" rather than as a
        // failure. Panicking from inside the host turns a spin into a named
        // test failure with a count attached.
        assert!(
            self.calls < 200_000,
            "the client made {} host calls without returning -- a retry loop is \
             not making progress",
            self.calls
        );

        if self.advance || self.calls > self.budget {
            // Past the budget the clock leaps, so any deadline is met and a
            // loop that is checking one must stop.
            self.clock = Timestamp::new(
                self.clock
                    .seconds
                    .wrapping_add(if self.calls > self.budget { 1000 } else { 1 }),
                self.rng.next(),
            );
        }
    }
}

impl SntpHost for HostileHost {
    fn resolve_dns(&mut self, _server: &ServerInfo<'_>) -> Option<u32> {
        self.tick();
        if self.rng.next() % 8 == 0 {
            None
        } else {
            Some(self.rng.next())
        }
    }

    fn now(&mut self) -> Timestamp {
        self.tick();
        self.clock
    }

    fn adjust_clock(
        &mut self,
        _server: &ServerInfo<'_>,
        _server_time: Timestamp,
        _offset_ms: i64,
        _leap_second: LeapSecond,
    ) {
        self.tick();
    }

    fn send_to(&mut self, _address: u32, _port: u16, buffer: &[u8]) -> Result<usize, NetworkError> {
        self.tick();
        match self.rng.next() % 5 {
            0 => Err(NetworkError),
            1 => Ok(0),
            // A transport that claims MORE than it was given. The library must
            // treat it as a failure, not index with it.
            2 => Ok(buffer.len().saturating_add(9999)),
            3 => Ok(buffer.len() / 2),
            _ => Ok(buffer.len()),
        }
    }

    fn recv_from(
        &mut self,
        _address: u32,
        _port: u16,
        buffer: &mut [u8],
    ) -> Result<usize, NetworkError> {
        self.tick();
        for b in buffer.iter_mut() {
            *b = (self.rng.next() >> 16) as u8;
        }
        match self.rng.next() % 5 {
            0 => Err(NetworkError),
            1 => Ok(0),
            2 => Ok(buffer.len().saturating_add(9999)),
            3 => Ok(buffer.len().saturating_sub(1)),
            _ => Ok(buffer.len()),
        }
    }
}

/// An authenticator that answers at random, including with sizes that cannot fit.
struct HostileAuth(Lcg);

impl Authenticator for HostileAuth {
    fn generate_client_auth(
        &mut self,
        _server: &ServerInfo<'_>,
        buffer: &mut [u8],
    ) -> Result<u16, AuthError> {
        match self.0.next() % 4 {
            0 => Err(AuthError::Failed),
            // A size larger than the buffer, which the library must refuse
            // rather than use as a length.
            1 => Ok(u16::MAX),
            2 => Ok((buffer.len().saturating_sub(PACKET_BASE_SIZE)) as u16),
            _ => Ok(8),
        }
    }

    fn validate_server_auth(
        &mut self,
        _server: &ServerInfo<'_>,
        _packet: &[u8],
    ) -> Result<(), AuthError> {
        match self.0.next() % 3 {
            0 => Err(AuthError::Failed),
            1 => Err(AuthError::ServerNotAuthenticated),
            _ => Ok(()),
        }
    }
}

const SERVERS: [ServerInfo<'static>; 3] = [
    ServerInfo::new("a.pool"),
    ServerInfo::on_port("b.pool", 12345),
    ServerInfo::on_port("c.pool", 0),
];

/// A hostile host, driven for many rounds, must never panic and must always
/// return.
#[test]
fn a_hostile_host_never_panics_and_always_returns() {
    for seed in 1..40u32 {
        let mut buffer = [0u8; 96];
        let mut client = Client::new(&SERVERS, &mut buffer, 5_000).expect("a valid client");
        let mut host = HostileHost::new(seed, 64, true);

        for round in 0..40 {
            let _ = client.send_time_request(&mut host, seed.wrapping_mul(round + 1), 100);
            let _ = client.receive_time_response(&mut host, 100);

            assert!(
                host.calls < 100_000,
                "seed {seed} round {round}: the client made {} host calls — a \
                 retry loop is not making progress",
                host.calls
            );
        }
    }
}

/// The same, with authentication configured, which adds two more callbacks and
/// a size the library must bounds-check rather than trust.
#[test]
fn a_hostile_authenticator_never_panics() {
    for seed in 1..40u32 {
        let mut buffer = [0u8; 96];
        let mut client =
            Client::with_authenticator(&SERVERS, &mut buffer, 5_000, HostileAuth(Lcg::new(seed)))
                .expect("a valid client");
        let mut host = HostileHost::new(seed.wrapping_add(500), 64, true);

        for _ in 0..40 {
            let _ = client.send_time_request(&mut host, seed, 100);
            let _ = client.receive_time_response(&mut host, 100);

            assert!(host.calls < 100_000, "a retry loop is not making progress");
        }
    }
}

/// Every buffer size the library will accept, and several it will not.
#[test]
fn every_buffer_size_is_safe() {
    for size in 0..96usize {
        let mut buffer = vec![0u8; size];
        let built = Client::new(&SERVERS, &mut buffer, 1_000);

        let Ok(mut client) = built else {
            // Under the base packet size, refusing is the whole point.
            assert!(size < PACKET_BASE_SIZE);
            continue;
        };

        let mut host = HostileHost::new(size as u32 + 1, 64, true);
        let _ = client.send_time_request(&mut host, 7, 100);
        let _ = client.receive_time_response(&mut host, 100);
    }
}

/// A clock that runs backwards must not panic, and must finish **once the
/// clock starts making progress again**.
///
/// # What this test originally asserted, and why that was wrong
///
/// The first version required the call to return under a clock that oscillated
/// between two values half a second apart. It hung — and the C hangs too.
///
/// Both retry loops exit only when a deadline computed from the *host's own
/// clock* is met. Under an oscillating clock the elapsed time alternates
/// between 499 ms and 0 ms and never accumulates, so neither the block time nor
/// the response timeout is ever reached, and `Sntp_ReceiveTimeResponse` never
/// returns. **The block time is only as good as the clock.** That is a property
/// of any timeout expressed purely in terms of a caller-supplied clock, it is
/// not documented upstream, and on a device it is a hung task rather than a
/// late one. `kairos-upstream/drafts/coresntp-elapsed-time-underflow.md`
/// carries it.
///
/// So this asserts the honest thing: backwards is survivable, and progress
/// resumes when the clock does.
#[test]
fn a_clock_running_backwards_finishes_once_the_clock_recovers() {
    struct Backwards {
        clock: Timestamp,
        calls: usize,
    }

    impl SntpHost for Backwards {
        fn resolve_dns(&mut self, _s: &ServerInfo<'_>) -> Option<u32> {
            Some(0x0A00_0001)
        }
        fn now(&mut self) -> Timestamp {
            self.calls += 1;
            assert!(
                self.calls < 200_000,
                "the client made {} clock reads without returning",
                self.calls
            );

            self.clock = if self.calls <= 12 {
                // Half a second backwards on every reading, which is what a
                // step-adjusting host does after this library hands it a
                // negative offset.
                Timestamp::new(
                    self.clock.seconds,
                    self.clock.fractions.wrapping_sub(0x8000_0000),
                )
            } else {
                // The clock settles and moves forward again.
                Timestamp::new(self.clock.seconds.wrapping_add(10), 0)
            };
            self.clock
        }
        fn adjust_clock(&mut self, _: &ServerInfo<'_>, _: Timestamp, _: i64, _: LeapSecond) {}
        fn send_to(&mut self, _: u32, _: u16, b: &[u8]) -> Result<usize, NetworkError> {
            Ok(b.len())
        }
        fn recv_from(&mut self, _: u32, _: u16, _: &mut [u8]) -> Result<usize, NetworkError> {
            Ok(0)
        }
    }

    let mut buffer = [0u8; 48];
    let mut client = Client::new(&SERVERS, &mut buffer, 5_000).expect("a valid client");
    let mut host = Backwards {
        clock: Timestamp::new(1000, 0x8000_0000),
        calls: 0,
    };

    for _ in 0..50 {
        let _ = client.send_time_request(&mut host, 1, 1_000);
        let _ = client.receive_time_response(&mut host, 1_000);
    }
}

/// Rotation visits every server and wraps.
///
/// The C wraps deliberately: a long-running client that has exhausted its list
/// should return to the first server, because a device with no time at all is
/// worse than one asking a server that refused it an hour ago.
#[test]
fn rotation_visits_every_server_and_wraps() {
    struct Silent(usize);

    impl SntpHost for Silent {
        fn resolve_dns(&mut self, _s: &ServerInfo<'_>) -> Option<u32> {
            Some(0x0A00_0001)
        }
        fn now(&mut self) -> Timestamp {
            self.0 += 1;
            // Every reading is a second later, so the response timeout is
            // reached and the client rotates.
            Timestamp::new(1000 + self.0 as u32, 0)
        }
        fn adjust_clock(&mut self, _: &ServerInfo<'_>, _: Timestamp, _: i64, _: LeapSecond) {}
        fn send_to(&mut self, _: u32, _: u16, b: &[u8]) -> Result<usize, NetworkError> {
            Ok(b.len())
        }
        fn recv_from(&mut self, _: u32, _: u16, _: &mut [u8]) -> Result<usize, NetworkError> {
            Ok(0)
        }
    }

    let mut buffer = [0u8; 48];
    let mut client = Client::new(&SERVERS, &mut buffer, 1_000).expect("a valid client");
    let mut host = Silent(0);

    let mut visited = Vec::new();
    for _ in 0..7 {
        visited.push(client.current_server_index());
        client
            .send_time_request(&mut host, 1, 1_000)
            .expect("the transport always accepts");
        let r = client
            .receive_time_response(&mut host, 10_000)
            .expect("a timeout is not an error");
        assert_eq!(r, Reception::TimedOut);
    }

    assert_eq!(
        visited,
        vec![0, 1, 2, 0, 1, 2, 0],
        "rotation should walk the list and wrap, not stop at the end"
    );
}
