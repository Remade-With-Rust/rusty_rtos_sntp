//! The types that cross the SNTP surface.
//!
//! The C has one `SntpStatus_t` with seventeen variants covering the
//! serializer, the client and the user-supplied interfaces, and each function's
//! documentation names the subset it can actually return. Here each function
//! gets an error type that holds only the subset it can produce, so the
//! impossible variant is not there to be matched on. That is the same choice
//! `rusty_rtos_json` made for its validator and its query engine, and the
//! reason is the same: a caller should not have to read the documentation to
//! learn which arms are dead.

/// An SNTP timestamp: seconds and fractions since 1 January 1900 UTC.
///
/// The fractions field divides one second into 2^32 parts, about 232
/// picoseconds each. The seconds field is 32 bits, so it wraps on 7 February
/// 2036 — see [`safe_time_difference`](crate::serializer) for what that costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timestamp {
    /// Seconds since the SNTP epoch.
    pub seconds: u32,
    /// Fractions of a second, at 2^-32 resolution.
    pub fractions: u32,
}

impl Timestamp {
    /// A timestamp from its two halves.
    #[must_use]
    pub const fn new(seconds: u32, fractions: u32) -> Self {
        Self { seconds, fractions }
    }

    /// Is this the zero timestamp?
    ///
    /// SNTP treats zero as invalid rather than as a time, and the library
    /// refuses it in both directions. That is not tidiness: a client which
    /// clears its stored request time after a reply would otherwise accept a
    /// forged response whose originate field was zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.seconds == 0 && self.fractions == 0
    }
}

/// `SntpLeapSecondInfo_t`: what the server says about the coming month.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeapSecond {
    /// No adjustment is coming.
    None,
    /// A second will be inserted before midnight on the last day of the month.
    LastMinuteHas61Seconds,
    /// A second will be deleted from that minute.
    LastMinuteHas59Seconds,
    /// An alarm: the server itself is not synchronised to an upstream clock.
    ///
    /// Its time should not be trusted, which is a thing to check rather than a
    /// thing to assume — the response is otherwise perfectly well-formed.
    AlarmServerNotSynchronized,
}

/// Why a server refused to give the time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// `DENY` or `RSTR`: do not come back. Use a different server.
    ChangeServer,
    /// `RATE`: you are asking too often. Back off, then retry.
    ///
    /// This is what [`rusty_rtos_backoff`](https://crates.io/crates/rusty_rtos_backoff)
    /// is for, and the pairing is the reason that package was built first.
    RetryWithBackoff,
    /// A code outside the three the specification names. The four ASCII
    /// characters are in [`Rejected::code`]; what they mean is the server's
    /// business.
    Other,
}

/// A Kiss-o'-Death: the server answered, and the answer was no.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejected {
    /// The four ASCII characters, big-endian, as the packet carried them.
    pub code: u32,
    /// What the client should do about it.
    pub kind: Rejection,
}

impl Rejected {
    /// The kiss code as the four ASCII bytes a human would read.
    #[must_use]
    pub const fn code_bytes(&self) -> [u8; 4] {
        self.code.to_be_bytes()
    }
}

/// A server response that carried a usable time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    /// The server's own time: the packet's **transmit** timestamp.
    pub server_time: Timestamp,
    /// Whether a leap second is coming, and whether to trust this at all.
    pub leap_second: LeapSecond,
    /// How far the local clock is behind the server, in milliseconds.
    ///
    /// Positive means the server is ahead. Computed from all four timestamps
    /// of the round trip, so a symmetric network delay cancels.
    pub clock_offset_ms: i64,
}

/// What a well-formed response turned out to say.
///
/// A Kiss-o'-Death is a **valid** response that refuses, so it is a verdict and
/// not an error. Only a malformed or unauthentic packet is an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The server gave the time.
    Accepted(Accepted),
    /// The server refused, politely and in the protocol.
    Rejected(Rejected),
}

/// Why a request could not be serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializeError {
    /// The request timestamp was zero, which SNTP does not allow.
    BadParameter,
    /// The buffer was smaller than
    /// [`PACKET_BASE_SIZE`](crate::serializer::PACKET_BASE_SIZE).
    BufferTooSmall,
}

/// Why a response could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeserializeError {
    /// The request timestamp passed in was zero.
    BadParameter,
    /// The buffer was smaller than
    /// [`PACKET_BASE_SIZE`](crate::serializer::PACKET_BASE_SIZE).
    BufferTooSmall,
    /// The packet failed validation: not from a server, a zero timestamp, or
    /// an originate field that does not echo the request.
    InvalidResponse,
}

/// Why a poll interval could not be calculated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollIntervalError {
    /// The clock tolerance or the desired accuracy was zero.
    BadParameter,
    /// The interval needed is under one second, which this cannot express.
    ///
    /// Asking an SNTP server more than once a second is not a poll interval
    /// problem; it is a different design.
    ZeroPollInterval,
}
