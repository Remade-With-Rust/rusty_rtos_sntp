#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! `rusty_rtos_sntp-core` — the pure heart of `rusty_rtos_sntp`.
//!
//! Rules this crate lives by (from the Kairos mission plan):
//!
//! 1. `no_std` by default; `alloc` is a feature, never an assumption.
//! 2. No CPU, no registers, no allocator, no operating system. Ports and
//!    backends are separate WRAP crates.
//! 3. Every type that crosses to another Kairos package comes from
//!    `rusty_rtos_core`, so packages compose without conversions.
//! 4. Handles are indices, never pointers; nothing on a hot path allocates.
//! 5. `forbid(unsafe)`. The C kernel's trace is the oracle; the scalar path
//!    is the oracle; any faster path is gated identical against it.

#[cfg(feature = "alloc")]
extern crate alloc;

pub use rusty_rtos_core as rtos_core;

/// The names a firmware wants in scope.
pub mod prelude {
    pub use rusty_rtos_core::prelude::*;
}

/// Crate version, for manifests and logs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The types that cross the SNTP surface.
pub mod types;

/// `core_sntp_serializer.c`: the SNTPv4 packet codec and its arithmetic.
pub mod serializer;

/// `core_sntp_client.c`: the polling client over a UDP transport.
pub mod client;

pub use client::{
    AuthError, Authenticator, Client, InitError, NetworkError, NoAuth, ReceiveError, Reception,
    SendError, ServerInfo, SntpHost,
};
pub use serializer::{
    FRACTION_VALUE_PER_MICROSECOND, KISS_OF_DEATH_CODE_LENGTH, PACKET_BASE_SIZE,
    TIME_AT_UNIX_EPOCH_SECS, UNIX_TIME_SECS_AT_SNTP_ERA_1_SMALLEST_TIME, calculate_poll_interval,
    convert_to_unix_time, deserialize_response, serialize_request,
};
pub use types::{
    Accepted, DeserializeError, LeapSecond, PollIntervalError, Rejected, Rejection, SerializeError,
    Timestamp, Verdict,
};
