#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! `rusty_rtos_sntp` — coreSNTP remade in Rust.
//!
//! **What is here:** `core_sntp_serializer.c` — the SNTPv4 packet codec, the
//! response validation, the clock-offset arithmetic across the 2036 era wrap,
//! the poll-interval calculation and the UNIX time conversion. Every one of
//! them diffed against the C, call for call.
//!
//! **What is not:** `core_sntp_client.c`, the state machine that drives a UDP
//! transport and an authentication interface. It needs a seam this package does
//! not have yet, and this crate does not pretend otherwise.
//!
//! Integer arithmetic throughout, because coreSNTP targets parts with no
//! floating-point unit. Zero allocation, `no_std`, `forbid(unsafe)`.
//!
//! This is the facade: it re-exports the `no_std` core. Depend on this crate;
//! reach into the sub-crates only when you are building a port or a backend.
//!
//! Part of Kairos (Remade With Rust). Plan: `docs/plans/rusty_rtos_sntp.md`.

pub use rusty_rtos_sntp_core::*;

/// The names a firmware wants in scope.
pub mod prelude {
    pub use rusty_rtos_sntp_core::prelude::*;
}
