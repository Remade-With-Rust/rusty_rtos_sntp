//! `core_sntp_client.c` remade: the polling client over a UDP transport.
//!
//! The serializer next door is a pure function — bytes in, bytes out. This is a
//! **state machine over five callbacks**: resolve a name, read the clock, adjust
//! the clock, send a datagram, receive one. Its observable behaviour is not only
//! what it returns but which callbacks it calls, in what order, with what
//! arguments; the differential compares all of that.
//!
//! # The seam
//!
//! The C takes five function pointers and two opaque user contexts. Here that is
//! one trait, [`SntpHost`], because a single `&mut self` is the natural Rust
//! equivalent of "these five callbacks share state". Authentication stays
//! separate in [`Authenticator`], because it is optional in the C and the
//! difference between *configured* and *not configured* changes behaviour — see
//! [`Authenticator::CONFIGURED`].
//!
//! # A context that cannot be uninitialised
//!
//! The C's `validateContext` runs on every call and can return
//! `SntpErrorContextNotInitialized`, because a `SntpContext_t` is a struct the
//! caller allocates and might not have passed to `Sntp_Init`. [`Client::new`] is
//! the only way to obtain a `Client`, so that status has no Rust equivalent and
//! is not in any error type here. That is not a gap in the transcription; it is
//! the whole reason the type exists.

use crate::serializer::{PACKET_BASE_SIZE, deserialize_response, serialize_request};
use crate::types::{LeapSecond, Timestamp, Verdict};

/// `SNTP_FRACTION_VALUE_PER_MICROSECOND * 1000`: the divisor that turns the
/// fractions field into whole milliseconds.
const FRACTIONS_PER_MS: u64 = 4_295_000;

/// A time server: a name to resolve, and a port to reach it on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerInfo<'a> {
    /// The server's name, passed to [`SntpHost::resolve_dns`].
    pub name: &'a str,
    /// The UDP port, conventionally 123.
    pub port: u16,
}

impl<'a> ServerInfo<'a> {
    /// A server on the standard SNTP port.
    #[must_use]
    pub const fn new(name: &'a str) -> Self {
        Self { name, port: 123 }
    }

    /// A server on a specific port.
    #[must_use]
    pub const fn on_port(name: &'a str, port: u16) -> Self {
        Self { name, port }
    }
}

/// Something went wrong in the transport itself.
///
/// This is the C's "negative return value" from `sendTo` or `recvFrom`. A
/// transport that simply has nothing to report returns `Ok(0)` instead, which
/// is not an error and is what the retry loops are built around.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkError;

/// Everything the client needs from the system it runs on.
///
/// The C splits this into `SntpResolveDns_t`, `SntpGetTime_t`, `SntpSetTime_t`
/// and a `UdpTransportInterface_t`, each with its own opaque user context. One
/// trait with `&mut self` says the same thing and lets an implementation share
/// state between them without a void pointer.
pub trait SntpHost {
    /// Resolve a server's name to an IPv4 address, or `None` on failure.
    ///
    /// The C calls this on **every** `Sntp_SendTimeRequest`, deliberately: a
    /// long-running client should follow a pool's DNS rotation rather than pin
    /// the first address it ever saw.
    fn resolve_dns(&mut self, server: &ServerInfo<'_>) -> Option<u32>;

    /// The current system time, as an SNTP timestamp.
    fn now(&mut self) -> Timestamp;

    /// Apply a measured correction to the system clock.
    ///
    /// `offset_ms` is how far this clock is behind the server. Whether to step
    /// or slew is the implementation's business; the library only measures.
    fn adjust_clock(
        &mut self,
        server: &ServerInfo<'_>,
        server_time: Timestamp,
        offset_ms: i64,
        leap_second: LeapSecond,
    );

    /// Send a datagram. `Ok(0)` means nothing moved and a retry is reasonable.
    ///
    /// # Errors
    ///
    /// [`NetworkError`] if the transport failed. A partial send is reported as
    /// `Ok(n)` and the library treats it as a failure, because UDP has no such
    /// thing as a partial datagram.
    fn send_to(&mut self, address: u32, port: u16, buffer: &[u8]) -> Result<usize, NetworkError>;

    /// Receive a datagram. `Ok(0)` means nothing was waiting.
    ///
    /// # Errors
    ///
    /// [`NetworkError`] if the transport failed.
    fn recv_from(
        &mut self,
        address: u32,
        port: u16,
        buffer: &mut [u8],
    ) -> Result<usize, NetworkError>;
}

/// Why an authentication callback refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// The mechanism itself failed: `SntpErrorAuthFailure`.
    Failed,
    /// The server is not who it claims to be: `SntpServerNotAuthenticated`.
    ///
    /// Only [`Authenticator::validate_server_auth`] can answer this.
    ServerNotAuthenticated,
}

/// Symmetric-key or NTS-style authentication, if the deployment uses it.
///
/// Implement this to add a client authentication code to each request and to
/// check the server's. Most deployments do not, and use [`NoAuth`].
pub trait Authenticator {
    /// Whether this is a real authenticator.
    ///
    /// [`NoAuth`] sets it `false`, which is the C's "the interface pointer is
    /// NULL". It is not cosmetic: on a Kiss-o'-Death the client clears its
    /// stored request timestamp **only** when authentication is configured.
    /// See [`Client::receive_time_response`] for why.
    const CONFIGURED: bool = true;

    /// Append a client authentication code after the 48-byte packet, and
    /// return its size in bytes.
    ///
    /// # Errors
    ///
    /// [`AuthError::Failed`] if the code could not be generated.
    fn generate_client_auth(
        &mut self,
        server: &ServerInfo<'_>,
        buffer: &mut [u8],
    ) -> Result<u16, AuthError>;

    /// Check the authentication data in a server's response.
    ///
    /// # Errors
    ///
    /// [`AuthError::ServerNotAuthenticated`] if the server failed the check,
    /// or [`AuthError::Failed`] if the mechanism itself failed.
    fn validate_server_auth(
        &mut self,
        server: &ServerInfo<'_>,
        packet: &[u8],
    ) -> Result<(), AuthError>;
}

/// No authentication, which is what most SNTP deployments use.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAuth;

impl Authenticator for NoAuth {
    const CONFIGURED: bool = false;

    fn generate_client_auth(
        &mut self,
        _server: &ServerInfo<'_>,
        _buffer: &mut [u8],
    ) -> Result<u16, AuthError> {
        Ok(0)
    }

    fn validate_server_auth(
        &mut self,
        _server: &ServerInfo<'_>,
        _packet: &[u8],
    ) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Why a client could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    /// The server list was empty.
    NoServers,
    /// The network buffer was smaller than [`PACKET_BASE_SIZE`].
    BufferTooSmall,
}

/// Why a time request could not be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The server's name could not be resolved.
    Dns,
    /// The transport failed, or reported a partial send, which UDP cannot do.
    Network,
    /// Nothing could be sent within the block time.
    SendTimeout,
    /// The authentication interface refused, or returned a code too large for
    /// the space left in the buffer.
    Auth,
}

/// What happened while waiting for a response.
///
/// Three of these are the protocol working as designed, so they are not errors.
/// A caller loops on [`Reception::NothingYet`] and sends a fresh request after
/// either of the other two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reception {
    /// A server answered with time and the clock was adjusted.
    Synchronised,
    /// Nothing arrived within the block time. The response timeout has not
    /// expired, so calling again is the right move.
    NothingYet,
    /// The server sent a Kiss-o'-Death. **The client has already rotated** to
    /// the next configured server.
    Rejected,
    /// The response timeout expired. **The client has already rotated.**
    TimedOut,
}

/// Why a response could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveError {
    /// The transport failed, or reported a partial read, which UDP cannot do.
    Network,
    /// The packet failed validation: not from a server, a zero timestamp, or an
    /// originate field that does not echo the request.
    InvalidResponse,
    /// The authentication mechanism itself failed.
    Auth,
    /// The server failed authentication.
    ServerNotAuthenticated,
}

/// `calculateElapsedTimeMs`: milliseconds from `older` to `current`.
///
/// # This reproduces a defect in the C, on purpose
///
/// The seconds difference handles the 2036 wrap correctly. The **fractions**
/// half does not: when `current` has smaller fractions than `older` the C
/// subtracts, on a `uint64_t`, from a total that may still be zero.
///
/// A clock that moves backwards by less than a second therefore produces
/// roughly 1.8 × 10¹⁹ milliseconds instead of a small number, and every caller
/// here compares that against a timeout — so the client concludes its request
/// timed out. That is not hypothetical: adjusting a clock backwards is
/// precisely what this library asks its host to do via
/// [`SntpHost::adjust_clock`].
///
/// It is transcribed exactly, because a differential that "fixes" the oracle is
/// measuring two different libraries. `docs/upstream/` carries the issue draft.
const fn calculate_elapsed_ms(current: &Timestamp, older: &Timestamp) -> u64 {
    let seconds = if current.seconds < older.seconds {
        // The wrap: time left in era 0, plus the era-1 epoch itself, plus the
        // time already spent in era 1. The branch guarantees no borrow.
        (u32::MAX.wrapping_sub(older.seconds) as u64)
            .wrapping_add(1)
            .wrapping_add(current.seconds as u64)
    } else {
        current.seconds.wrapping_sub(older.seconds) as u64
    };

    let millis = seconds.wrapping_mul(1000);

    if current.fractions > older.fractions {
        millis.wrapping_add(
            (current.fractions as u64).wrapping_sub(older.fractions as u64) / FRACTIONS_PER_MS,
        )
    } else {
        // The C's `-=`, wrap and all. See the note above.
        millis.wrapping_sub(
            (older.fractions as u64).wrapping_sub(current.fractions as u64) / FRACTIONS_PER_MS,
        )
    }
}

/// A long-running SNTP client: one server at a time, rotating on refusal.
///
/// Built once with [`Client::new`], then driven by alternating
/// [`send_time_request`](Client::send_time_request) and
/// [`receive_time_response`](Client::receive_time_response). Both take the host
/// as an argument rather than owning it, so the same host can serve several
/// clients and a test can drive one with a script.
#[derive(Debug)]
pub struct Client<'a, A: Authenticator = NoAuth> {
    servers: &'a [ServerInfo<'a>],
    buffer: &'a mut [u8],
    current_server: usize,
    current_server_addr: u32,
    last_request_time: Timestamp,
    packet_size: u16,
    response_timeout_ms: u32,
    auth: A,
}

impl<'a> Client<'a, NoAuth> {
    /// A client with no authentication, which is the usual case.
    ///
    /// # Errors
    ///
    /// [`InitError::NoServers`] for an empty list, and
    /// [`InitError::BufferTooSmall`] for a buffer under [`PACKET_BASE_SIZE`].
    pub fn new(
        servers: &'a [ServerInfo<'a>],
        buffer: &'a mut [u8],
        response_timeout_ms: u32,
    ) -> Result<Self, InitError> {
        Self::with_authenticator(servers, buffer, response_timeout_ms, NoAuth)
    }
}

impl<'a, A: Authenticator> Client<'a, A> {
    /// A client that authenticates its requests and its servers.
    ///
    /// # Errors
    ///
    /// As [`Client::new`].
    pub fn with_authenticator(
        servers: &'a [ServerInfo<'a>],
        buffer: &'a mut [u8],
        response_timeout_ms: u32,
        auth: A,
    ) -> Result<Self, InitError> {
        if servers.is_empty() {
            return Err(InitError::NoServers);
        }

        if buffer.len() < PACKET_BASE_SIZE {
            return Err(InitError::BufferTooSmall);
        }

        Ok(Self {
            servers,
            buffer,
            current_server: 0,
            current_server_addr: 0,
            last_request_time: Timestamp::new(0, 0),
            packet_size: PACKET_BASE_SIZE as u16,
            response_timeout_ms,
            auth,
        })
    }

    /// The server the next request will go to.
    ///
    /// The index is always in range -- the list cannot be empty (checked at
    /// construction) and rotation takes it modulo the length -- so the
    /// fallback below is unreachable. It exists because the alternative is
    /// indexing, and a library that must not panic does not index.
    #[must_use]
    pub fn current_server(&self) -> &ServerInfo<'a> {
        static NO_SERVER: ServerInfo<'static> = ServerInfo { name: "", port: 0 };
        self.servers.get(self.current_server).unwrap_or(&NO_SERVER)
    }

    /// The index of the server in use, which changes as the client rotates.
    #[must_use]
    pub const fn current_server_index(&self) -> usize {
        self.current_server
    }

    /// The timestamp of the last request, which a server must echo back.
    ///
    /// Zero means there is no request outstanding — the client clears it after
    /// a response it could use, so a replay of the same request cannot be
    /// serviced twice.
    #[must_use]
    pub const fn last_request_time(&self) -> Timestamp {
        self.last_request_time
    }

    /// The size of the packets being exchanged: 48, plus any authentication
    /// data the last request carried.
    #[must_use]
    pub const fn packet_size(&self) -> u16 {
        self.packet_size
    }

    /// The resolved address of the server in use.
    #[must_use]
    pub const fn current_server_address(&self) -> u32 {
        self.current_server_addr
    }

    /// `rotateServerForNextTimeQuery`.
    ///
    /// Wraps around rather than running out: a long-running client that has
    /// exhausted its server list should go back to the first one, because a
    /// device with no time at all is worse than a device asking a server that
    /// refused it an hour ago.
    fn rotate_server(&mut self) {
        let next = self
            .current_server
            .saturating_add(1)
            .checked_rem(self.servers.len())
            .unwrap_or(0);
        self.current_server = next;
    }

    /// `Sntp_SendTimeRequest`: resolve, serialize, authenticate, send.
    ///
    /// `random_number` is the caller's, as in the C: its top 16 bits go into
    /// the low bits of the request's fractions so a response cannot be
    /// predicted and replayed. `block_time_ms` bounds the retrying of a
    /// transport that keeps reporting that it sent nothing.
    ///
    /// # Errors
    ///
    /// See [`SendError`].
    pub fn send_time_request<H: SntpHost>(
        &mut self,
        host: &mut H,
        random_number: u32,
        block_time_ms: u32,
    ) -> Result<(), SendError> {
        let Some(server) = self.servers.get(self.current_server).copied() else {
            return Err(SendError::Dns);
        };

        // Resolved on every request, not cached: a pool's DNS rotation is how
        // load is spread, and a client that pins one address defeats it.
        let Some(address) = host.resolve_dns(&server) else {
            return Err(SendError::Dns);
        };
        self.current_server_addr = address;

        self.last_request_time = host.now();

        // The context was validated at construction, so the only way this can
        // fail is a zero clock reading -- which the C asserts against and we
        // report, because an assert is not available to a library that must
        // not panic.
        if serialize_request(&mut self.last_request_time, random_number, self.buffer).is_err() {
            return Err(SendError::Network);
        }

        // The packet size is deliberately NOT reset here. The C assigns it
        // only in addClientAuthentication, so a FAILED generation leaves the
        // previous request's size in place -- and the next response is then
        // read at that size. Resetting it first looks tidier and is a
        // different library; a scenario with two authenticated requests, the
        // second failing, is what caught it.
        if A::CONFIGURED {
            let auth_size = self
                .auth
                .generate_client_auth(&server, self.buffer)
                .map_err(|_| SendError::Auth)?;

            // The code must fit in what is left after the 48-byte packet.
            let spare = self.buffer.len().saturating_sub(PACKET_BASE_SIZE);
            if usize::from(auth_size) > spare {
                return Err(SendError::Auth);
            }

            self.packet_size = (PACKET_BASE_SIZE as u16).saturating_add(auth_size);
        }

        self.send_packet(host, address, server.port, block_time_ms)
    }

    /// `sendSntpPacket`: send it all, retrying a transport that moves nothing.
    fn send_packet<H: SntpHost>(
        &mut self,
        host: &mut H,
        address: u32,
        port: u16,
        block_time_ms: u32,
    ) -> Result<(), SendError> {
        let size = usize::from(self.packet_size);

        // The retry window opens here, before the first attempt.
        let started = host.now();

        loop {
            let Some(packet) = self.buffer.get(..size) else {
                return Err(SendError::Network);
            };

            match host.send_to(address, port, packet) {
                Err(NetworkError) => return Err(SendError::Network),
                Ok(0) => {
                    let now = host.now();
                    if calculate_elapsed_ms(&now, &started) >= u64::from(block_time_ms) {
                        return Err(SendError::SendTimeout);
                    }
                    // Otherwise go round again.
                }
                // UDP has no partial datagram, so anything else is a failure.
                Ok(sent) if sent != size => return Err(SendError::Network),
                Ok(_) => return Ok(()),
            }
        }
    }

    /// `Sntp_ReceiveTimeResponse`: read, validate, and adjust the clock.
    ///
    /// Retries the read until either the block time expires (giving
    /// [`Reception::NothingYet`]) or the response timeout does (giving
    /// [`Reception::TimedOut`], after rotating the server).
    ///
    /// # The block time is only as good as the clock
    ///
    /// Both deadlines are measured with [`SntpHost::now`], so a clock that does
    /// not make progress past one of them means this **never returns**. A
    /// stopped clock is the obvious case; an oscillating one is the realistic
    /// one, because a host that steps the clock backwards on a negative offset
    /// can produce readings that alternate rather than advance.
    ///
    /// The C behaves identically and does not document it. If your clock can
    /// misbehave, give the caller its own escape — a task watchdog, or a clock
    /// implementation that refuses to go backwards. See
    /// `kairos-upstream/drafts/coresntp-elapsed-time-underflow.md`.
    ///
    /// # The replay-protection asymmetry
    ///
    /// After a response the client can use, it clears its stored request
    /// timestamp, so a replayed request's later response cannot be serviced.
    /// After a **Kiss-o'-Death** it clears it only when authentication is
    /// configured — because without authentication anyone can forge a
    /// rejection, and clearing on a forged one would make the real response
    /// fail its originate check. That would turn a spoofed packet into a denial
    /// of service, so the C deliberately keeps the timestamp. It is one `if`,
    /// and it is the most security-relevant line in the file.
    ///
    /// # Errors
    ///
    /// See [`ReceiveError`].
    pub fn receive_time_response<H: SntpHost>(
        &mut self,
        host: &mut H,
        block_time_ms: u32,
    ) -> Result<Reception, ReceiveError> {
        let Some(server) = self.servers.get(self.current_server).copied() else {
            return Err(ReceiveError::Network);
        };

        let size = usize::from(self.packet_size);
        let address = self.current_server_addr;

        // The base for the block-time window, taken before the first read.
        let started = host.now();

        loop {
            let read = {
                let Some(packet) = self.buffer.get_mut(..size) else {
                    return Err(ReceiveError::Network);
                };
                host.recv_from(address, server.port, packet)
            };

            match read {
                Err(NetworkError) => return Err(ReceiveError::Network),
                Ok(n) if n == size => {
                    let received_at = host.now();
                    return self.process_response(host, &server, received_at);
                }
                Ok(0) => {
                    let now = host.now();
                    let since_request = calculate_elapsed_ms(&now, &self.last_request_time);
                    let in_this_call = calculate_elapsed_ms(&now, &started);

                    if since_request >= u64::from(self.response_timeout_ms) {
                        self.rotate_server();
                        return Ok(Reception::TimedOut);
                    }

                    if in_this_call >= u64::from(block_time_ms) {
                        return Ok(Reception::NothingYet);
                    }
                    // Otherwise read again.
                }
                // A partial read, which UDP cannot produce honestly.
                Ok(_) => return Err(ReceiveError::Network),
            }
        }
    }

    /// `processServerResponse`.
    fn process_response<H: SntpHost>(
        &mut self,
        host: &mut H,
        server: &ServerInfo<'a>,
        received_at: Timestamp,
    ) -> Result<Reception, ReceiveError> {
        let size = usize::from(self.packet_size);

        if A::CONFIGURED {
            let Some(packet) = self.buffer.get(..size) else {
                return Err(ReceiveError::Network);
            };
            match self.auth.validate_server_auth(server, packet) {
                Ok(()) => {}
                Err(AuthError::Failed) => return Err(ReceiveError::Auth),
                Err(AuthError::ServerNotAuthenticated) => {
                    return Err(ReceiveError::ServerNotAuthenticated);
                }
            }
        }

        let Some(packet) = self.buffer.get(..size) else {
            return Err(ReceiveError::Network);
        };

        let verdict = deserialize_response(&self.last_request_time, &received_at, packet);

        match verdict {
            Err(_) => Err(ReceiveError::InvalidResponse),
            Ok(Verdict::Rejected(_)) => {
                self.rotate_server();

                // See the note on `receive_time_response`: without
                // authentication the rejection may be forged, and forgetting
                // our request timestamp would make the genuine response fail
                // its originate check.
                if A::CONFIGURED {
                    self.last_request_time = Timestamp::new(0, 0);
                }

                Ok(Reception::Rejected)
            }
            Ok(Verdict::Accepted(accepted)) => {
                host.adjust_clock(
                    server,
                    accepted.server_time,
                    accepted.clock_offset_ms,
                    accepted.leap_second,
                );

                // A request that has been answered must not be answerable
                // again: a replayed request would otherwise be serviced by the
                // (stateless) server and accepted here a second time.
                self.last_request_time = Timestamp::new(0, 0);

                Ok(Reception::Synchronised)
            }
        }
    }
}
