//! The client against `core_sntp_client.c`, callback for callback.
//!
//! The C arm is `oracle/client_driver.c` driving `core_sntp_client.c` compiled
//! VERBATIM from the pinned checkout (v2.0.0 at `50f5f96`), and its trace is
//! checked in.
//!
//! # Why this differential compares more than return values
//!
//! The serializer is a pure function: give it bytes, compare bytes. The client
//! is a **state machine over five callbacks** — resolve a name, read the clock,
//! adjust the clock, send a datagram, receive one — and its observable
//! behaviour is not only what it returns but *which callbacks it calls, in what
//! order, with what arguments*. A transcription that produced the right status
//! while reading the clock a different number of times would be a different
//! library, and a differential that only checked statuses would bless it.
//!
//! So every callback is scripted and logged on both sides. Comparing those logs
//! is the differential; the return status is only its last line. The context
//! state is printed after every action too, because where a state machine
//! leaves itself is part of what it did.
//!
//! # The scenarios live in the trace
//!
//! Each begins with `cfg` lines holding the whole setup — servers, buffer size,
//! timeouts, every scripted return value, the actions to run — so this file
//! replays the workload rather than keeping a second copy of the driver's
//! tables. Two tables drift; one does not.

// A test asserts, indexes into a trace it parses, and builds probe values.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::cell::RefCell;
use std::fmt::Write as _;
use std::rc::Rc;

use rusty_rtos_sntp_core::{
    AuthError, Authenticator, Client, InitError, LeapSecond, NetworkError, ReceiveError, Reception,
    SendError, ServerInfo, SntpHost, Timestamp,
};

const TRACE: &str = include_str!("../../../oracle/client.trace");

/// The driver's buffer, which is the largest it will ever hand the library.
const MAX_BUFFER: usize = 96;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd-length hex: {text:?}");
    text.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn ts(text: &str) -> Timestamp {
    let (s, f) = text.split_once(':').expect("a seconds:fractions pair");
    Timestamp::new(
        u32::from_str_radix(s, 16).unwrap(),
        u32::from_str_radix(f, 16).unwrap(),
    )
}

const fn leap_name(l: LeapSecond) -> &'static str {
    match l {
        LeapSecond::None => "NoLeapSecond",
        LeapSecond::LastMinuteHas61Seconds => "Has61",
        LeapSecond::LastMinuteHas59Seconds => "Has59",
        LeapSecond::AlarmServerNotSynchronized => "Alarm",
    }
}

/// Everything a scenario scripts, plus the log both mocks append to.
///
/// The host and the authenticator are separate objects — the client owns one
/// and borrows the other — so the log they share lives behind an `Rc<RefCell>`.
/// The ORDER of their lines is the thing being compared, so they cannot each
/// keep their own.
#[derive(Default)]
struct Script {
    clock: Vec<Timestamp>,
    clock_at: usize,
    dns: Vec<(bool, u32)>,
    dns_at: usize,
    send_to: Vec<i32>,
    send_at: usize,
    recv: Vec<(i32, Vec<u8>)>,
    recv_at: usize,
    auth_gen: Vec<(String, u16)>,
    gen_at: usize,
    auth_val: Vec<String>,
    val_at: usize,
    log: String,
}

impl Script {
    /// A script that runs out means the scenario was not written for the number
    /// of calls the library actually makes. That is a defect in the WORKLOAD,
    /// and it stops the run rather than returning a default that would quietly
    /// diverge.
    fn exhausted(which: &str) -> ! {
        panic!("script exhausted: {which} — the scenario does not cover this many calls");
    }
}

type Shared = Rc<RefCell<Script>>;

struct ScriptHost(Shared);
struct ScriptAuth(Shared);

impl SntpHost for ScriptHost {
    fn resolve_dns(&mut self, server: &ServerInfo<'_>) -> Option<u32> {
        let mut s = self.0.borrow_mut();
        if s.dns_at >= s.dns.len() {
            Script::exhausted("dns");
        }
        let (ok, addr) = s.dns[s.dns_at];
        s.dns_at += 1;
        let _ = writeln!(
            s.log,
            "call dns {} -> {}:{addr:08x}",
            server.name,
            u8::from(ok)
        );
        if ok { Some(addr) } else { None }
    }

    fn now(&mut self) -> Timestamp {
        let mut s = self.0.borrow_mut();
        if s.clock_at >= s.clock.len() {
            Script::exhausted("clock");
        }
        let t = s.clock[s.clock_at];
        s.clock_at += 1;
        let _ = writeln!(
            s.log,
            "call getTime -> {:08x}:{:08x}",
            t.seconds, t.fractions
        );
        t
    }

    fn adjust_clock(
        &mut self,
        server: &ServerInfo<'_>,
        server_time: Timestamp,
        offset_ms: i64,
        leap_second: LeapSecond,
    ) {
        let mut s = self.0.borrow_mut();
        let _ = writeln!(
            s.log,
            "call setTime {} {:08x}:{:08x} {offset_ms} {}",
            server.name,
            server_time.seconds,
            server_time.fractions,
            leap_name(leap_second)
        );
    }

    fn send_to(&mut self, address: u32, port: u16, buffer: &[u8]) -> Result<usize, NetworkError> {
        let mut s = self.0.borrow_mut();
        if s.send_at >= s.send_to.len() {
            Script::exhausted("sendTo");
        }
        let ret = s.send_to[s.send_at];
        s.send_at += 1;
        let _ = writeln!(
            s.log,
            "call sendTo {address:08x} {port} {} {} -> {ret}",
            buffer.len(),
            hex(buffer)
        );
        if ret < 0 {
            Err(NetworkError)
        } else {
            Ok(ret as usize)
        }
    }

    fn recv_from(
        &mut self,
        address: u32,
        port: u16,
        buffer: &mut [u8],
    ) -> Result<usize, NetworkError> {
        let mut s = self.0.borrow_mut();
        if s.recv_at >= s.recv.len() {
            Script::exhausted("recvFrom");
        }
        let (ret, packet) = s.recv[s.recv_at].clone();
        s.recv_at += 1;

        // Only fill the buffer on a claimed FULL read: a transport that reports
        // nothing must not also be writing into the caller's buffer.
        if ret == buffer.len() as i32 {
            buffer.copy_from_slice(&packet[..buffer.len()]);
        }

        let _ = writeln!(
            s.log,
            "call recvFrom {address:08x} {port} {} -> {ret}",
            buffer.len()
        );
        if ret < 0 {
            Err(NetworkError)
        } else {
            Ok(ret as usize)
        }
    }
}

impl Authenticator for ScriptAuth {
    fn generate_client_auth(
        &mut self,
        server: &ServerInfo<'_>,
        buffer: &mut [u8],
    ) -> Result<u16, AuthError> {
        let mut s = self.0.borrow_mut();
        if s.gen_at >= s.auth_gen.len() {
            Script::exhausted("authGen");
        }
        let (status, size) = s.auth_gen[s.gen_at].clone();
        s.gen_at += 1;
        let _ = writeln!(
            s.log,
            "call authGen {} {} -> {status}:{size}",
            server.name,
            buffer.len()
        );
        if status == "Success" {
            Ok(size)
        } else {
            Err(AuthError::Failed)
        }
    }

    fn validate_server_auth(
        &mut self,
        server: &ServerInfo<'_>,
        packet: &[u8],
    ) -> Result<(), AuthError> {
        let mut s = self.0.borrow_mut();
        if s.val_at >= s.auth_val.len() {
            Script::exhausted("authVal");
        }
        let status = s.auth_val[s.val_at].clone();
        s.val_at += 1;
        let _ = writeln!(
            s.log,
            "call authVal {} {} -> {status}",
            server.name,
            packet.len()
        );
        match status.as_str() {
            "Success" => Ok(()),
            "ServerNotAuthenticated" => Err(AuthError::ServerNotAuthenticated),
            _ => Err(AuthError::Failed),
        }
    }
}

/// Generic over what was built, so both the authenticated and the plain
/// constructor can report through it.
fn init_status_of<T>(r: &Result<T, InitError>) -> &'static str {
    match r {
        Ok(_) => "Success",
        // The C answers BadParameter for an empty server list.
        Err(InitError::NoServers) => "BadParameter",
        Err(InitError::BufferTooSmall) => "BufferTooSmall",
    }
}

const fn send_status(r: &Result<(), SendError>) -> &'static str {
    match r {
        Ok(()) => "Success",
        Err(SendError::Dns) => "DnsFailure",
        Err(SendError::Network) => "NetworkFailure",
        Err(SendError::SendTimeout) => "SendTimeout",
        Err(SendError::Auth) => "AuthFailure",
    }
}

const fn receive_status(r: &Result<Reception, ReceiveError>) -> &'static str {
    match r {
        Ok(Reception::Synchronised) => "Success",
        Ok(Reception::NothingYet) => "NoResponseReceived",
        Ok(Reception::Rejected) => "RejectedResponse",
        Ok(Reception::TimedOut) => "ResponseTimeout",
        Err(ReceiveError::Network) => "NetworkFailure",
        Err(ReceiveError::InvalidResponse) => "InvalidResponse",
        Err(ReceiveError::Auth) => "AuthFailure",
        Err(ReceiveError::ServerNotAuthenticated) => "ServerNotAuthenticated",
    }
}

/// One scenario's configuration, as parsed from its `cfg` lines.
#[derive(Default)]
struct Config {
    servers: Vec<(String, u16)>,
    buffer: usize,
    timeout: u32,
    auth: bool,
    actions: Vec<(char, u32, u32)>,
}

/// Replay one scenario and append our side of its lines to `out`.
fn run_scenario(out: &mut String, cfg: &Config, script: Shared) {
    let servers: Vec<ServerInfo<'_>> = cfg
        .servers
        .iter()
        .map(|(name, port)| ServerInfo::on_port(name.as_str(), *port))
        .collect();

    let mut buffer = [0u8; MAX_BUFFER];
    let claimed = &mut buffer[..cfg.buffer.min(MAX_BUFFER)];

    // The two arms differ in shape here and nowhere else: the C builds one
    // context and passes a NULL auth interface, while this picks a type. Both
    // report the same status, which is what the trace compares.
    if cfg.auth {
        let built = Client::with_authenticator(
            &servers,
            claimed,
            cfg.timeout,
            ScriptAuth(Rc::clone(&script)),
        );
        let _ = writeln!(out, "init -> {}", init_status_of(&built));
        let Ok(mut client) = built else { return };
        drive(out, cfg, &mut client, script);
    } else {
        let built = Client::new(&servers, claimed, cfg.timeout);
        let _ = writeln!(out, "init -> {}", init_status_of(&built));
        let Ok(mut client) = built else { return };
        drive(out, cfg, &mut client, script);
    }
}

fn drive<A: Authenticator>(
    out: &mut String,
    cfg: &Config,
    client: &mut Client<'_, A>,
    script: Shared,
) {
    let mut host = ScriptHost(Rc::clone(&script));

    for (i, (kind, a, b)) in cfg.actions.iter().enumerate() {
        let status = if *kind == 's' {
            let r = client.send_time_request(&mut host, *a, *b);
            send_status(&r)
        } else {
            let r = client.receive_time_response(&mut host, *b);
            receive_status(&r)
        };

        // The mocks have been logging into the shared script; splice their
        // lines in before this action's result, which is where the C's
        // interleaved printf put them.
        {
            let mut s = script.borrow_mut();
            out.push_str(&s.log);
            s.log.clear();
        }

        let _ = writeln!(out, "action {i} {kind} -> {status}");

        let t = client.last_request_time();
        let _ = writeln!(
            out,
            "state {} {:08x}:{:08x} {} {:08x}",
            client.current_server_index(),
            t.seconds,
            t.fractions,
            client.packet_size(),
            client.current_server_address()
        );
    }
}

/// Build our whole side of the trace by replaying every scenario in it.
fn our_trace() -> String {
    let mut out = String::new();
    let mut lines = TRACE.lines();

    let geometry = lines.next().expect("a geometry line");
    let _ = writeln!(out, "{geometry}");

    let mut cfg = Config::default();
    let script: Shared = Rc::new(RefCell::new(Script::default()));

    for line in lines {
        let f: Vec<&str> = line.split_whitespace().collect();

        match f.first().copied() {
            Some("scenario") => {
                let _ = writeln!(out, "{line}");
                cfg = Config::default();
                *script.borrow_mut() = Script::default();
            }
            Some("cfg") => {
                let _ = writeln!(out, "{line}");
                let mut s = script.borrow_mut();
                match f[1] {
                    "servers" => {
                        cfg.servers = f[3..]
                            .iter()
                            .map(|e| {
                                let (n, p) = e.split_once(':').unwrap();
                                (n.to_owned(), p.parse().unwrap())
                            })
                            .collect();
                    }
                    "buffer" => cfg.buffer = f[2].parse().unwrap(),
                    "timeout" => cfg.timeout = f[2].parse().unwrap(),
                    "auth" => cfg.auth = f[2] == "yes",
                    "clock" => s.clock = f[3..].iter().map(|e| ts(e)).collect(),
                    "dns" => {
                        s.dns = f[3..]
                            .iter()
                            .map(|e| {
                                let (ok, addr) = e.split_once(':').unwrap();
                                (ok == "1", u32::from_str_radix(addr, 16).unwrap())
                            })
                            .collect();
                    }
                    "sendto" => s.send_to = f[3..].iter().map(|e| e.parse().unwrap()).collect(),
                    "recv" => {
                        s.recv = f[3..]
                            .iter()
                            .map(|e| {
                                let (ret, packet) = e.split_once(':').unwrap();
                                (ret.parse().unwrap(), unhex(packet))
                            })
                            .collect();
                    }
                    "authgen" => {
                        s.auth_gen = f[3..]
                            .iter()
                            .map(|e| {
                                let (st, size) = e.split_once(':').unwrap();
                                (st.to_owned(), size.parse().unwrap())
                            })
                            .collect();
                    }
                    "authval" => s.auth_val = f[3..].iter().map(|e| (*e).to_owned()).collect(),
                    "actions" => {
                        cfg.actions = f[3..]
                            .iter()
                            .map(|e| {
                                let p: Vec<&str> = e.split(':').collect();
                                (
                                    p[0].chars().next().unwrap(),
                                    p[1].parse().unwrap(),
                                    p[2].parse().unwrap(),
                                )
                            })
                            .collect();
                    }
                    other => panic!("unknown cfg kind {other:?}"),
                }
                drop(s);

                // `actions` is the last cfg line, so the scenario is complete.
                if f[1] == "actions" {
                    run_scenario(&mut out, &cfg, Rc::clone(&script));
                }
            }
            Some("end") if f.len() > 1 => {
                let _ = writeln!(out, "{line}");
            }
            Some("end") => {
                let _ = writeln!(out, "end");
            }
            // Every other line is one WE produce; the C's copy is compared
            // against ours rather than echoed.
            _ => {}
        }
    }

    out
}

#[test]
fn our_client_matches_the_c_callback_for_callback() {
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
        n += 1;
    }

    assert_eq!(n, 549, "the trace should be 549 lines, not {n}");
}

/// The guard: the scenarios must reach every outcome the client has.
///
/// heap_4's guard fails on too few refusals, heap_1's on never exhausting,
/// heap_5's on an unvisited region, backoff's on an unvisited branch, json's on
/// a corpus that stops being mostly rejections, the serializer's on an
/// unreached status. This is the seventh shape and it says the same thing.
#[test]
fn the_scenarios_reach_every_outcome() {
    let seen: Vec<&str> = TRACE
        .lines()
        .filter(|l| l.starts_with("action ") || l.starts_with("init "))
        .filter_map(|l| l.split_whitespace().last())
        .collect();

    for required in [
        "Success",
        "DnsFailure",
        "NetworkFailure",
        "SendTimeout",
        "NoResponseReceived",
        "ResponseTimeout",
        "RejectedResponse",
        "InvalidResponse",
        "AuthFailure",
        "ServerNotAuthenticated",
        "BadParameter",
        "BufferTooSmall",
    ] {
        assert!(
            seen.contains(&required),
            "no scenario ever produces {required}"
        );
    }

    // Every callback must be exercised, or a whole seam is untested.
    for call in [
        "call dns",
        "call getTime",
        "call setTime",
        "call sendTo",
        "call recvFrom",
        "call authGen",
        "call authVal",
    ] {
        assert!(TRACE.contains(call), "no scenario ever makes a {call}");
    }
}

/// The security asymmetry, stated as a test rather than left in a comment.
///
/// After a Kiss-o'-Death the client clears its stored request timestamp **only
/// when authentication is configured**. Without authentication anyone can forge
/// a rejection, and clearing on a forged one would make the genuine response
/// fail its originate check — turning a spoofed packet into a denial of
/// service. It is one `if` in the C and it is the most security-relevant line
/// in the file, so it gets its own test: the two scenarios must disagree.
#[test]
fn a_kiss_of_death_clears_the_request_time_only_when_authenticated() {
    fn final_state(scenario_name: &str) -> String {
        let mut in_scenario = false;
        let mut last_state = String::new();
        for line in TRACE.lines() {
            if line.starts_with("scenario ") {
                in_scenario = line.ends_with(scenario_name);
            }
            if in_scenario && line.starts_with("state ") {
                last_state = line.to_owned();
            }
        }
        assert!(!last_state.is_empty(), "no scenario named {scenario_name}");
        last_state
    }

    let without = final_state("kod-without-auth-keeps-request-time");
    let with = final_state("kod-with-auth-clears-request-time");

    let request_time = |s: &str| s.split_whitespace().nth(2).unwrap().to_owned();

    assert_ne!(
        request_time(&without),
        "00000000:00000000",
        "an UNAUTHENTICATED rejection cleared the request time — a spoofed \
         Kiss-o'-Death would now deny service by making the real response fail \
         its originate check"
    );
    assert_eq!(
        request_time(&with),
        "00000000:00000000",
        "an AUTHENTICATED rejection did not clear the request time"
    );
}
