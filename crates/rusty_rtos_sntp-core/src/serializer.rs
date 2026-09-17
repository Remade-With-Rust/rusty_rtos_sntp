//! `core_sntp_serializer.c` remade: the SNTPv4 packet codec and its arithmetic.
//!
//! Four entry points, no I/O and no clock. The caller supplies the time and the
//! randomness, exactly as the C does — which is what lets both arms be driven
//! from one table, and is the same boundary `rusty_rtos_backoff` keeps.
//!
//! # Integer arithmetic, on purpose
//!
//! Every calculation here is integer. That is not an accident of transcription:
//! coreSNTP targets parts with no floating-point unit, where an `f64` divide is
//! a soft-float call, and the clock offset is computed on the receive path of
//! every poll. It is also what makes this differentiable at all — two floating
//! point implementations agree to within an epsilon, and "within an epsilon" is
//! not something a byte-for-byte trace can assert.
//!
//! # The part that is easy to get wrong
//!
//! An SNTP timestamp's seconds field is 32 bits counting from 1900, so it wraps
//! on **7 February 2036**. Everything before that date is "era 0" and everything
//! after is "era 1". A client and a server can therefore sit either side of the
//! wrap and disagree by ~136 years on a naive subtraction.
//!
//! [`safe_time_difference`] handles it the way the C does: compute the
//! difference three ways — same era, server an era ahead, client an era ahead —
//! and take whichever has the **smallest absolute value**, on the assumption
//! that the two clocks are within 68 years of each other. A transcription that
//! gets the packet layout perfect and this comparison wrong is correct until
//! 2036 and then silently wrong forever.

use crate::{
    DeserializeError, LeapSecond, PollIntervalError, Rejected, Rejection, SerializeError,
    Timestamp, Verdict,
};

/// `SNTP_PACKET_BASE_SIZE`: a packet without authentication data.
pub const PACKET_BASE_SIZE: usize = 48;

/// `SNTP_FRACTION_VALUE_PER_MICROSECOND`. The fractions field is 32 bits over
/// one second, so one tick is about 232 picoseconds and a microsecond is 4,295
/// of them.
pub const FRACTION_VALUE_PER_MICROSECOND: u32 = 4295;

/// `SNTP_TIME_AT_UNIX_EPOCH_SECS`: 70 years, in seconds, between the SNTP epoch
/// (1 Jan 1900) and the UNIX epoch (1 Jan 1970).
pub const TIME_AT_UNIX_EPOCH_SECS: u32 = 2_208_988_800;

/// `UNIX_TIME_SECS_AT_SNTP_ERA_1_SMALLEST_TIME`: the UNIX time at the moment
/// SNTP's seconds field wraps, 7 Feb 2036 06:28:16 UTC.
pub const UNIX_TIME_SECS_AT_SNTP_ERA_1_SMALLEST_TIME: u32 = 2_085_978_496;

/// `SNTP_KISS_OF_DEATH_CODE_LENGTH`: a kiss code is four ASCII characters.
pub const KISS_OF_DEATH_CODE_LENGTH: usize = 4;

/// `SNTP_VERSION`.
const VERSION: u8 = 4;
/// `SNTP_MODE_BITS_MASK`.
const MODE_BITS_MASK: u8 = 0x07;
/// `SNTP_MODE_CLIENT`.
const MODE_CLIENT: u8 = 3;
/// `SNTP_MODE_SERVER`.
const MODE_SERVER: u8 = 4;
/// `SNTP_LEAP_INDICATOR_LSB_POSITION`.
const LEAP_INDICATOR_LSB_POSITION: u8 = 6;
/// `SNTP_VERSION_LSB_POSITION`.
const VERSION_LSB_POSITION: u8 = 3;
/// `SNTP_KISS_OF_DEATH_STRATUM`.
const KISS_OF_DEATH_STRATUM: u8 = 0;

/// The three kiss codes the specification names, as big-endian ASCII.
const KOD_DENY: u32 = 0x4445_4E59;
const KOD_RSTR: u32 = 0x5253_5452;
const KOD_RATE: u32 = 0x5241_5445;

/// `CLOCK_OFFSET_MAX_TIME_DIFFERENCE`: half an NTP era, in milliseconds.
///
/// At exactly this difference every era configuration yields the same absolute
/// value, so no comparison can tell them apart. The C resolves the tie by
/// ASSUMING the server is ahead, and so does this.
///
/// **Only observable from one side**, which a poison found: for a POSITIVE tie
/// the general three-way comparison happens to produce the same answer, so the
/// special case earns its keep only when the client is half an era ahead —
/// there it turns a -2^31 second answer into a +2^31 second one. The
/// differential carries a case for each side.
const CLOCK_OFFSET_MAX_TIME_DIFFERENCE: i64 = (i32::MAX as i64 + 1) * 1000;

/// `TOTAL_MILLISECONDS_IN_NTP_ERA`: one whole era, about 136 years.
const TOTAL_MILLISECONDS_IN_NTP_ERA: i64 = (u32::MAX as i64 + 1) * 1000;

// ---- byte-order helpers --------------------------------------------------

/// `readWordFromNetworkByteOrderMemory`, for a field at a known offset.
///
/// Returns `None` past the end. Every caller has already checked the buffer is
/// at least [`PACKET_BASE_SIZE`], so this is the same defence-in-depth the
/// json validator's reader turned out to be — it costs nothing and it means a
/// future edit cannot turn a missing bound into a panic.
fn word_at(buf: &[u8], offset: usize) -> Option<u32> {
    let end = offset.saturating_add(4);
    let slice = buf.get(offset..end)?;
    let bytes: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

/// `fillWordMemoryInNetworkOrder`.
fn put_word(buf: &mut [u8], offset: usize, value: u32) {
    let end = offset.saturating_add(4);
    if let Some(slice) = buf.get_mut(offset..end) {
        slice.copy_from_slice(&value.to_be_bytes());
    }
}

/// The offsets of the fields this codec reads. The header is fixed-layout, so
/// these are the specification's own numbers rather than a struct's padding.
mod field {
    pub const LEAP_VERSION_MODE: usize = 0;
    pub const STRATUM: usize = 1;
    pub const REF_ID: usize = 12;
    pub const ORIGIN_SECONDS: usize = 24;
    pub const ORIGIN_FRACTIONS: usize = 28;
    pub const RECEIVE_SECONDS: usize = 32;
    pub const RECEIVE_FRACTIONS: usize = 36;
    pub const TRANSMIT_SECONDS: usize = 40;
    pub const TRANSMIT_FRACTIONS: usize = 44;
}

/// Read a timestamp pair at two offsets.
fn timestamp_at(buf: &[u8], seconds_at: usize, fractions_at: usize) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: word_at(buf, seconds_at)?,
        fractions: word_at(buf, fractions_at)?,
    })
}

// ---- the arithmetic ------------------------------------------------------

/// `fractionsToMs`.
///
/// The largest fraction, `0xFFFFFFFF`, gives **999** and not 1000 — the divisor
/// is 4,295,000 while a whole second is 4,294,967,296 ticks, so the conversion
/// loses a little and can never round up into the next second.
const fn fractions_to_ms(fractions: u32) -> u32 {
    fractions / (1000 * FRACTION_VALUE_PER_MICROSECOND)
}

/// `absoluteOf`.
///
/// Saturating rather than wrapping: the C's `0 - value` is undefined at
/// `INT64_MIN`, and the values here are bounded far below it, so the two agree
/// everywhere they are defined and this one has no undefined case at all.
const fn absolute_of(value: i64) -> i64 {
    value.saturating_abs()
}

/// A timestamp as signed milliseconds since the SNTP epoch.
const fn as_millis(t: &Timestamp) -> i64 {
    (t.seconds as i64)
        .saturating_mul(1000)
        .saturating_add(fractions_to_ms(t.fractions) as i64)
}

/// `safeTimeDifference`: `server - client`, in milliseconds, across NTP eras.
///
/// See the module documentation for why this exists. The three candidate
/// differences are computed and the smallest in absolute value wins, because
/// the two clocks are assumed to be within 68 years of each other — so only one
/// era configuration can produce a plausibly small answer.
fn safe_time_difference(server: &Timestamp, client: &Timestamp) -> i64 {
    let server_ms = as_millis(server);
    let client_ms = as_millis(client);

    let same_era = server_ms.saturating_sub(client_ms);
    let abs_same_era = absolute_of(same_era);

    // Exactly half an era apart: every configuration gives the same absolute
    // value, so nothing can distinguish them. The C assumes the server is
    // ahead, which makes the offset positive.
    if abs_same_era == CLOCK_OFFSET_MAX_TIME_DIFFERENCE {
        return CLOCK_OFFSET_MAX_TIME_DIFFERENCE;
    }

    let server_era_ahead = server_ms
        .saturating_add(TOTAL_MILLISECONDS_IN_NTP_ERA)
        .saturating_sub(client_ms);
    let client_era_ahead =
        server_ms.saturating_sub(TOTAL_MILLISECONDS_IN_NTP_ERA.saturating_add(client_ms));

    let abs_server_ahead = absolute_of(server_era_ahead);
    let abs_client_ahead = absolute_of(client_era_ahead);

    if abs_same_era <= abs_server_ahead && abs_same_era <= abs_client_ahead {
        same_era
    } else if abs_server_ahead < abs_same_era {
        server_era_ahead
    } else {
        client_era_ahead
    }
}

/// `calculateClockOffset`: the NTP on-wire formula.
///
/// ```text
///               (T2 - T1) + (T3 - T4)
/// clock offset = ---------------------
///                         2
/// ```
///
/// T1 is when the client sent, T2 when the server received, T3 when the server
/// replied and T4 when the client received. Averaging the two legs cancels a
/// symmetric network delay, which is the whole idea.
fn calculate_clock_offset(
    client_tx: &Timestamp,
    server_rx: &Timestamp,
    server_tx: &Timestamp,
    client_rx: &Timestamp,
) -> i64 {
    let send = safe_time_difference(server_rx, client_tx);
    let recv = safe_time_difference(server_tx, client_rx);

    // C's integer division truncates toward zero, and so does Rust's, so a
    // negative offset rounds the same way in both arms.
    send.saturating_add(recv) / 2
}

// ---- the public surface --------------------------------------------------

/// `Sntp_SerializeRequest`: build an SNTP request packet.
///
/// **`request_time` is an in-out parameter, as it is in the C.** The random
/// number's top 16 bits are OR-ed into the low 16 bits of the fractions, which
/// the specification recommends as replay protection, and the caller must send
/// and remember the *modified* timestamp — a server echoes it back in the
/// originate field and [`deserialize_response`] checks it exactly.
///
/// Only the first [`PACKET_BASE_SIZE`] bytes are touched; anything the caller
/// has reserved beyond that for authentication data is left alone.
///
/// # Errors
///
/// [`SerializeError::BufferTooSmall`] if the buffer is under
/// [`PACKET_BASE_SIZE`], and [`SerializeError::BadParameter`] if the request
/// timestamp is zero — which is refused because a zero originate field is what
/// a spoofed response would carry.
///
/// **The size is checked first**, so a call that is both too small and zero
/// gets `BufferTooSmall`. That order is the C's.
pub fn serialize_request(
    request_time: &mut Timestamp,
    random_number: u32,
    buffer: &mut [u8],
) -> Result<(), SerializeError> {
    if buffer.len() < PACKET_BASE_SIZE {
        return Err(SerializeError::BufferTooSmall);
    }

    if request_time.is_zero() {
        return Err(SerializeError::BadParameter);
    }

    let Some(packet) = buffer.get_mut(..PACKET_BASE_SIZE) else {
        return Err(SerializeError::BufferTooSmall);
    };

    // Most of a request is zero.
    packet.fill(0);

    if let Some(first) = packet.get_mut(field::LEAP_VERSION_MODE) {
        // Leap indicator 0, version 4, mode 3 (client).
        *first = (VERSION << VERSION_LSB_POSITION) | MODE_CLIENT;
    }

    // ~15 microseconds of the timestamp is given up to make the request hard
    // to predict. It is an OR and not an add, so it can never carry into the
    // seconds.
    request_time.fractions |= random_number >> 16;

    put_word(packet, field::TRANSMIT_SECONDS, request_time.seconds);
    put_word(packet, field::TRANSMIT_FRACTIONS, request_time.fractions);

    Ok(())
}

/// `Sntp_DeserializeResponse`: validate a server response and time the clock.
///
/// A response is accepted only if it is from a server, carries no zero
/// timestamp, and echoes `request_time` exactly in its originate field. Those
/// checks are what stop an off-path attacker forging a reply.
///
/// A server that refuses gives a **Kiss-o'-Death**: stratum 0, with a
/// four-character reason in the reference-id field. That is a valid response
/// rather than a malformed one, so it comes back as
/// [`Verdict::Rejected`] rather than as an error.
///
/// # Errors
///
/// [`DeserializeError::BufferTooSmall`] under [`PACKET_BASE_SIZE`],
/// [`DeserializeError::BadParameter`] for a zero request timestamp, and
/// [`DeserializeError::InvalidResponse`] for anything that fails validation.
/// The size is checked before the zero timestamp, as in the C.
pub fn deserialize_response(
    request_time: &Timestamp,
    response_rx_time: &Timestamp,
    buffer: &[u8],
) -> Result<Verdict, DeserializeError> {
    if buffer.len() < PACKET_BASE_SIZE {
        return Err(DeserializeError::BufferTooSmall);
    }

    if request_time.is_zero() {
        return Err(DeserializeError::BadParameter);
    }

    let Some(leap_version_mode) = buffer.get(field::LEAP_VERSION_MODE).copied() else {
        return Err(DeserializeError::BufferTooSmall);
    };

    if (leap_version_mode & MODE_BITS_MASK) != MODE_SERVER {
        return Err(DeserializeError::InvalidResponse);
    }

    let (Some(origin), Some(receive), Some(transmit)) = (
        timestamp_at(buffer, field::ORIGIN_SECONDS, field::ORIGIN_FRACTIONS),
        timestamp_at(buffer, field::RECEIVE_SECONDS, field::RECEIVE_FRACTIONS),
        timestamp_at(buffer, field::TRANSMIT_SECONDS, field::TRANSMIT_FRACTIONS),
    ) else {
        return Err(DeserializeError::BufferTooSmall);
    };

    // A zero timestamp anywhere is refused. The subtle one is the ORIGINATE
    // field: a client that clears its stored request time after a reply would
    // otherwise accept a forged response carrying zero there.
    if origin.is_zero() || receive.is_zero() || transmit.is_zero() {
        return Err(DeserializeError::InvalidResponse);
    }

    // The server must echo the exact timestamp we sent, fractions and all --
    // including the random bits `serialize_request` OR-ed in.
    if origin != *request_time {
        return Err(DeserializeError::InvalidResponse);
    }

    let Some(stratum) = buffer.get(field::STRATUM).copied() else {
        return Err(DeserializeError::BufferTooSmall);
    };

    if stratum == KISS_OF_DEATH_STRATUM {
        let Some(code) = word_at(buffer, field::REF_ID) else {
            return Err(DeserializeError::BufferTooSmall);
        };

        let kind = match code {
            KOD_DENY | KOD_RSTR => Rejection::ChangeServer,
            KOD_RATE => Rejection::RetryWithBackoff,
            _ => Rejection::Other,
        };

        return Ok(Verdict::Rejected(Rejected { code, kind }));
    }

    // The leap indicator is the top two bits, so the shift can only produce
    // 0..=3 and every value maps to a variant.
    let leap_second = match leap_version_mode >> LEAP_INDICATOR_LSB_POSITION {
        0 => LeapSecond::None,
        1 => LeapSecond::LastMinuteHas61Seconds,
        2 => LeapSecond::LastMinuteHas59Seconds,
        _ => LeapSecond::AlarmServerNotSynchronized,
    };

    // The server's own time is its TRANSMIT timestamp; its receive timestamp
    // is only an input to the offset.
    let clock_offset_ms =
        calculate_clock_offset(request_time, &receive, &transmit, response_rx_time);

    Ok(Verdict::Accepted(crate::Accepted {
        server_time: transmit,
        leap_second,
        clock_offset_ms,
    }))
}

/// `Sntp_CalculatePollInterval`: how often to ask, for a wanted accuracy.
///
/// A clock drifting at `clock_freq_tolerance` parts per million loses
/// `desired_accuracy` milliseconds after `accuracy * 1000 / tolerance`
/// seconds. The answer is rounded **down** to a power of two, because a shorter
/// interval is more accurate than asked for and a longer one is not.
///
/// # Errors
///
/// [`PollIntervalError::BadParameter`] if either argument is zero, and
/// [`PollIntervalError::ZeroPollInterval`] when the exact interval works out
/// under one second, which this cannot express.
pub fn calculate_poll_interval(
    clock_freq_tolerance: u16,
    desired_accuracy: u16,
) -> Result<u32, PollIntervalError> {
    if clock_freq_tolerance == 0 || desired_accuracy == 0 {
        return Err(PollIntervalError::BadParameter);
    }

    let exact = u32::from(desired_accuracy)
        .saturating_mul(1000)
        .checked_div(u32::from(clock_freq_tolerance))
        .unwrap_or(0);

    if exact == 0 {
        return Err(PollIntervalError::ZeroPollInterval);
    }

    // The C finds the highest set bit by dividing until the value is zero and
    // then stepping back one, which is floor(log2(exact)).
    let log2_poll_interval = u32::BITS
        .saturating_sub(exact.leading_zeros())
        .saturating_sub(1);

    Ok(1u32 << log2_poll_interval)
}

/// `Sntp_ConvertToUnixTime`: an SNTP timestamp as UNIX seconds and microseconds.
///
/// **This cannot fail.** The C returns a status only because all three of its
/// parameters are pointers that might be NULL; with a reference and a returned
/// tuple there is nothing left to refuse, so the status is gone rather than
/// stubbed out.
///
/// Seconds at or above [`TIME_AT_UNIX_EPOCH_SECS`] are era 0 and simply lose
/// the 70-year offset. Anything below has wrapped into era 1, and counts from
/// [`UNIX_TIME_SECS_AT_SNTP_ERA_1_SMALLEST_TIME`] instead.
///
/// # The two branches meet exactly, and that is not luck
///
/// The two constants sum to **exactly 2^32**, so at the boundary the era-0
/// subtraction and the era-1 wrapping addition give the same answer. That is
/// what makes the era-1 formula a plain wrapping add rather than something
/// that needs a carry, and it means `>=` and `>` here are indistinguishable —
/// a poison on that comparison changed nothing.
/// [`the_two_era_constants_are_complementary`](self) pins it.
#[must_use]
pub const fn convert_to_unix_time(sntp_time: &Timestamp) -> (u32, u32) {
    let seconds = if sntp_time.seconds >= TIME_AT_UNIX_EPOCH_SECS {
        // The branch condition is what makes this exact; saturating says so
        // to the compiler as well as to the reader.
        sntp_time.seconds.saturating_sub(TIME_AT_UNIX_EPOCH_SECS)
    } else {
        UNIX_TIME_SECS_AT_SNTP_ERA_1_SMALLEST_TIME.wrapping_add(sntp_time.seconds)
    };

    let microseconds = sntp_time.fractions / FRACTION_VALUE_PER_MICROSECOND;

    (seconds, microseconds)
}

#[cfg(test)]
// A test builds its own probe values; the workspace's arithmetic policy is
// written for library code, where an unchecked operation is a defect.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// Why `>=` and `>` are the same thing in [`convert_to_unix_time`].
    ///
    /// This started as a poison that did not fire. The two era constants sum
    /// to exactly 2^32, so at the single second where the comparison differs,
    /// the era-0 subtraction and the era-1 wrapping addition agree. That is a
    /// property of the constants, and a property nobody checks is one edit
    /// away from being false.
    #[test]
    fn the_two_era_constants_are_complementary() {
        assert_eq!(
            u64::from(TIME_AT_UNIX_EPOCH_SECS)
                + u64::from(UNIX_TIME_SECS_AT_SNTP_ERA_1_SMALLEST_TIME),
            1u64 << 32,
            "the era constants no longer sum to 2^32, so the two branches no \
             longer meet at the boundary"
        );

        // And the boundary second itself, computed both ways.
        let boundary = Timestamp::new(TIME_AT_UNIX_EPOCH_SECS, 0);
        let (era_zero_answer, _) = convert_to_unix_time(&boundary);
        let era_one_answer =
            UNIX_TIME_SECS_AT_SNTP_ERA_1_SMALLEST_TIME.wrapping_add(TIME_AT_UNIX_EPOCH_SECS);
        assert_eq!(era_zero_answer, era_one_answer);
        assert_eq!(era_zero_answer, 0);
    }

    /// Why the `<=` in [`safe_time_difference`] can never be a `<`.
    ///
    /// Also a poison that did not fire. The equality cases of that comparison
    /// are EXACTLY the half-an-era tie, which the special case above has
    /// already returned on — so the boundary is unreachable and `<=` is
    /// defence in depth.
    ///
    /// Algebraically: `|d| == |d + E|` forces `d == -E/2`, and
    /// `|d| == |d - E|` forces `d == E/2`. Both are the tie. This sweeps a
    /// wide range of differences and asserts no OTHER equality exists.
    #[test]
    fn the_era_comparison_can_only_tie_at_half_an_era() {
        let era = TOTAL_MILLISECONDS_IN_NTP_ERA;
        let half = CLOCK_OFFSET_MAX_TIME_DIFFERENCE;

        // A spread of differences, including the tie and its neighbours.
        let mut probes = alloc_probes(era, half);
        probes.sort_unstable();

        for d in probes {
            let same = absolute_of(d);
            let server_ahead = absolute_of(d.saturating_add(era));
            let client_ahead = absolute_of(d.saturating_sub(era));

            if same == server_ahead || same == client_ahead {
                assert_eq!(
                    same, half,
                    "a tie at {d} that is not half an era -- the `<=` is load-bearing \
                     after all and this test is now the wrong shape"
                );
            }
        }
    }

    /// The probe set for the sweep above: the tie, its neighbours, the era
    /// boundaries, and a spread across the whole representable range.
    fn alloc_probes(era: i64, half: i64) -> [i64; 17] {
        [
            0,
            1,
            -1,
            half,
            -half,
            half - 1,
            -half + 1,
            half + 1,
            -half - 1,
            era,
            -era,
            era - 1,
            -era + 1,
            1_000,
            -1_000,
            i64::from(i32::MAX),
            -i64::from(i32::MAX),
        ]
    }

    /// The largest fraction converts to 999 ms, never 1000.
    ///
    /// The divisor is 4,295,000 while a whole second is 4,294,967,296 ticks,
    /// so the conversion loses a little on purpose and can never round up into
    /// the next second. Using the exact divisor instead fails the
    /// differential, which is one of the poisons.
    #[test]
    fn fractions_never_round_up_into_the_next_second() {
        assert_eq!(fractions_to_ms(u32::MAX), 999);
        assert_eq!(fractions_to_ms(0), 0);
        // Half a second, which the exact divisor would call 500.
        assert_eq!(fractions_to_ms(0x8000_0000), 499);
    }
}
