//! Instruction counts for the SNTPv4 packet codec.
//!
//! Serialise a request, then walk a corpus of responses through the
//! deserialiser: well-formed replies, a kiss-of-death, wrong modes and
//! versions, zero timestamps, and times either side of the **2036 era wrap** --
//! which is the defect in this protocol that a client gets wrong silently and
//! only discovers years later.
//!
//! A deterministic counter, not a clock. The verdict counts are the work parity
//! anchors.

use rusty_rtos_sntp_core::{PACKET_BASE_SIZE, Timestamp, deserialize_response, serialize_request};

const REPS: u32 = 400;

/// Seconds either side of the era wrap, plus ordinary times.
const SECONDS: &[u32] = &[
    0,
    1,
    3_913_056_000,  // an ordinary time in era 0
    u32::MAX - 1,   // the last moments of era 0
    u32::MAX,
    2_085_978_496,  // 7 February 2036, the wrap itself
];

/// Leap-indicator / version / mode bytes, legal and not.
const LVM: &[u8] = &[0x24, 0x1C, 0x04, 0xE4, 0x00, 0xFF, 0x23, 0x25];

/// Write a 64-bit SNTP timestamp at `at`.
fn write_ts(buf: &mut [u8], at: usize, seconds: u32, fractions: u32) {
    for (i, b) in seconds.to_be_bytes().iter().enumerate() {
        if let Some(slot) = buf.get_mut(at.saturating_add(i)) {
            *slot = *b;
        }
    }
    for (i, b) in fractions.to_be_bytes().iter().enumerate() {
        if let Some(slot) = buf.get_mut(at.saturating_add(4).saturating_add(i)) {
            *slot = *b;
        }
    }
}

fn main() {
    let mut ok = 0u64;
    let mut refused = 0u64;
    let mut checksum = 0u64;

    for rep in 0..REPS {
        for (si, &secs) in SECONDS.iter().enumerate() {
            for (li, &lvm) in LVM.iter().enumerate() {
                let mut buf = [0u8; PACKET_BASE_SIZE];

                // The request half, which also fills in the transmit time.
                let mut request_time = Timestamp::new(secs, rep.wrapping_mul(7));
                if serialize_request(&mut request_time, rep.wrapping_add(1), &mut buf).is_ok() {
                    checksum = checksum
                        .wrapping_add(u64::from(request_time.seconds))
                        .wrapping_add(u64::from(request_time.fractions));
                }

                // Turn it into a reply the deserialiser can actually accept,
                // or deliberately not: mode SERVER in the low bits, a stratum,
                // the ORIGINATE timestamp echoing the request exactly, and
                // non-zero receive and transmit times. Getting this right is
                // the difference between measuring the parse and measuring the
                // first refusal -- the first corpus refused all 48.
                let mut reply = [0u8; PACKET_BASE_SIZE];
                write_ts(&mut reply, 24, request_time.seconds, request_time.fractions);
                write_ts(&mut reply, 32, secs.wrapping_add(1).max(1), 0x4000_0000);
                write_ts(&mut reply, 40, secs.wrapping_add(2).max(1), 0x8000_0000);
                if let Some(slot) = reply.get_mut(0) {
                    *slot = lvm;
                }
                if let Some(slot) = reply.get_mut(1) {
                    // Stratum 0 is the kiss of death, which is its own path.
                    *slot = u8::try_from(si).unwrap_or(0);
                }

                let rx = Timestamp::new(secs.wrapping_add(1), 0);
                match deserialize_response(&request_time, &rx, &reply) {
                    Ok(_) => {
                        ok = ok.wrapping_add(1);
                        checksum = checksum
                            .wrapping_add((si * LVM.len() + li) as u64)
                            .wrapping_add(1);
                    }
                    Err(_) => refused = refused.wrapping_add(1),
                }
            }
        }
    }

    println!("checksum {checksum}");
    println!(
        "reps {REPS} calls {} ok {} refused {}",
        ok.wrapping_add(refused),
        ok / u64::from(REPS),
        refused / u64::from(REPS)
    );
}
