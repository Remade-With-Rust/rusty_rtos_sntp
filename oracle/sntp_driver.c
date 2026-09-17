/* The C arm of K7's coreSNTP serializer differential.
 *
 * `core_sntp_serializer.c` is compiled VERBATIM out of the pinned checkout;
 * nothing here copies or edits it. This driver only decides WHAT to ask, and
 * prints every observable of each answer.
 *
 * Four entry points, and the interesting one by a wide margin is
 * Sntp_DeserializeResponse: it computes a clock offset across NTP ERAS. The
 * "seconds" field is 32 bits and wraps in Feb 2036, so the library works out
 * whether client and server sit in the same era or adjacent ones by computing
 * the difference three ways and taking the smallest absolute value. A
 * transcription that gets the packet layout perfect and that comparison wrong
 * is correct for another ten years and then silently wrong forever, which is
 * precisely the kind of thing a differential is for.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core_sntp_serializer.h"

#define BASE SNTP_PACKET_BASE_SIZE

static const char *status_name( SntpStatus_t s )
{
    switch( s )
    {
        case SntpSuccess:                          return "Success";
        case SntpErrorBadParameter:                return "BadParameter";
        case SntpRejectedResponse:                 return "Rejected";
        case SntpRejectedResponseChangeServer:     return "RejectedChangeServer";
        case SntpRejectedResponseRetryWithBackoff: return "RejectedRetryWithBackoff";
        case SntpRejectedResponseOtherCode:        return "RejectedOtherCode";
        case SntpErrorBufferTooSmall:              return "BufferTooSmall";
        case SntpInvalidResponse:                  return "InvalidResponse";
        case SntpZeroPollInterval:                 return "ZeroPollInterval";
        default:                                   return "UNEXPECTED";
    }
}

static const char *leap_name( SntpLeapSecondInfo_t l )
{
    switch( l )
    {
        case NoLeapSecond:               return "NoLeapSecond";
        case LastMinuteHas61Seconds:     return "Has61";
        case LastMinuteHas59Seconds:     return "Has59";
        case AlarmServerNotSynchronized: return "Alarm";
        default:                         return "UNEXPECTED";
    }
}

static void put_hex( const uint8_t *p, size_t n )
{
    size_t i;
    for( i = 0; i < n; i++ )
    {
        printf( "%02x", p[ i ] );
    }
}

/* ---- 1. Sntp_SerializeRequest ---------------------------------------- */

/* seconds, fractions, randomNumber, bufferSize */
static const uint32_t SERIALIZE_CASES[][ 4 ] = {
    { 0x00000000U, 0x00000000U, 0x00000000U, BASE },        /* a zero timestamp is refused */
    { 0x00000000U, 0x00000001U, 0x00000000U, BASE },        /* not zero: fractions alone count */
    { 0x00000001U, 0x00000000U, 0x00000000U, BASE },        /* nor seconds alone */
    { 0xE7E1F4C8U, 0x00000000U, 0x00000000U, BASE },        /* a realistic 2023 timestamp */
    { 0xE7E1F4C8U, 0x00000000U, 0xFFFFFFFFU, BASE },        /* every random bit set */
    { 0xE7E1F4C8U, 0xFFFF0000U, 0xFFFFFFFFU, BASE },        /* the OR cannot carry */
    { 0xE7E1F4C8U, 0x0000FFFFU, 0x12345678U, BASE },        /* low bits already set */
    { 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, BASE },        /* the largest timestamp */
    { 0xE7E1F4C8U, 0x00000000U, 0x00010000U, BASE },        /* exactly one random bit survives the >> 16 */
    { 0xE7E1F4C8U, 0x00000000U, 0x0000FFFFU, BASE },        /* every random bit is shifted AWAY */
    { 0xE7E1F4C8U, 0x00000000U, 0x00000000U, BASE - 1U },   /* one byte short */
    { 0xE7E1F4C8U, 0x00000000U, 0x00000000U, 0U },          /* no buffer at all */
    { 0xE7E1F4C8U, 0x00000000U, 0xABCDEF01U, BASE + 16U },  /* room for authentication data */
    /* BOTH faults at once. The C checks the buffer size BEFORE the zero
     * timestamp, so this is BufferTooSmall and not BadParameter -- the
     * classic place a transcription reorders two guards and still passes
     * every test that triggers only one of them. */
    { 0x00000000U, 0x00000000U, 0x00000000U, BASE - 1U },
};

#define N_SERIALIZE ( sizeof( SERIALIZE_CASES ) / sizeof( SERIALIZE_CASES[ 0 ] ) )

static void run_serialize( void )
{
    size_t i;

    for( i = 0; i < N_SERIALIZE; i++ )
    {
        uint8_t buffer[ BASE + 16U ];
        SntpTimestamp_t t;
        SntpStatus_t r;
        size_t size = ( size_t ) SERIALIZE_CASES[ i ][ 3 ];

        t.seconds = SERIALIZE_CASES[ i ][ 0 ];
        t.fractions = SERIALIZE_CASES[ i ][ 1 ];

        /* A recognisable fill, so a field the library does NOT write shows up
         * as 0xAA rather than as a plausible zero. */
        memset( buffer, 0xAA, sizeof buffer );

        printf( "serialize %zu in %08x %08x %08x %zu\n", i,
                SERIALIZE_CASES[ i ][ 0 ], SERIALIZE_CASES[ i ][ 1 ],
                SERIALIZE_CASES[ i ][ 2 ], size );

        r = Sntp_SerializeRequest( &t, SERIALIZE_CASES[ i ][ 2 ], buffer, size );

        /* The request timestamp is an IN-OUT parameter: the library ORs the
         * random number into its fractions. Printing it back is the only way
         * to catch a transcription that treated it as read-only. */
        printf( "serialize %zu out %s %08x %08x ", i, status_name( r ), t.seconds, t.fractions );
        put_hex( buffer, BASE );
        printf( "\n" );
    }
}

/* ---- 2. Sntp_DeserializeResponse -------------------------------------- */

typedef struct
{
    uint8_t leapVersionMode;
    uint8_t stratum;
    uint32_t refId;
    uint32_t originSec, originFrac;
    uint32_t recvSec, recvFrac;
    uint32_t xmitSec, xmitFrac;
    uint32_t reqSec, reqFrac;      /* what the client says it sent */
    uint32_t rxSec, rxFrac;        /* when the client received the response */
    size_t bufferSize;
} DeserCase_t;

/* 0x24 = LI 0, version 4, mode 4 (server). */
#define OK_LVM 0x24U

static const DeserCase_t DESER_CASES[] = {
    /* --- the refusals ------------------------------------------------- */
    { OK_LVM, 1, 0, 1, 1, 2, 2, 3, 3, 1, 1, 4, 4, BASE - 1U },   /* buffer too small */
    { OK_LVM, 1, 0, 1, 1, 2, 2, 3, 3, 0, 0, 4, 4, BASE },        /* zero request time */
    { OK_LVM, 1, 0, 1, 1, 2, 2, 3, 3, 0, 0, 4, 4, BASE - 1U },   /* BOTH: size is checked first */
    { 0x23U,  1, 0, 1, 1, 2, 2, 3, 3, 1, 1, 4, 4, BASE },        /* mode 3 = client, not server */
    { 0x27U,  1, 0, 1, 1, 2, 2, 3, 3, 1, 1, 4, 4, BASE },        /* mode 7 = private */
    { OK_LVM, 1, 0, 0, 0, 2, 2, 3, 3, 1, 1, 4, 4, BASE },        /* zero originate */
    { OK_LVM, 1, 0, 1, 1, 0, 0, 3, 3, 1, 1, 4, 4, BASE },        /* zero receive */
    { OK_LVM, 1, 0, 1, 1, 2, 2, 0, 0, 1, 1, 4, 4, BASE },        /* zero transmit */
    { OK_LVM, 1, 0, 9, 1, 2, 2, 3, 3, 1, 1, 4, 4, BASE },        /* originate seconds mismatch */
    { OK_LVM, 1, 0, 1, 9, 2, 2, 3, 3, 1, 1, 4, 4, BASE },        /* originate fractions mismatch */

    /* --- Kiss-o'-Death: stratum 0, code in the reference id ------------ */
    { OK_LVM, 0, 0x44454E59U, 1, 1, 2, 2, 3, 3, 1, 1, 4, 4, BASE },  /* DENY */
    { OK_LVM, 0, 0x52535452U, 1, 1, 2, 2, 3, 3, 1, 1, 4, 4, BASE },  /* RSTR */
    { OK_LVM, 0, 0x52415445U, 1, 1, 2, 2, 3, 3, 1, 1, 4, 4, BASE },  /* RATE */
    { OK_LVM, 0, 0x41435354U, 1, 1, 2, 2, 3, 3, 1, 1, 4, 4, BASE },  /* ACST: some other code */
    { OK_LVM, 0, 0x00000000U, 1, 1, 2, 2, 3, 3, 1, 1, 4, 4, BASE },  /* a zero kiss code */

    /* --- accepted, and the leap indicator ------------------------------ */
    { 0x24U, 1, 0, 100, 0, 200, 0, 300, 0, 100, 0, 400, 0, BASE },   /* LI 0 */
    { 0x64U, 1, 0, 100, 0, 200, 0, 300, 0, 100, 0, 400, 0, BASE },   /* LI 1: 61 seconds */
    { 0xA4U, 1, 0, 100, 0, 200, 0, 300, 0, 100, 0, 400, 0, BASE },   /* LI 2: 59 seconds */
    { 0xE4U, 1, 0, 100, 0, 200, 0, 300, 0, 100, 0, 400, 0, BASE },   /* LI 3: alarm */

    /* --- the clock offset, same era ------------------------------------ */
    /* A symmetric round trip: T1=1000 T2=1005 T3=1006 T4=1002 -> +~4.5s */
    { OK_LVM, 1, 0, 1000, 0, 1005, 0, 1006, 0, 1000, 0, 1002, 0, BASE },
    /* Client AHEAD of the server, so a negative offset. */
    { OK_LVM, 1, 0, 5000, 0, 1005, 0, 1006, 0, 5000, 0, 5002, 0, BASE },
    /* Fractions only, to exercise fractionsToMs. */
    { OK_LVM, 1, 0, 100, 0x80000000U, 100, 0xC0000000U, 100, 0xC0000000U, 100, 0x80000000U, 100, 0x90000000U, BASE },
    /* The largest fraction, which must convert to 999 ms and not 1000. */
    { OK_LVM, 1, 0, 100, 0xFFFFFFFFU, 100, 0xFFFFFFFFU, 100, 0xFFFFFFFFU, 100, 0xFFFFFFFFU, 100, 0x00000000U, BASE },

    /* --- the clock offset ACROSS NTP ERAS ------------------------------ */
    /* Client just before the 2036 wrap, server just after: the server's
     * seconds have wrapped to a small number, so a naive subtraction gives
     * ~-136 years and the era logic must recover ~+2 seconds. */
    { OK_LVM, 1, 0, 0xFFFFFFFEU, 0, 1, 0, 2, 0, 0xFFFFFFFEU, 0, 0xFFFFFFFFU, 0, BASE },
    /* The mirror: client has wrapped, server has not. */
    { OK_LVM, 1, 0, 1, 0, 0xFFFFFFFEU, 0, 0xFFFFFFFFU, 0, 1, 0, 2, 0, BASE },
    /* The send leg crosses an era boundary and the receive leg does not, so
     * the two first-order differences are adjusted differently and then
     * averaged: +3000 ms and -2000 ms give +500. Nothing else here mixes era
     * configurations within a single call.
     * (The documented half-an-era TIE is reached by the 0x80000001 case two
     * rows below, where 0x80000001 - 1 is exactly 2^31.) */
    { OK_LVM, 1, 0, 0xFFFFFFFEU, 0, 1, 0, 2, 0, 0xFFFFFFFEU, 0, 4, 0, BASE },
    /* Just under and just over that tie, either side of the branch. */
    { OK_LVM, 1, 0, 1, 0, 0x7FFFFFFFU, 0, 0x7FFFFFFFU, 0, 1, 0, 1, 0, BASE },
    { OK_LVM, 1, 0, 1, 0, 0x80000001U, 0, 0x80000001U, 0, 1, 0, 1, 0, BASE },
    /* The tie again, but from the OTHER side: the client is half an era
     * AHEAD of the server. This is the only case where the special case is
     * observable at all -- for a positive tie the general three-way compare
     * happens to produce the same value, so removing the special case changes
     * nothing. Here it turns a -2^31 s answer into a +2^31 s one, which is the
     * documented "assume the server is ahead" rule. */
    { OK_LVM, 1, 0, 0x80000001U, 0, 1, 0, 1, 0, 0x80000001U, 0, 0x80000001U, 0, BASE },
    /* A realistic pair around the actual 2036 rollover moment. */
    { OK_LVM, 1, 0, 0xFFFFFFFFU, 0x80000000U, 0, 0x40000000U, 0, 0x50000000U, 0xFFFFFFFFU, 0x80000000U, 0, 0x60000000U, BASE },
};

#define N_DESER ( sizeof( DESER_CASES ) / sizeof( DESER_CASES[ 0 ] ) )

static void put_word( uint8_t *p, uint32_t v )
{
    p[ 0 ] = ( uint8_t ) ( v >> 24 );
    p[ 1 ] = ( uint8_t ) ( v >> 16 );
    p[ 2 ] = ( uint8_t ) ( v >> 8 );
    p[ 3 ] = ( uint8_t ) v;
}

static void build_packet( uint8_t *b, const DeserCase_t *c )
{
    memset( b, 0, BASE );
    b[ 0 ] = c->leapVersionMode;
    b[ 1 ] = c->stratum;
    b[ 2 ] = 0;                     /* poll */
    b[ 3 ] = 0;                     /* precision */
    put_word( &b[ 4 ], 0 );         /* root delay */
    put_word( &b[ 8 ], 0 );         /* root dispersion */
    put_word( &b[ 12 ], c->refId );
    put_word( &b[ 16 ], 0 );        /* reference timestamp */
    put_word( &b[ 20 ], 0 );
    put_word( &b[ 24 ], c->originSec );
    put_word( &b[ 28 ], c->originFrac );
    put_word( &b[ 32 ], c->recvSec );
    put_word( &b[ 36 ], c->recvFrac );
    put_word( &b[ 40 ], c->xmitSec );
    put_word( &b[ 44 ], c->xmitFrac );
}

static void run_deserialize( void )
{
    size_t i;

    for( i = 0; i < N_DESER; i++ )
    {
        const DeserCase_t *c = &DESER_CASES[ i ];
        uint8_t packet[ BASE ];
        SntpTimestamp_t req, rx;
        SntpResponseData_t parsed;
        SntpStatus_t r;

        build_packet( packet, c );
        req.seconds = c->reqSec;
        req.fractions = c->reqFrac;
        rx.seconds = c->rxSec;
        rx.fractions = c->rxFrac;
        memset( &parsed, 0xAA, sizeof parsed );

        printf( "deser %zu in %08x %08x %08x %08x %zu ", i,
                c->reqSec, c->reqFrac, c->rxSec, c->rxFrac, c->bufferSize );
        put_hex( packet, BASE );
        printf( "\n" );

        r = Sntp_DeserializeResponse( &req, &rx, packet, c->bufferSize, &parsed );

        printf( "deser %zu out %s", i, status_name( r ) );

        /* The library zeroes the output before filling it, so the parsed
         * struct is meaningful for every status EXCEPT the early refusals
         * that return before parseValidSntpResponse runs. */
        if( ( r == SntpSuccess ) || ( r == SntpRejectedResponseChangeServer ) ||
            ( r == SntpRejectedResponseRetryWithBackoff ) || ( r == SntpRejectedResponseOtherCode ) )
        {
            printf( " %08x %08x %s %08x %lld",
                    parsed.serverTime.seconds, parsed.serverTime.fractions,
                    leap_name( parsed.leapSecondType ),
                    parsed.rejectedResponseCode,
                    ( long long ) parsed.clockOffsetMs );
        }

        printf( "\n" );
    }
}

/* ---- 3. Sntp_CalculatePollInterval ------------------------------------ */

static const uint16_t POLL_CASES[][ 2 ] = {
    { 0, 100 },        /* zero tolerance */
    { 100, 0 },        /* zero accuracy */
    { 0, 0 },          /* both zero */
    { 32, 500 },       /* the library's own documented example */
    { 500, 1 },        /* under a second: refused */
    { 1000, 1 },       /* well under a second */
    { 1, 1 },          /* exactly 1000 seconds -> 512 */
    { 1, 65535 },      /* the largest accuracy */
    { 65535, 1 },      /* the largest tolerance */
    { 65535, 65535 },  /* both largest */
    { 1000, 1000 },    /* exactly 1000 -> 512 */
    { 999, 1000 },     /* 1001 -> 512 */
    { 1001, 1000 },    /* 999 -> 512 */
    { 2000, 1000 },    /* exactly 500 -> 256 */
    { 1024, 1024 },    /* exactly 1000 */
    { 1, 2 },          /* 2000 -> 1024 */
    { 3, 1 },          /* 333 -> 256 */
    { 7, 1 },          /* 142 -> 128 */
};

#define N_POLL ( sizeof( POLL_CASES ) / sizeof( POLL_CASES[ 0 ] ) )

static void run_poll( void )
{
    size_t i;

    for( i = 0; i < N_POLL; i++ )
    {
        uint32_t interval = 0xAAAAAAAAU;
        SntpStatus_t r;

        printf( "poll %zu in %u %u\n", i,
                ( unsigned ) POLL_CASES[ i ][ 0 ], ( unsigned ) POLL_CASES[ i ][ 1 ] );

        r = Sntp_CalculatePollInterval( POLL_CASES[ i ][ 0 ],
                                        POLL_CASES[ i ][ 1 ],
                                        &interval );

        printf( "poll %zu out %s", i, status_name( r ) );

        if( r == SntpSuccess )
        {
            printf( " %u", interval );
        }

        printf( "\n" );
    }
}

/* ---- 4. Sntp_ConvertToUnixTime ---------------------------------------- */

static const uint32_t UNIX_CASES[][ 2 ] = {
    { 0U, 0U },                       /* SNTP era 1 epoch */
    { 1U, 0U },
    { 2208988800U, 0U },              /* exactly the UNIX epoch */
    { 2208988799U, 0U },              /* one second before it, so era 1 */
    { 2208988801U, 0U },
    { 3913056000U, 0U },              /* a 2024-ish time */
    { 4294967295U, 0xFFFFFFFFU },     /* the largest SNTP time */
    { 61505151U, 0U },                /* SNTP_TIME_AT_LARGEST_UNIX_TIME_SECS */
    { 61505152U, 0U },                /* one past it */
    { 2208988800U, 4295U },           /* exactly one microsecond */
    { 2208988800U, 4294U },           /* one tick short of a microsecond */
    { 2208988800U, 0xFFFFFFFFU },     /* the largest fraction */
    { 2208988800U, 0x80000000U },     /* half a second */
};

#define N_UNIX ( sizeof( UNIX_CASES ) / sizeof( UNIX_CASES[ 0 ] ) )

static void run_unix( void )
{
    size_t i;

    for( i = 0; i < N_UNIX; i++ )
    {
        SntpTimestamp_t t;
        uint32_t secs = 0xAAAAAAAAU, micros = 0xAAAAAAAAU;
        SntpStatus_t r;

        t.seconds = UNIX_CASES[ i ][ 0 ];
        t.fractions = UNIX_CASES[ i ][ 1 ];

        printf( "unix %zu in %08x %08x\n", i,
                UNIX_CASES[ i ][ 0 ], UNIX_CASES[ i ][ 1 ] );

        r = Sntp_ConvertToUnixTime( &t, &secs, &micros );

        printf( "unix %zu out %s %u %u\n", i, status_name( r ), secs, micros );
    }
}

/* ---- 5. the fields that must be IGNORED -------------------------------- */

/* Every case above leaves poll, precision, root delay, root dispersion and the
 * reference timestamp at zero, so nothing proved they are ignored rather than
 * merely absent. A parser that accidentally read the reference timestamp as
 * the transmit timestamp would pass every test above.
 *
 * This takes one accepted response and fills those five fields with junk. The
 * parse must come out identical. */
static void run_ignored( void )
{
    static const uint8_t FILLS[] = { 0x00U, 0xFFU, 0x5AU, 0xA5U };
    size_t i;

    for( i = 0; i < ( sizeof( FILLS ) / sizeof( FILLS[ 0 ] ) ); i++ )
    {
        uint8_t packet[ BASE ];
        SntpTimestamp_t req, rx;
        SntpResponseData_t parsed;
        SntpStatus_t r;
        DeserCase_t c;

        memset( &c, 0, sizeof c );
        c.leapVersionMode = OK_LVM;
        c.stratum = 1;
        c.originSec = 1000;
        c.recvSec = 1005;
        c.xmitSec = 1006;
        c.reqSec = 1000;
        c.rxSec = 1002;
        c.bufferSize = BASE;

        build_packet( packet, &c );

        /* poll, precision, root delay, root dispersion, reference timestamp:
         * bytes 2-3, 4-7, 8-11 and 16-23. NOT the reference id at 12-15,
         * which carries the kiss code and is genuinely read. */
        memset( &packet[ 2 ], FILLS[ i ], 10 );
        memset( &packet[ 16 ], FILLS[ i ], 8 );

        req.seconds = c.reqSec;
        req.fractions = c.reqFrac;
        rx.seconds = c.rxSec;
        rx.fractions = c.rxFrac;
        memset( &parsed, 0xAA, sizeof parsed );

        r = Sntp_DeserializeResponse( &req, &rx, packet, c.bufferSize, &parsed );

        printf( "ignored %zu in %02x %08x %08x %08x %08x %zu ", i, FILLS[ i ],
                c.reqSec, c.reqFrac, c.rxSec, c.rxFrac, c.bufferSize );
        put_hex( packet, BASE );
        printf( "\n" );

        printf( "ignored %zu out %s %08x %08x %s %08x %lld\n", i, status_name( r ),
                parsed.serverTime.seconds, parsed.serverTime.fractions,
                leap_name( parsed.leapSecondType ),
                parsed.rejectedResponseCode,
                ( long long ) parsed.clockOffsetMs );
    }
}

int main( void )
{
    printf( "geometry serialize=%zu deser=%zu poll=%zu unix=%zu base=%u\n",
            N_SERIALIZE, N_DESER, N_POLL, N_UNIX, ( unsigned ) BASE );

    run_serialize();
    run_deserialize();
    run_poll();
    run_unix();
    run_ignored();

    printf( "end\n" );
    return 0;
}
