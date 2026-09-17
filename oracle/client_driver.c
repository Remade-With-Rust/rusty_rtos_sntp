/* The C arm of K7's coreSNTP CLIENT differential.
 *
 * `core_sntp_client.c` is compiled VERBATIM out of the pinned checkout;
 * nothing here copies or edits it.
 *
 * # Why this one is different
 *
 * The serializer is a pure function: give it bytes, compare bytes. The client
 * is a STATE MACHINE over five user callbacks -- DNS, get-time, set-time, and
 * a UDP send/receive pair -- and its observable behaviour is not only what it
 * returns but WHICH callbacks it calls, in what order, with what arguments.
 * A transcription that returned the right status while calling the clock a
 * different number of times would be a different library.
 *
 * So every callback is scripted and logged. The mock returns the next entry
 * from a list, and the log line records the arguments it was given. Comparing
 * those logs is the differential; the return status is only its last line.
 *
 * # The trace carries its own scenarios
 *
 * Each scenario begins with `cfg` lines holding the whole setup, so the Rust
 * arm replays the workload rather than keeping a second copy of this file's
 * tables. That is the rule `sntp`'s serializer differential established.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core_sntp_client.h"

#define BASE          SNTP_PACKET_BASE_SIZE
#define MAX_SCRIPT    32
#define MAX_BUFFER    96
#define MAX_SERVERS   4
#define MAX_ACTIONS   8

/* ---- the scripted mocks ------------------------------------------------ */

typedef struct
{
    SntpTimestamp_t clock[ MAX_SCRIPT ];
    size_t clockLen, clockAt;

    struct { bool ok; uint32_t addr; } dns[ MAX_SCRIPT ];
    size_t dnsLen, dnsAt;

    int32_t sendTo[ MAX_SCRIPT ];
    size_t sendToLen, sendToAt;

    struct { int32_t ret; uint8_t packet[ MAX_BUFFER ]; } recv[ MAX_SCRIPT ];
    size_t recvLen, recvAt;

    struct { SntpStatus_t status; uint16_t size; } authGen[ MAX_SCRIPT ];
    size_t authGenLen, authGenAt;

    SntpStatus_t authVal[ MAX_SCRIPT ];
    size_t authValLen, authValAt;
} Mock_t;

static Mock_t mock;

static const char *status_name( SntpStatus_t s )
{
    switch( s )
    {
        case SntpSuccess:                          return "Success";
        case SntpErrorBadParameter:                return "BadParameter";
        case SntpRejectedResponse:                 return "RejectedResponse";
        case SntpRejectedResponseChangeServer:     return "RejectedChangeServer";
        case SntpRejectedResponseRetryWithBackoff: return "RejectedRetryWithBackoff";
        case SntpRejectedResponseOtherCode:        return "RejectedOtherCode";
        case SntpErrorBufferTooSmall:              return "BufferTooSmall";
        case SntpInvalidResponse:                  return "InvalidResponse";
        case SntpZeroPollInterval:                 return "ZeroPollInterval";
        case SntpErrorDnsFailure:                  return "DnsFailure";
        case SntpErrorNetworkFailure:              return "NetworkFailure";
        case SntpServerNotAuthenticated:           return "ServerNotAuthenticated";
        case SntpErrorAuthFailure:                 return "AuthFailure";
        case SntpErrorSendTimeout:                 return "SendTimeout";
        case SntpErrorResponseTimeout:             return "ResponseTimeout";
        case SntpNoResponseReceived:               return "NoResponseReceived";
        case SntpErrorContextNotInitialized:       return "ContextNotInitialized";
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

/* A script that runs out is a scenario that was not written for the number of
 * calls the library actually makes. That is a defect in the WORKLOAD, and it
 * should stop the run rather than quietly return a default. */
static void exhausted( const char *which )
{
    fprintf( stderr, "script exhausted: %s\n", which );
    printf( "SCRIPT-EXHAUSTED %s\n", which );
    fflush( stdout );
    assert( 0 );
}

static void mock_get_time( SntpTimestamp_t *pTime )
{
    if( mock.clockAt >= mock.clockLen )
    {
        exhausted( "clock" );
        return;
    }

    *pTime = mock.clock[ mock.clockAt++ ];
    printf( "call getTime -> %08x:%08x\n", pTime->seconds, pTime->fractions );
}

static void mock_set_time( const SntpServerInfo_t *pServer,
                           const SntpTimestamp_t *pServerTime,
                           int64_t clockOffsetMs,
                           SntpLeapSecondInfo_t leapSecondInfo )
{
    printf( "call setTime %.*s %08x:%08x %lld %s\n",
            ( int ) pServer->serverNameLen, pServer->pServerName,
            pServerTime->seconds, pServerTime->fractions,
            ( long long ) clockOffsetMs, leap_name( leapSecondInfo ) );
}

static bool mock_resolve_dns( const SntpServerInfo_t *pServerAddr, uint32_t *pIpV4Addr )
{
    bool ok;

    if( mock.dnsAt >= mock.dnsLen )
    {
        exhausted( "dns" );
        return false;
    }

    ok = mock.dns[ mock.dnsAt ].ok;
    *pIpV4Addr = mock.dns[ mock.dnsAt ].addr;
    mock.dnsAt++;

    printf( "call dns %.*s -> %d:%08x\n",
            ( int ) pServerAddr->serverNameLen, pServerAddr->pServerName,
            ok ? 1 : 0, *pIpV4Addr );
    return ok;
}

static int32_t mock_send_to( NetworkContext_t *pNetworkContext,
                             uint32_t serverAddr,
                             uint16_t serverPort,
                             const void *pBuffer,
                             uint16_t bytesToSend )
{
    int32_t ret;

    ( void ) pNetworkContext;

    if( mock.sendToAt >= mock.sendToLen )
    {
        exhausted( "sendTo" );
        return -1;
    }

    ret = mock.sendTo[ mock.sendToAt++ ];

    printf( "call sendTo %08x %u %u ", serverAddr, serverPort, bytesToSend );
    put_hex( ( const uint8_t * ) pBuffer, bytesToSend );
    printf( " -> %d\n", ( int ) ret );
    return ret;
}

static int32_t mock_recv_from( NetworkContext_t *pNetworkContext,
                               uint32_t serverAddr,
                               uint16_t serverPort,
                               void *pBuffer,
                               uint16_t bytesToRecv )
{
    int32_t ret;

    ( void ) pNetworkContext;

    if( mock.recvAt >= mock.recvLen )
    {
        exhausted( "recvFrom" );
        return -1;
    }

    ret = mock.recv[ mock.recvAt ].ret;

    /* Only fill the buffer when the mock claims a full read: a transport that
     * reports nothing must not also be writing into the caller's buffer. */
    if( ret == ( int32_t ) bytesToRecv )
    {
        memcpy( pBuffer, mock.recv[ mock.recvAt ].packet, bytesToRecv );
    }

    mock.recvAt++;

    printf( "call recvFrom %08x %u %u -> %d\n",
            serverAddr, serverPort, bytesToRecv, ( int ) ret );
    return ret;
}

static SntpStatus_t mock_generate_auth( SntpAuthContext_t *pContext,
                                        const SntpServerInfo_t *pTimeServer,
                                        void *pBuffer,
                                        size_t bufferSize,
                                        uint16_t *pAuthCodeSize )
{
    SntpStatus_t status;

    ( void ) pContext;
    ( void ) pBuffer;

    if( mock.authGenAt >= mock.authGenLen )
    {
        exhausted( "authGen" );
        return SntpErrorAuthFailure;
    }

    status = mock.authGen[ mock.authGenAt ].status;
    *pAuthCodeSize = mock.authGen[ mock.authGenAt ].size;
    mock.authGenAt++;

    printf( "call authGen %.*s %u -> %s:%u\n",
            ( int ) pTimeServer->serverNameLen, pTimeServer->pServerName,
            ( unsigned ) bufferSize, status_name( status ), *pAuthCodeSize );
    return status;
}

static SntpStatus_t mock_validate_auth( SntpAuthContext_t *pContext,
                                        const SntpServerInfo_t *pTimeServer,
                                        const void *pResponseData,
                                        uint16_t responseSize )
{
    SntpStatus_t status;

    ( void ) pContext;
    ( void ) pResponseData;

    if( mock.authValAt >= mock.authValLen )
    {
        exhausted( "authVal" );
        return SntpErrorAuthFailure;
    }

    status = mock.authVal[ mock.authValAt++ ];

    printf( "call authVal %.*s %u -> %s\n",
            ( int ) pTimeServer->serverNameLen, pTimeServer->pServerName,
            responseSize, status_name( status ) );
    return status;
}

/* ---- scenario description ---------------------------------------------- */

typedef struct
{
    char kind;       /* 's' = send request, 'r' = receive response */
    uint32_t a, b;   /* send: random, blockTime. receive: blockTime */
} Action_t;

typedef struct
{
    const char *name;
    size_t numServers;
    const char *serverNames[ MAX_SERVERS ];
    uint16_t serverPorts[ MAX_SERVERS ];
    size_t bufferSize;
    uint32_t responseTimeoutMs;
    bool useAuth;
    Action_t actions[ MAX_ACTIONS ];
    size_t actionsLen;
    Mock_t script;
} Scenario_t;

static SntpTimestamp_t ts( uint32_t s, uint32_t f )
{
    SntpTimestamp_t t;
    t.seconds = s;
    t.fractions = f;
    return t;
}

/* A well-formed server response echoing `origin`, built into `out`. */
static void build_response( uint8_t *out, uint8_t lvm, uint8_t stratum, uint32_t refId,
                            SntpTimestamp_t origin, SntpTimestamp_t recvT, SntpTimestamp_t xmit )
{
    memset( out, 0, MAX_BUFFER );
    out[ 0 ] = lvm;
    out[ 1 ] = stratum;
    out[ 12 ] = ( uint8_t ) ( refId >> 24 );
    out[ 13 ] = ( uint8_t ) ( refId >> 16 );
    out[ 14 ] = ( uint8_t ) ( refId >> 8 );
    out[ 15 ] = ( uint8_t ) refId;

#define PUT( at, v )                              \
    out[ ( at ) ] = ( uint8_t ) ( ( v ) >> 24 );  \
    out[ ( at ) + 1 ] = ( uint8_t ) ( ( v ) >> 16 ); \
    out[ ( at ) + 2 ] = ( uint8_t ) ( ( v ) >> 8 );  \
    out[ ( at ) + 3 ] = ( uint8_t ) ( v );

    PUT( 24, origin.seconds )
    PUT( 28, origin.fractions )
    PUT( 32, recvT.seconds )
    PUT( 36, recvT.fractions )
    PUT( 40, xmit.seconds )
    PUT( 44, xmit.fractions )
#undef PUT
}

/* ---- printing a scenario's configuration -------------------------------- */

static void print_cfg( const Scenario_t *sc )
{
    size_t i;

    printf( "cfg servers %u", ( unsigned ) sc->numServers );
    for( i = 0; i < sc->numServers; i++ )
    {
        printf( " %s:%u", sc->serverNames[ i ], sc->serverPorts[ i ] );
    }
    printf( "\n" );

    printf( "cfg buffer %u\n", ( unsigned ) sc->bufferSize );
    printf( "cfg timeout %u\n", sc->responseTimeoutMs );
    printf( "cfg auth %s\n", sc->useAuth ? "yes" : "none" );

    printf( "cfg clock %u", ( unsigned ) sc->script.clockLen );
    for( i = 0; i < sc->script.clockLen; i++ )
    {
        printf( " %08x:%08x", sc->script.clock[ i ].seconds, sc->script.clock[ i ].fractions );
    }
    printf( "\n" );

    printf( "cfg dns %u", ( unsigned ) sc->script.dnsLen );
    for( i = 0; i < sc->script.dnsLen; i++ )
    {
        printf( " %d:%08x", sc->script.dns[ i ].ok ? 1 : 0, sc->script.dns[ i ].addr );
    }
    printf( "\n" );

    printf( "cfg sendto %u", ( unsigned ) sc->script.sendToLen );
    for( i = 0; i < sc->script.sendToLen; i++ )
    {
        printf( " %d", ( int ) sc->script.sendTo[ i ] );
    }
    printf( "\n" );

    printf( "cfg recv %u", ( unsigned ) sc->script.recvLen );
    for( i = 0; i < sc->script.recvLen; i++ )
    {
        printf( " %d:", ( int ) sc->script.recv[ i ].ret );
        put_hex( sc->script.recv[ i ].packet, MAX_BUFFER );  /* the WHOLE buffer: an auth scenario exchanges more than BASE bytes, and a trace that implies zero padding is a trace the other arm has to guess at */
    }
    printf( "\n" );

    printf( "cfg authgen %u", ( unsigned ) sc->script.authGenLen );
    for( i = 0; i < sc->script.authGenLen; i++ )
    {
        printf( " %s:%u", status_name( sc->script.authGen[ i ].status ),
                sc->script.authGen[ i ].size );
    }
    printf( "\n" );

    printf( "cfg authval %u", ( unsigned ) sc->script.authValLen );
    for( i = 0; i < sc->script.authValLen; i++ )
    {
        printf( " %s", status_name( sc->script.authVal[ i ] ) );
    }
    printf( "\n" );

    printf( "cfg actions %u", ( unsigned ) sc->actionsLen );
    for( i = 0; i < sc->actionsLen; i++ )
    {
        printf( " %c:%u:%u", sc->actions[ i ].kind, sc->actions[ i ].a, sc->actions[ i ].b );
    }
    printf( "\n" );
}

/* ---- running a scenario -------------------------------------------------- */

static void run_scenario( size_t id, const Scenario_t *sc )
{
    SntpContext_t context;
    SntpServerInfo_t servers[ MAX_SERVERS ];
    static uint8_t buffer[ MAX_BUFFER ];
    UdpTransportInterface_t transport;
    SntpAuthenticationInterface_t auth;
    SntpStatus_t status;
    size_t i;

    printf( "scenario %u %s\n", ( unsigned ) id, sc->name );
    print_cfg( sc );

    mock = sc->script;

    for( i = 0; i < sc->numServers; i++ )
    {
        servers[ i ].pServerName = sc->serverNames[ i ];
        servers[ i ].serverNameLen = strlen( sc->serverNames[ i ] );
        servers[ i ].port = sc->serverPorts[ i ];
    }

    memset( buffer, 0, sizeof buffer );

    transport.pUserContext = NULL;
    transport.sendTo = mock_send_to;
    transport.recvFrom = mock_recv_from;

    auth.pAuthContext = NULL;
    auth.generateClientAuth = mock_generate_auth;
    auth.validateServerAuth = mock_validate_auth;

    status = Sntp_Init( &context, servers, sc->numServers, sc->responseTimeoutMs,
                        buffer, sc->bufferSize, mock_resolve_dns,
                        mock_get_time, mock_set_time, &transport,
                        sc->useAuth ? &auth : NULL );

    printf( "init -> %s\n", status_name( status ) );

    if( status != SntpSuccess )
    {
        printf( "end scenario %u\n", ( unsigned ) id );
        return;
    }

    for( i = 0; i < sc->actionsLen; i++ )
    {
        if( sc->actions[ i ].kind == 's' )
        {
            status = Sntp_SendTimeRequest( &context, sc->actions[ i ].a, sc->actions[ i ].b );
            printf( "action %u s -> %s\n", ( unsigned ) i, status_name( status ) );
        }
        else
        {
            status = Sntp_ReceiveTimeResponse( &context, sc->actions[ i ].b );
            printf( "action %u r -> %s\n", ( unsigned ) i, status_name( status ) );
        }

        /* The context state after every action. A state machine's observable
         * behaviour includes where it left itself. */
        printf( "state %u %08x:%08x %u %08x\n",
                ( unsigned ) context.currentServerIndex,
                context.lastRequestTime.seconds, context.lastRequestTime.fractions,
                context.sntpPacketSize, context.currentServerAddr );
    }

    printf( "end scenario %u\n", ( unsigned ) id );
}

/* ---- the scenarios ------------------------------------------------------- */

static Scenario_t sc;

static void reset( const char *name )
{
    memset( &sc, 0, sizeof sc );
    sc.name = name;
    sc.numServers = 1;
    sc.serverNames[ 0 ] = "a.pool";
    sc.serverPorts[ 0 ] = 123;
    sc.bufferSize = BASE;
    sc.responseTimeoutMs = 5000;
    sc.useAuth = false;
}

static void clock_push( SntpTimestamp_t t )
{
    sc.script.clock[ sc.script.clockLen++ ] = t;
}

static void dns_push( bool ok, uint32_t addr )
{
    sc.script.dns[ sc.script.dnsLen ].ok = ok;
    sc.script.dns[ sc.script.dnsLen ].addr = addr;
    sc.script.dnsLen++;
}

static void send_push( int32_t v )
{
    sc.script.sendTo[ sc.script.sendToLen++ ] = v;
}

static void recv_push( int32_t ret, const uint8_t *packet )
{
    sc.script.recv[ sc.script.recvLen ].ret = ret;
    if( packet != NULL )
    {
        memcpy( sc.script.recv[ sc.script.recvLen ].packet, packet, MAX_BUFFER );
    }
    sc.script.recvLen++;
}

static void act_send( uint32_t random, uint32_t blockMs )
{
    sc.actions[ sc.actionsLen ].kind = 's';
    sc.actions[ sc.actionsLen ].a = random;
    sc.actions[ sc.actionsLen ].b = blockMs;
    sc.actionsLen++;
}

static void act_recv( uint32_t blockMs )
{
    sc.actions[ sc.actionsLen ].kind = 'r';
    sc.actions[ sc.actionsLen ].a = 0;
    sc.actions[ sc.actionsLen ].b = blockMs;
    sc.actionsLen++;
}

int main( void )
{
    size_t id = 0;
    uint8_t packet[ MAX_BUFFER ];

    /* The request timestamp the library will produce: the clock's first
     * reading, with the random number's top 16 bits OR-ed into the fractions.
     * Every scenario that needs a VALID response has to echo exactly that. */
    SntpTimestamp_t req = ts( 0xE7E1F4C8U, 0x00001234U );

    printf( "geometry base=%u maxbuffer=%u\n", ( unsigned ) BASE, ( unsigned ) MAX_BUFFER );

    /* 1. the happy path */
    reset( "happy-path" );
    clock_push( ts( 0xE7E1F4C8U, 0x00000000U ) );   /* request time */
    clock_push( ts( 0xE7E1F4C8U, 0x00000000U ) );   /* send retry base */
    clock_push( ts( 0xE7E1F4C9U, 0x00000000U ) );   /* receive start */
    clock_push( ts( 0xE7E1F4CAU, 0x00000000U ) );   /* response rx time */
    dns_push( true, 0x0A000001U );
    send_push( BASE );
    build_response( packet, 0x24U, 1, 0, req, ts( 0xE7E1F4C9U, 0 ), ts( 0xE7E1F4C9U, 0x40000000U ) );
    recv_push( BASE, packet );
    act_send( 0x12340000U, 1000 );
    act_recv( 1000 );
    run_scenario( id++, &sc );

    /* 2. DNS refuses */
    reset( "dns-failure" );
    dns_push( false, 0 );
    act_send( 0x12340000U, 1000 );
    run_scenario( id++, &sc );

    /* 3. the transport reports an error on send */
    reset( "send-error" );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    dns_push( true, 0x0A000001U );
    send_push( -1 );
    act_send( 0x12340000U, 1000 );
    run_scenario( id++, &sc );

    /* 4. send moves nothing, twice, then succeeds: the retry loop works */
    reset( "send-retries-then-succeeds" );
    clock_push( ts( 100, 0 ) );        /* request time */
    clock_push( ts( 100, 0 ) );        /* retry window base */
    clock_push( ts( 100, 0x20000000U ) ); /* after the first zero send */
    clock_push( ts( 100, 0x40000000U ) ); /* after the second */
    dns_push( true, 0x0A000001U );
    send_push( 0 );
    send_push( 0 );
    send_push( BASE );
    act_send( 0x12340000U, 5000 );
    run_scenario( id++, &sc );

    /* 5. send moves nothing until the block time expires */
    reset( "send-times-out" );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 102, 0 ) );        /* 2000 ms later, past a 1000 ms block */
    dns_push( true, 0x0A000001U );
    send_push( 0 );
    act_send( 0x12340000U, 1000 );
    run_scenario( id++, &sc );

    /* 6. a partial send, which UDP cannot do */
    reset( "send-partial" );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    dns_push( true, 0x0A000001U );
    send_push( BASE - 1 );
    act_send( 0x12340000U, 1000 );
    run_scenario( id++, &sc );

    /* 7. nothing arrives, and the block time expires before the response
     *    timeout: NoResponseReceived, and the server is NOT rotated */
    reset( "receive-blocks-then-gives-up" );
    clock_push( ts( 100, 0 ) );        /* request time */
    clock_push( ts( 100, 0 ) );        /* send retry base */
    clock_push( ts( 100, 0 ) );        /* read start */
    clock_push( ts( 101, 0 ) );        /* after the first empty read: 1000 ms */
    dns_push( true, 0x0A000001U );
    send_push( BASE );
    recv_push( 0, NULL );
    act_send( 0x12340000U, 1000 );
    act_recv( 500 );                   /* block time 500 ms, timeout 5000 ms */
    run_scenario( id++, &sc );

    /* 8. nothing arrives until the RESPONSE timeout: rotate the server */
    reset( "receive-times-out-and-rotates" );
    sc.numServers = 2;
    sc.serverNames[ 1 ] = "b.pool";
    sc.serverPorts[ 1 ] = 123;
    sc.responseTimeoutMs = 1000;
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 102, 0 ) );        /* 2000 ms since the request */
    dns_push( true, 0x0A000001U );
    send_push( BASE );
    recv_push( 0, NULL );
    act_send( 0x12340000U, 1000 );
    act_recv( 5000 );
    run_scenario( id++, &sc );

    /* 9. the transport reports an error on receive */
    reset( "receive-error" );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    dns_push( true, 0x0A000001U );
    send_push( BASE );
    recv_push( -1, NULL );
    act_send( 0x12340000U, 1000 );
    act_recv( 1000 );
    run_scenario( id++, &sc );

    /* 10. a partial receive */
    reset( "receive-partial" );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    dns_push( true, 0x0A000001U );
    send_push( BASE );
    recv_push( BASE - 1, NULL );
    act_send( 0x12340000U, 1000 );
    act_recv( 1000 );
    run_scenario( id++, &sc );

    /* 11. a Kiss-o'-Death with NO authentication interface.
     *     The last request time must NOT be cleared -- clearing it would let
     *     an attacker who spoofs a rejection cause the real response to be
     *     discarded, which is a denial of service. */
    reset( "kod-without-auth-keeps-request-time" );
    sc.numServers = 2;
    sc.serverNames[ 1 ] = "b.pool";
    sc.serverPorts[ 1 ] = 123;
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 101, 0 ) );
    dns_push( true, 0x0A000001U );
    send_push( BASE );
    build_response( packet, 0x24U, 0, 0x44454E59U, ts( 100, 0x00001234U ), ts( 100, 0 ), ts( 100, 0 ) );
    recv_push( BASE, packet );
    act_send( 0x12340000U, 1000 );
    act_recv( 1000 );
    run_scenario( id++, &sc );

    /* 12. a response whose originate field does not echo the request */
    reset( "response-does-not-echo-the-request" );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 101, 0 ) );
    dns_push( true, 0x0A000001U );
    send_push( BASE );
    build_response( packet, 0x24U, 1, 0, ts( 999, 999 ), ts( 100, 0 ), ts( 100, 0 ) );
    recv_push( BASE, packet );
    act_send( 0x12340000U, 1000 );
    act_recv( 1000 );
    run_scenario( id++, &sc );

    /* 13. authentication configured, and the generator fails */
    reset( "auth-generate-fails" );
    sc.useAuth = true;
    sc.bufferSize = 64;
    clock_push( ts( 100, 0 ) );
    dns_push( true, 0x0A000001U );
    sc.script.authGen[ 0 ].status = SntpErrorAuthFailure;
    sc.script.authGen[ 0 ].size = 0;
    sc.script.authGenLen = 1;
    act_send( 0x12340000U, 1000 );
    run_scenario( id++, &sc );

    /* 14. authentication data that does not fit the remaining buffer */
    reset( "auth-code-too-large" );
    sc.useAuth = true;
    sc.bufferSize = 64;                /* 16 bytes spare after the 48-byte packet */
    clock_push( ts( 100, 0 ) );
    dns_push( true, 0x0A000001U );
    sc.script.authGen[ 0 ].status = SntpSuccess;
    sc.script.authGen[ 0 ].size = 17;  /* one more than fits */
    sc.script.authGenLen = 1;
    act_send( 0x12340000U, 1000 );
    run_scenario( id++, &sc );

    /* 15. authentication succeeds: the packet size GROWS, and the same size is
     *     then expected from the server */
    reset( "auth-grows-the-packet" );
    sc.useAuth = true;
    sc.bufferSize = 64;
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 101, 0 ) );
    dns_push( true, 0x0A000001U );
    sc.script.authGen[ 0 ].status = SntpSuccess;
    sc.script.authGen[ 0 ].size = 16;
    sc.script.authGenLen = 1;
    send_push( BASE + 16 );
    build_response( packet, 0x24U, 1, 0, ts( 100, 0x00001234U ), ts( 100, 0x40000000U ), ts( 100, 0x80000000U ) );
    recv_push( BASE + 16, packet );
    sc.script.authVal[ 0 ] = SntpSuccess;
    sc.script.authValLen = 1;
    act_send( 0x12340000U, 1000 );
    act_recv( 1000 );
    run_scenario( id++, &sc );

    /* 16. the server fails authentication */
    reset( "server-not-authenticated" );
    sc.useAuth = true;
    sc.bufferSize = 64;
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 101, 0 ) );
    dns_push( true, 0x0A000001U );
    sc.script.authGen[ 0 ].status = SntpSuccess;
    sc.script.authGen[ 0 ].size = 16;
    sc.script.authGenLen = 1;
    send_push( BASE + 16 );
    build_response( packet, 0x24U, 1, 0, ts( 100, 0x00001234U ), ts( 100, 0 ), ts( 100, 0 ) );
    recv_push( BASE + 16, packet );
    sc.script.authVal[ 0 ] = SntpServerNotAuthenticated;
    sc.script.authValLen = 1;
    act_send( 0x12340000U, 1000 );
    act_recv( 1000 );
    run_scenario( id++, &sc );

    /* 17. a Kiss-o'-Death WITH authentication configured.
     *     Here the last request time IS cleared, because an authenticated
     *     rejection came from the real server. This is the mirror of 11 and
     *     the pair is the whole point. */
    reset( "kod-with-auth-clears-request-time" );
    sc.useAuth = true;
    sc.bufferSize = 64;
    sc.numServers = 2;
    sc.serverNames[ 1 ] = "b.pool";
    sc.serverPorts[ 1 ] = 123;
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 100, 0 ) );
    clock_push( ts( 101, 0 ) );
    dns_push( true, 0x0A000001U );
    sc.script.authGen[ 0 ].status = SntpSuccess;
    sc.script.authGen[ 0 ].size = 16;
    sc.script.authGenLen = 1;
    send_push( BASE + 16 );
    build_response( packet, 0x24U, 0, 0x52415445U, ts( 100, 0x00001234U ), ts( 100, 0 ), ts( 100, 0 ) );
    recv_push( BASE + 16, packet );
    sc.script.authVal[ 0 ] = SntpSuccess;
    sc.script.authValLen = 1;
    act_send( 0x12340000U, 1000 );
    act_recv( 1000 );
    run_scenario( id++, &sc );

    /* 18. Sntp_Init refuses a buffer under the base packet size */
    reset( "init-buffer-too-small" );
    sc.bufferSize = BASE - 1;
    run_scenario( id++, &sc );

    /* 19. Sntp_Init refuses an empty server list */
    reset( "init-no-servers" );
    sc.numServers = 0;
    run_scenario( id++, &sc );

    /* 20. server rotation WRAPS around the list rather than running out */
    reset( "rotation-wraps-around" );
    sc.numServers = 2;
    sc.serverNames[ 1 ] = "b.pool";
    sc.serverPorts[ 1 ] = 123;
    sc.responseTimeoutMs = 1000;
    {
        int k;
        for( k = 0; k < 3; k++ )
        {
            clock_push( ts( 100, 0 ) );    /* request */
            clock_push( ts( 100, 0 ) );    /* send base */
            clock_push( ts( 100, 0 ) );    /* read start */
            clock_push( ts( 102, 0 ) );    /* past the response timeout */
            dns_push( true, 0x0A000001U + ( uint32_t ) k );
            send_push( BASE );
            recv_push( 0, NULL );
            act_send( 0x12340000U, 1000 );
            act_recv( 5000 );
        }
    }
    run_scenario( id++, &sc );

    /* 21. the elapsed-time helper across the 2036 wrap: the request goes out
     *     in era 0 and the clock is read in era 1 */
    reset( "elapsed-time-across-the-era-wrap" );
    sc.responseTimeoutMs = 1000;
    clock_push( ts( 0xFFFFFFFEU, 0 ) );    /* request time, just before the wrap */
    clock_push( ts( 0xFFFFFFFEU, 0 ) );    /* send base */
    clock_push( ts( 0xFFFFFFFEU, 0 ) );    /* read start */
    clock_push( ts( 0x00000001U, 0 ) );    /* wrapped: 3 seconds later, not -136 years */
    dns_push( true, 0x0A000001U );
    send_push( BASE );
    recv_push( 0, NULL );
    act_send( 0x12340000U, 1000 );
    act_recv( 5000 );
    run_scenario( id++, &sc );

    /* 22. the fractions branch of the elapsed-time helper, where the newer
     *     timestamp has SMALLER fractions than the older one within the same
     *     second. The C subtracts on an unsigned value that is still zero. */
    reset( "elapsed-time-fractions-go-backwards" );
    sc.responseTimeoutMs = 1000;
    clock_push( ts( 100, 0x80000000U ) );  /* request time */
    clock_push( ts( 100, 0x80000000U ) );  /* send base */
    clock_push( ts( 100, 0x80000000U ) );  /* read start */
    clock_push( ts( 100, 0x00000000U ) );  /* EARLIER fractions, same second */
    dns_push( true, 0x0A000001U );
    send_push( BASE );
    recv_push( 0, NULL );
    act_send( 0x12340000U, 1000 );
    act_recv( 5000 );
    run_scenario( id++, &sc );

    /* 23. A SECOND authenticated request whose authentication FAILS.
     *     The C never resets sntpPacketSize in Sntp_SendTimeRequest -- only
     *     addClientAuthentication assigns it -- so a failed generation leaves
     *     the PREVIOUS size in place. Nothing else here sends two authenticated
     *     requests, so without this scenario a transcription that helpfully
     *     reset the size first would pass every test and still be wrong. */
    reset( "auth-failure-keeps-the-previous-packet-size" );
    sc.useAuth = true;
    sc.bufferSize = 64;
    clock_push( ts( 100, 0 ) );        /* request time, first send */
    clock_push( ts( 100, 0 ) );        /* send retry base */
    clock_push( ts( 101, 0 ) );        /* request time, second send */
    dns_push( true, 0x0A000001U );
    dns_push( true, 0x0A000001U );
    sc.script.authGen[ 0 ].status = SntpSuccess;
    sc.script.authGen[ 0 ].size = 16;
    sc.script.authGen[ 1 ].status = SntpErrorAuthFailure;
    sc.script.authGen[ 1 ].size = 0;
    sc.script.authGenLen = 2;
    send_push( BASE + 16 );
    act_send( 0x12340000U, 1000 );
    act_send( 0x12340000U, 1000 );
    run_scenario( id++, &sc );

    printf( "end\n" );
    return 0;
}
