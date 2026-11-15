/*
* Copyright (c) 2026 Marc E. Fiuczynski
* Based on QUICast by Max Franke.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
* Multicast QUIC receiver and minimal sender (draft-jholland-quic-multicast-08, the
* frame-based channel model, as implemented by QUICast quiche).
*
* Scope: DATAGRAM channels only. The sender API is described below. The client advertises the
* multicast_client_params transport parameter, handles the server's MC_*
* control frames on the unicast connection, and sends MC_LIMITS, MC_STATE and
* MC_ACK. Channel packets arrive on a socket owned either by picoquic's packet
* loop (picoquic_mcquic_loop_config(), below) or by the application, and go to
* picoquic_incoming_multicast_packet(). A channel packet is
* released only after its hash, received in an MC_INTEGRITY frame over the
* unicast connection, matches; its DATAGRAM frames are then delivered with the
* picoquic_callback_mc_datagram event. Channel plaintext never goes through
* picoquic_decode_frames(): channel packet numbers are a separate space.
*
* The wire format is draft-08's, as implemented by quiche, since
* interoperability is the goal. Where draft-09 changes it, the change is
* noted next to the code concerned.
*/

#ifndef PICOQUIC_MCQUIC_H
#define PICOQUIC_MCQUIC_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "picoquic.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Experimental code points (draft-08; draft-09 uses the same values) */
#define PICOQUIC_MCQUIC_TP_CLIENT_PARAMS 0xff3e800
#define PICOQUIC_MCQUIC_TP_SERVER_SUPPORT 0xff3e808

#define PICOQUIC_MCQUIC_FRAME_KEY 0xff3e801
#define PICOQUIC_MCQUIC_FRAME_JOIN 0xff3e802
#define PICOQUIC_MCQUIC_FRAME_LEAVE 0xff3e803
#define PICOQUIC_MCQUIC_FRAME_INTEGRITY 0xff3e804
#define PICOQUIC_MCQUIC_FRAME_INTEGRITY_LEN 0xff3e805
#define PICOQUIC_MCQUIC_FRAME_ACK 0xff3e806
#define PICOQUIC_MCQUIC_FRAME_ACK_ECN 0xff3e807
#define PICOQUIC_MCQUIC_FRAME_LIMITS 0xff3e809
#define PICOQUIC_MCQUIC_FRAME_RETIRE 0xff3e80a
#define PICOQUIC_MCQUIC_FRAME_STATE 0xff3e80b
#define PICOQUIC_MCQUIC_FRAME_STATE_APP 0xff3e80c
#define PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V4 0xff3e811
#define PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V6 0xff3e812

#define PICOQUIC_MCQUIC_STATE_LEFT 1
#define PICOQUIC_MCQUIC_STATE_DECLINED_JOIN 2
#define PICOQUIC_MCQUIC_STATE_JOINED 3
#define PICOQUIC_MCQUIC_STATE_RETIRED 4

#define PICOQUIC_MCQUIC_REASON_UNSPECIFIED 0
#define PICOQUIC_MCQUIC_REASON_REQUESTED_BY_SERVER 1
#define PICOQUIC_MCQUIC_REASON_ADMINISTRATIVE_BLOCK 2
#define PICOQUIC_MCQUIC_REASON_UNSYNCHRONIZED_PROPERTIES 5

/* Integrity hash algorithm identifiers (Named Information Hash Algorithm registry) */
#define PICOQUIC_MCQUIC_HASH_SHA256 1
#define PICOQUIC_MCQUIC_HASH_SHA256_128 2
#define PICOQUIC_MCQUIC_HASH_SHA256_120 3
#define PICOQUIC_MCQUIC_HASH_SHA256_96 4
#define PICOQUIC_MCQUIC_HASH_SHA256_64 5
#define PICOQUIC_MCQUIC_HASH_SHA256_32 6
#define PICOQUIC_MCQUIC_HASH_SHA384 7
#define PICOQUIC_MCQUIC_HASH_SHA512 8

#define PICOQUIC_MCQUIC_CHANNEL_ID_MAX 20
#define PICOQUIC_MCQUIC_SECRET_MAX 64
#define PICOQUIC_MCQUIC_HASH_MAX 64
/* Release delay histogram: 100 us buckets up to 100 ms, then 1 ms buckets up to
 * 2 s; the last one collects 2 s and more */
#define PICOQUIC_MCQUIC_DELAY_BUCKETS 2901
#define PICOQUIC_MCQUIC_ALGS_MAX 8
#define PICOQUIC_MCQUIC_PN_LENGTH 4

typedef struct st_picoquic_mcquic_channel_id_t {
    uint8_t id_len;
    uint8_t id[PICOQUIC_MCQUIC_CHANNEL_ID_MAX];
} picoquic_mcquic_channel_id_t;

/* Value of the multicast_client_params transport parameter, as in draft-08 (and
 * quiche): the flags, the rate, the channel ID limit and the two algorithm
 * lists. draft-09 changes this, adding Max Joined Count after Max Channel IDs.
 * Max Joined Count is carried only in MC_LIMITS here, as in draft-08. */
typedef struct st_picoquic_mcquic_client_params_t {
    int ipv4_allowed;
    int ipv6_allowed;
    uint64_t max_rate_kibps;
    uint64_t max_channel_ids;
    uint64_t max_joined; /* sent in MC_LIMITS */
    size_t nb_hash_algs;
    uint16_t hash_algs[PICOQUIC_MCQUIC_ALGS_MAX];
    size_t nb_cipher_suites;
    uint16_t cipher_suites[PICOQUIC_MCQUIC_ALGS_MAX];
} picoquic_mcquic_client_params_t;

/* A decoded MC_* frame. Variable-length fields of the integrity, ACK and state
 * frames point into the decoded buffer. */
typedef struct st_picoquic_mcquic_frame_t {
    uint64_t frame_type;
    picoquic_mcquic_channel_id_t channel_id;
    union {
        struct {
            int is_ipv6;
            uint8_t source[16];
            uint8_t group[16];
            uint16_t port;
            uint16_t header_protection_alg;
            size_t header_secret_len;
            uint8_t header_secret[PICOQUIC_MCQUIC_SECRET_MAX];
            uint16_t aead_alg;
            uint16_t hash_alg;
            uint64_t max_rate_kibps;
            uint64_t max_ack_delay_ms;
        } announce;
        struct {
            uint64_t key_sequence;
            uint64_t from_packet_number;
            size_t secret_len;
            uint8_t secret[PICOQUIC_MCQUIC_SECRET_MAX];
        } key;
        struct {
            uint64_t limits_sequence;
            uint64_t state_sequence;
            uint64_t key_sequence;
        } join;
        struct {
            uint64_t state_sequence;
            uint64_t after_packet_number;
        } leave;
        struct {
            uint64_t packet_number_start;
            int has_count;
            uint64_t hash_count;
            const uint8_t* hashes;
            size_t hashes_length;
        } integrity;
        struct {
            uint64_t largest;
            uint64_t ack_delay;
            uint64_t range_count;
            uint64_t first_range;
            const uint8_t* ranges; /* range_count (gap, length) varint pairs */
            size_t ranges_length;
            int has_ecn;
            uint64_t ecn[3];
        } ack;
        struct {
            uint64_t sequence;
            int ipv4_allowed;
            int ipv6_allowed;
            uint64_t max_rate_kibps;
            uint64_t max_channel_ids;
            uint64_t max_joined;
        } limits;
        struct {
            uint64_t after_packet_number;
        } retire;
        struct {
            uint64_t sequence;
            uint8_t state;
            uint64_t reason;
            const uint8_t* phrase;
            size_t phrase_length;
        } state;
    } u;
} picoquic_mcquic_frame_t;

/* Channel description passed with the join and leave events */
typedef struct st_picoquic_mcquic_channel_info_t {
    picoquic_mcquic_channel_id_t channel_id;
    int is_ipv6;
    uint8_t source[16];
    uint8_t group[16];
    uint16_t port;
    uint64_t max_rate_kibps;
} picoquic_mcquic_channel_info_t;

typedef struct st_picoquic_mcquic_stats_t {
    uint64_t packets_received;
    uint64_t packets_duplicate;
    uint64_t packets_buffered;
    uint64_t packets_evicted;
    uint64_t packets_released;
    uint64_t integrity_hashes;
    uint64_t integrity_failures;
    uint64_t header_failures;
    uint64_t decrypt_failures;
    uint64_t no_key;
    uint64_t unsupported_frames;
    uint64_t datagrams;
    uint64_t acks_sent;
    uint64_t largest_released;
    uint64_t integrity_frames;
    uint64_t integrity_bytes; /* MC_INTEGRITY frame bytes, type included */
    uint64_t test_dropped; /* channel packets dropped by picoquic_mcquic_set_ack_policy's test_drop */
    uint64_t ack_bytes; /* MC_ACK frame bytes, type included */
    uint64_t ack_ranges_max; /* most ACK ranges in one MC_ACK */
    uint64_t ack_window; /* packet numbers the receiver currently tracks */
    /* Time from a channel packet's arrival to its release, by bucket */
    uint32_t release_delay[PICOQUIC_MCQUIC_DELAY_BUCKETS];
} picoquic_mcquic_stats_t;

/* Transport parameter value codec */
uint8_t* picoquic_mcquic_client_params_encode(uint8_t* bytes, const uint8_t* bytes_max, const picoquic_mcquic_client_params_t* params);
const uint8_t* picoquic_mcquic_client_params_decode(const uint8_t* bytes, const uint8_t* bytes_max, picoquic_mcquic_client_params_t* params);

/* Frame codec. Decode starts after the frame type. hash_length is the integrity
 * hash length of the channel, needed to size MC_INTEGRITY frames that carry a
 * hash count; 0 if unknown. Encode writes the frame type. */
int picoquic_mcquic_is_frame_type(uint64_t frame_type);
const uint8_t* picoquic_mcquic_frame_decode(const uint8_t* bytes, const uint8_t* bytes_max, uint64_t frame_type,
    size_t hash_length, picoquic_mcquic_frame_t* frame);
uint8_t* picoquic_mcquic_frame_encode(uint8_t* bytes, const uint8_t* bytes_max, const picoquic_mcquic_frame_t* frame);
const uint8_t* picoquic_mcquic_frame_skip(const uint8_t* bytes, const uint8_t* bytes_max, uint64_t frame_type, int* pure_ack);

/* Channel packet protection. The secrets are used as HKDF pseudo-random keys
 * as they come, whatever their length ("quic key", "quic iv" from the MC_KEY
 * secret, "quic hp" from the MC_ANNOUNCE header secret). */
size_t picoquic_mcquic_hash_length(uint16_t hash_alg);
int picoquic_mcquic_integrity_hash(uint16_t hash_alg, const uint8_t* bytes, size_t length, uint8_t* hash, size_t hash_max);
int picoquic_mcquic_derive(uint16_t cipher_suite_id, const uint8_t* secret, size_t secret_length, const char* label,
    uint8_t* out, size_t out_length);
void* picoquic_mcquic_hp_create(uint16_t cipher_suite_id, const uint8_t* header_secret, size_t secret_length);
void* picoquic_mcquic_aead_create(uint16_t cipher_suite_id, const uint8_t* secret, size_t secret_length);
/* Removes header protection. Returns the header length (1 + channel ID + 4), 0 on error.
 * header receives the unprotected header, first_byte the unprotected first byte. */
size_t picoquic_mcquic_unprotect_header(void* hp_ctx, const uint8_t* bytes, size_t length, size_t channel_id_length,
    uint64_t expected_pn, uint8_t* header, uint64_t* pn);
/* Decrypts the payload after an unprotected header. Returns the plaintext length, or SIZE_MAX. */
size_t picoquic_mcquic_decrypt(void* aead_ctx, const uint8_t* bytes, size_t length, const uint8_t* header,
    size_t header_length, uint64_t pn, uint8_t* plaintext);

/* Receiver API.
 * Enable the client capability on a connection before starting it. The library
 * then reports, through the connection callback:
 *   picoquic_callback_mc_join: the server asks to join a channel. bytes points to a
 *       picoquic_mcquic_channel_info_t. The application joins (S,G) on its own
 *       socket and returns 0, or returns non-zero to decline.
 *   picoquic_callback_mc_leave: the channel was left or retired (same argument).
 *   picoquic_callback_mc_datagram: an authenticated DATAGRAM frame from a channel.
 *       stream_id is the channel packet number; v_stream_ctx points to the
 *       picoquic_mcquic_channel_id_t of the channel.
 */
int picoquic_mcquic_enable_client(picoquic_cnx_t* cnx, const picoquic_mcquic_client_params_t* params);
void picoquic_mcquic_set_default_client_params(picoquic_mcquic_client_params_t* params);
int picoquic_incoming_multicast_packet(picoquic_quic_t* quic, const uint8_t* bytes, size_t length,
    const struct sockaddr* addr_from, uint64_t current_time);
/* Sends MC_ACK frames that are due, or all pending ones if force is set. */
void picoquic_mcquic_send_acks(picoquic_cnx_t* cnx, uint64_t current_time, int force);
/* MC_ACK scheduling on a receiving connection.
 * jitter (default 1): each MC_ACK is sent at a time drawn uniformly in
 *   [0.5, 1.0] x Max ACK Delay after the previous one, re-drawn every interval,
 *   so that clients do not acknowledge in step. 0: the previous behaviour, one
 *   MC_ACK each Max ACK Delay after the last one.
 * jitter_first (default 1, used with jitter): the first MC_ACK of a channel is
 *   drawn uniformly in [0, 1.0] x Max ACK Delay after its first packet. draft-08
 *   10.1 says clients SHOULD NOT delay it; 0 sends it at once.
 * test_drop: fraction of channel packets dropped at random before processing,
 *   for tests (0 = none).
 * The ACK record keeps at least 2 x packet rate x Max ACK Delay packet numbers
 * (and at least 4096), and as many ranges as fit one MC_ACK in a 1-RTT packet
 * on the path. */
typedef struct st_picoquic_mcquic_ack_policy_t {
    int jitter;
    int jitter_first;
    double test_drop;
} picoquic_mcquic_ack_policy_t;
int picoquic_mcquic_set_ack_policy(picoquic_cnx_t* cnx, const picoquic_mcquic_ack_policy_t* policy);
int picoquic_mcquic_get_ack_policy(picoquic_cnx_t* cnx, picoquic_mcquic_ack_policy_t* policy);
/* Logs control events (MC_ANNOUNCE, MC_KEY, MC_JOIN, MC_LIMITS, MC_STATE, failures) to f; NULL to stop. */
void picoquic_mcquic_set_log(picoquic_cnx_t* cnx, FILE* f);
int picoquic_mcquic_get_stats(picoquic_cnx_t* cnx, const picoquic_mcquic_channel_id_t* channel_id,
    picoquic_mcquic_stats_t* stats);
/* Number of (gap, length) pairs, newest first, whose varints fit in budget
 * bytes: the rule the receiver applies when it builds an MC_ACK. */
size_t picoquic_mcquic_ack_ranges_fit(size_t budget, const uint64_t* gaps_lengths, size_t nb_pairs);
/* Upper bound, in microseconds, of a release delay histogram bucket */
uint64_t picoquic_mcquic_delay_bucket_limit(size_t bucket);

/* Sender API (one channel, one static key, IPv4, DATAGRAM channels).
 * picoquic_mcquic_sender_create() attaches the sender to a server QUIC context.
 * Connections whose client sends multicast_client_params then get the empty
 * multicast_server_support parameter. When such a connection is ready, the
 * application calls picoquic_mcquic_server_start(), which sends MC_ANNOUNCE and
 * MC_KEY; MC_JOIN follows the client's MC_LIMITS, as in the QUICast example
 * server. picoquic_mcquic_sender_prepare() builds the next channel packet around
 * one DATAGRAM frame, for the application to send to (S,G), and queues its
 * MC_INTEGRITY on every connection whose client reported Joined. MC_ACKs are
 * counted and logged; there is no multicast retransmission. */
typedef struct st_picoquic_mcquic_sender_config_t {
    picoquic_mcquic_channel_id_t channel_id;
    uint8_t source[4];
    uint8_t group[4];
    uint16_t port;
    uint16_t cipher_suite; /* used for both header protection and the AEAD */
    uint16_t hash_alg;
    size_t header_secret_len;
    uint8_t header_secret[PICOQUIC_MCQUIC_SECRET_MAX];
    uint64_t key_sequence;
    uint64_t from_pn;
    size_t key_secret_len;
    uint8_t key_secret[PICOQUIC_MCQUIC_SECRET_MAX];
    uint64_t max_rate_kibps;
    uint64_t max_ack_delay_ms;
} picoquic_mcquic_sender_config_t;

/* MC_ACKs received from one client (server side) */
typedef struct st_picoquic_mcquic_client_ack_stats_t {
    uint64_t client_index; /* order in which the sender saw the connections, from 1 */
    uint16_t hash_alg; /* integrity hash announced to this client, 0 if not announced */
    uint64_t acks;
    uint64_t ack_bytes; /* MC_ACK frame bytes, type included */
    uint64_t ranges_max; /* ACK ranges per MC_ACK, First ACK Range counted as one */
    uint64_t ranges_p50;
    uint64_t first_ack_time;
    uint64_t last_ack_time;
} picoquic_mcquic_client_ack_stats_t;

typedef struct st_picoquic_mcquic_sender_stats_t {
    uint64_t packets_sent;
    uint64_t integrity_sent; /* hashes */
    uint64_t integrity_frames;
    uint64_t integrity_bytes; /* MC_INTEGRITY frame bytes, type included */
    uint64_t integrity_dropped;
    uint64_t acks_received;
    uint64_t largest_acked;
} picoquic_mcquic_sender_stats_t;

/* Max Rate, in Kibps as MC_ANNOUNCE carries it, for one payload of
 * payload_bytes every interval_us, times headroom_percent / 100, rounded up.
 * 0 if interval_us is 0. */
uint64_t picoquic_mcquic_max_rate_kibps(size_t payload_bytes, uint64_t interval_us, unsigned int headroom_percent);
/* The QUICast example server's constants; the source address is left to the caller. */
void picoquic_mcquic_set_default_sender_config(picoquic_mcquic_sender_config_t* config);
int picoquic_mcquic_sender_create(picoquic_quic_t* quic, const picoquic_mcquic_sender_config_t* config);
void picoquic_mcquic_sender_delete(picoquic_quic_t* quic);
void picoquic_mcquic_sender_set_log(picoquic_quic_t* quic, FILE* f);
int picoquic_mcquic_sender_get_stats(picoquic_quic_t* quic, picoquic_mcquic_sender_stats_t* stats);
/* Announces the channel to a client. The integrity hash is chosen per
 * connection, since MC_INTEGRITY goes over each client's unicast connection:
 * the configured hash if the client's multicast_client_params lists it, else
 * the first listed hash this sender supports. draft-08 3: the server MUST NOT
 * send an MC_ANNOUNCE for a channel using an algorithm the client did not
 * list, so a client that lists none gets no MC_ANNOUNCE (logged). */
int picoquic_mcquic_server_start(picoquic_cnx_t* cnx);
uint16_t picoquic_mcquic_choose_hash_alg(uint16_t configured, const picoquic_mcquic_client_params_t* params);
int picoquic_mcquic_get_client_ack_stats(picoquic_cnx_t* cnx, picoquic_mcquic_client_ack_stats_t* stats);
/* MC_INTEGRITY batching: per client, one frame carries up to max_hashes hashes
 * (capped so the frame fits the path MTU), sent when max_hashes are pending or
 * the oldest has waited max_hold_us. The default is 1 hash per frame. */
int picoquic_mcquic_sender_set_integrity_batch(picoquic_quic_t* quic, size_t max_hashes, uint64_t max_hold_us);
int picoquic_mcquic_sender_get_integrity_batch(picoquic_quic_t* quic, size_t* max_hashes, uint64_t* max_hold_us);
/* Sends the batches that are due, or all pending ones if force is set.
 * Returns the time at which the next batch is due, UINT64_MAX if none. */
uint64_t picoquic_mcquic_sender_flush(picoquic_quic_t* quic, uint64_t current_time, int force);
/* Returns the channel packet length, 0 on error; pn receives its packet number. */
size_t picoquic_mcquic_sender_prepare(picoquic_quic_t* quic, const uint8_t* payload, size_t payload_length,
    uint64_t current_time, uint8_t* bytes, size_t bytes_max, uint64_t* pn);
/* Fills an MC_ANNOUNCE (IPv4), MC_KEY or MC_JOIN frame from a sender configuration. */
void picoquic_mcquic_sender_frame(const picoquic_mcquic_sender_config_t* config, uint64_t frame_type,
    picoquic_mcquic_frame_t* frame);
/* Builds a protected channel packet: header, AEAD, then header protection. Returns its length, 0 on error. */
void* picoquic_mcquic_aead_create_encrypt(uint16_t cipher_suite_id, const uint8_t* secret, size_t secret_length);
size_t picoquic_mcquic_protect(void* hp_ctx, void* aead_ctx, int key_phase, const picoquic_mcquic_channel_id_t* channel_id,
    uint64_t pn, const uint8_t* plaintext, size_t plaintext_length, uint8_t* bytes, size_t bytes_max);

/* Sockets owned by the packet loop (POSIX poll and select loops).
 * After picoquic_mcquic_loop_config(), the packet loop opens, joins, polls and
 * closes the channel sockets of a receiver (MC_JOIN to the last leave), passes
 * their packets to picoquic_incoming_multicast_packet(), and sends the channel
 * packets of a sender; the join and leave events become notifications (a
 * non-zero return from the join event still declines). if_addr is the IPv4
 * address of the interface to join and send on (NULL: let the system choose).
 * Without it, the application owns the sockets as described above. */
typedef struct st_picoquic_mcquic_loop_stats_t {
    uint64_t sockets_opened;
    uint64_t sockets_closed;
    uint64_t join_failures;
    uint64_t packets_received;
    uint64_t packets_sent;
    uint64_t send_errors;
    uint64_t queue_full;
} picoquic_mcquic_loop_stats_t;

int picoquic_mcquic_loop_config(picoquic_quic_t* quic, const struct sockaddr* if_addr, int ttl, int loopback);
int picoquic_mcquic_loop_get_stats(picoquic_quic_t* quic, picoquic_mcquic_loop_stats_t* stats);
/* Sender with a loop-owned socket: builds the next channel packet around one
 * DATAGRAM frame and queues it; the loop sends it to (S,G). Returns 0, or -1 if
 * the queue is full or the sender is not configured. Call it on the loop's thread. */
int picoquic_mcquic_sender_publish(picoquic_quic_t* quic, const uint8_t* payload, size_t payload_length,
    uint64_t current_time);
int picoquic_mcquic_sender_get_config(picoquic_quic_t* quic, picoquic_mcquic_sender_config_t* config);
/* Queues the MC_ACK and MC_INTEGRITY frames that are due on every connection.
 * Returns the time the next one is due, UINT64_MAX if none. The packet loop
 * calls it; applications with their own loop may too. */
uint64_t picoquic_mcquic_service(picoquic_quic_t* quic, uint64_t current_time);

/* Hooks called from the transport, frame decoder and connection code. */
int picoquic_mcquic_receive_client_params(picoquic_cnx_t* cnx, const uint8_t* bytes, size_t length);
uint8_t* picoquic_mcquic_prepare_transport_parameter(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max);
int picoquic_mcquic_receive_server_support(picoquic_cnx_t* cnx, uint64_t extension_length);
const uint8_t* picoquic_mcquic_decode_control_frame(picoquic_cnx_t* cnx, const uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t frame_type, uint64_t current_time);
void picoquic_mcquic_delete(picoquic_cnx_t* cnx);

#ifdef __cplusplus
}
#endif

#endif /* PICOQUIC_MCQUIC_H */
