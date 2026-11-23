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
* Multicast QUIC receiver and sender. See mcquic.h for the scope and the API.
*
* The frame codecs, the channel packet format, the key derivation, the
* integrity check and the acknowledgement ranges follow the QUICast quiche
* implementation (quiche/src/multicast.rs), which implements
* draft-jholland-quic-multicast-08. draft-09 uses the same experimental code
* points but changes these points of the wire format:
*   - multicast_client_params has no Max Joined Count (it is only in MC_LIMITS;
*     draft-09 adds it to the parameter);
*   - the IP family flags are IPv4 = 0x01, IPv6 = 0x02 (draft-09 swaps them);
*   - MC_ANNOUNCE carries a header protection algorithm before the header
*     secret and an AEAD algorithm after it, then the hash algorithm, Max Rate
*     and Max ACK Delay in milliseconds (draft-09: one cipher suite, Max ACK
*     Delay in microseconds, plus Max Authentication Delay, Ack-Eliciting
*     Threshold and Reordering Threshold);
*   - MC_INTEGRITY with a length field carries a hash count (draft-09: a byte length);
*   - MC_LEAVE and MC_RETIRE carry an After Packet Number (draft-09 removes it).
*/

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <picotls.h>
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "tls_api.h"
#include "mcquic.h"
#include "mcquic_loop.h"

#define MCQUIC_IP_FLAG_V4 0x01
#define MCQUIC_IP_FLAG_V6 0x02
#define MCQUIC_RING_SIZE 2048
/* The ACK record: quiche keeps 64 ranges over the last 4096 packet numbers.
 * Here the window is at least 2 x packet rate x Max ACK Delay (never under
 * 4096 nor over 2^20), and the range count is bounded by what fits one MC_ACK
 * in a 1-RTT packet on the path, and by the tracker's size. */
#define MCQUIC_MAX_TRACKED_RANGES 1024
#define MCQUIC_ACK_WINDOW_MIN 4096
#define MCQUIC_ACK_WINDOW_MAX (1ull << 20)
/* MC_ACK fixed part: 4-byte type, ID length, ID, then four varints at their largest */
#define MCQUIC_ACK_FIXED(id_len) (4 + 1 + (id_len) + 8 + 8 + 8 + 8)
#define MCQUIC_MAX_PACKET 2048
#define MCQUIC_LABEL_PREFIX "tls13 "
#define MCQUIC_AEGIS_256_SHA512 0x1307
#define MCQUIC_INTEGRITY_BATCH_MAX 256

typedef struct st_mcquic_pending_packet_t {
    uint64_t pn;
    uint64_t arrival_time;
    uint8_t* bytes;
    size_t length;
    size_t header_length;
    uint8_t header[1 + PICOQUIC_MCQUIC_CHANNEL_ID_MAX + PICOQUIC_MCQUIC_PN_LENGTH];
} mcquic_pending_packet_t;

typedef struct st_mcquic_pending_hash_t {
    uint64_t pn;
    int in_use;
    uint8_t hash[PICOQUIC_MCQUIC_HASH_MAX];
} mcquic_pending_hash_t;

typedef struct st_mcquic_range_t {
    uint64_t start;
    uint64_t end;
} mcquic_range_t;

typedef struct st_mcquic_key_t {
    int valid;
    uint64_t key_sequence;
    uint64_t from_pn;
    size_t secret_length;
    uint8_t secret[PICOQUIC_MCQUIC_SECRET_MAX];
    void* aead;
} mcquic_key_t;

typedef struct st_mcquic_channel_t {
    struct st_mcquic_channel_t* next;
    picoquic_mcquic_channel_id_t id;
    int has_announce;
    picoquic_mcquic_channel_info_t info;
    uint16_t cipher_suite;
    uint16_t hash_alg;
    size_t hash_length;
    uint64_t max_ack_delay_us;
    void* hp_ctx;
    mcquic_key_t keys[2]; /* by key phase */
    int joined;
    int loop_joined;
    int retired;
    uint64_t state_sequence;
    int has_largest;
    uint64_t largest_pn;
    mcquic_pending_packet_t* packets;
    mcquic_pending_hash_t* hashes;
    mcquic_range_t ranges[MCQUIC_MAX_TRACKED_RANGES + 1];
    size_t nb_ranges;
    size_t max_ranges;
    uint64_t ack_window;
    uint64_t retired_before;
    int ack_pending;
    int ack_sent_once;
    int ack_scheduled;
    uint64_t next_ack_time;
    uint64_t last_ack_time;
    uint64_t largest_recv_time;
    uint64_t rate_first_pn;
    uint64_t rate_first_time;
    picoquic_mcquic_stats_t stats;
} mcquic_channel_t;

typedef struct st_picoquic_mcquic_ctx_t {
    picoquic_mcquic_client_params_t params; /* on a server connection, the client's */
    int is_server;
    int announced;
    int join_sent;
    int sender_joined;
    uint64_t integrity_dropped;
    size_t batch_count;
    uint64_t batch_pn_start;
    uint64_t batch_oldest;
    uint8_t* batch_hashes;
    uint64_t acks_received;
    uint64_t largest_acked;
    picoquic_mcquic_ack_policy_t ack_policy;
    /* Server side: integrity hash announced to this client */
    uint16_t hash_alg;
    size_t hash_length;
    /* Server side: MC_ACKs from this client */
    uint64_t client_index;
    uint64_t ack_bytes;
    uint64_t ack_first_time;
    uint64_t ack_last_time;
    uint32_t ack_ranges_hist[MCQUIC_MAX_TRACKED_RANGES + 2];
    int server_support;
    uint64_t limits_sequence;
    mcquic_channel_t* first_channel;
    size_t nb_channels;
    FILE* log_file;
} picoquic_mcquic_ctx_t;

static void mcquic_log(picoquic_mcquic_ctx_t* ctx, const char* fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 2, 3)))
#endif
    ;

static void mcquic_log(picoquic_mcquic_ctx_t* ctx, const char* fmt, ...)
{
    if (ctx != NULL && ctx->log_file != NULL) {
        va_list args;
        va_start(args, fmt);
        fprintf(ctx->log_file, "mcquic: ");
        vfprintf(ctx->log_file, fmt, args);
        fprintf(ctx->log_file, "\n");
        fflush(ctx->log_file);
        va_end(args);
    }
}

static const char* mcquic_id_hex(const picoquic_mcquic_channel_id_t* id, char* buf)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < id->id_len; i++) {
        buf[2 * i] = hex[id->id[i] >> 4];
        buf[2 * i + 1] = hex[id->id[i] & 15];
    }
    buf[2 * id->id_len] = 0;
    return buf;
}

/*
* Frame codecs
*/

static const uint8_t* mcquic_channel_id_decode(const uint8_t* bytes, const uint8_t* bytes_max, picoquic_mcquic_channel_id_t* id)
{
    if ((bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &id->id_len)) != NULL) {
        if (id->id_len < 1 || id->id_len > PICOQUIC_MCQUIC_CHANNEL_ID_MAX || bytes + id->id_len > bytes_max) {
            bytes = NULL;
        }
        else {
            memcpy(id->id, bytes, id->id_len);
            bytes += id->id_len;
        }
    }
    return bytes;
}

static uint8_t* mcquic_channel_id_encode(uint8_t* bytes, const uint8_t* bytes_max, const picoquic_mcquic_channel_id_t* id)
{
    if (id->id_len < 1 || id->id_len > PICOQUIC_MCQUIC_CHANNEL_ID_MAX) {
        return NULL;
    }
    if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, id->id_len)) != NULL) {
        bytes = picoquic_frames_fixed_copy(bytes, bytes_max, id->id, id->id_len);
    }
    return bytes;
}

static const uint8_t* mcquic_secret_decode(const uint8_t* bytes, const uint8_t* bytes_max, uint8_t* secret, size_t* secret_len)
{
    uint64_t len = 0;
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &len)) != NULL) {
        if (len > PICOQUIC_MCQUIC_SECRET_MAX || len > (uint64_t)(bytes_max - bytes)) {
            bytes = NULL;
        }
        else {
            memcpy(secret, bytes, (size_t)len);
            *secret_len = (size_t)len;
            bytes += len;
        }
    }
    return bytes;
}

static uint8_t* mcquic_bytes_encode(uint8_t* bytes, const uint8_t* bytes_max, const uint8_t* v, size_t len)
{
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, len)) != NULL) {
        bytes = picoquic_frames_fixed_copy(bytes, bytes_max, v, len);
    }
    return bytes;
}

static uint8_t mcquic_ip_flags(int ipv4_allowed, int ipv6_allowed)
{
    return (uint8_t)((ipv4_allowed ? MCQUIC_IP_FLAG_V4 : 0) | (ipv6_allowed ? MCQUIC_IP_FLAG_V6 : 0));
}

uint8_t* picoquic_mcquic_client_params_encode(uint8_t* bytes, const uint8_t* bytes_max, const picoquic_mcquic_client_params_t* params)
{
    if (params->nb_hash_algs > PICOQUIC_MCQUIC_ALGS_MAX || params->nb_cipher_suites > PICOQUIC_MCQUIC_ALGS_MAX) {
        return NULL;
    }
    if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, mcquic_ip_flags(params->ipv4_allowed, params->ipv6_allowed))) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, params->max_rate_kibps)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, params->max_channel_ids)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, params->nb_hash_algs)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, params->nb_cipher_suites)) != NULL) {
        for (size_t i = 0; bytes != NULL && i < params->nb_hash_algs; i++) {
            bytes = picoquic_frames_uint16_encode(bytes, bytes_max, params->hash_algs[i]);
        }
        for (size_t i = 0; bytes != NULL && i < params->nb_cipher_suites; i++) {
            bytes = picoquic_frames_uint16_encode(bytes, bytes_max, params->cipher_suites[i]);
        }
    }
    return bytes;
}

const uint8_t* picoquic_mcquic_client_params_decode(const uint8_t* bytes, const uint8_t* bytes_max, picoquic_mcquic_client_params_t* params)
{
    uint8_t flags = 0;
    uint64_t nb_hash = 0;
    uint64_t nb_cipher = 0;

    memset(params, 0, sizeof(picoquic_mcquic_client_params_t));
    if ((bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &flags)) != NULL &&
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &params->max_rate_kibps)) != NULL &&
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &params->max_channel_ids)) != NULL &&
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &nb_hash)) != NULL &&
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &nb_cipher)) != NULL) {
        params->ipv4_allowed = (flags & MCQUIC_IP_FLAG_V4) != 0;
        params->ipv6_allowed = (flags & MCQUIC_IP_FLAG_V6) != 0;
        if (nb_hash > PICOQUIC_MCQUIC_ALGS_MAX || nb_cipher > PICOQUIC_MCQUIC_ALGS_MAX ||
            2 * (nb_hash + nb_cipher) != (uint64_t)(bytes_max - bytes)) {
            /* The parameter length must match the two counts exactly */
            return NULL;
        }
        params->nb_hash_algs = (size_t)nb_hash;
        params->nb_cipher_suites = (size_t)nb_cipher;
        for (size_t i = 0; bytes != NULL && i < params->nb_hash_algs; i++) {
            bytes = picoquic_frames_uint16_decode(bytes, bytes_max, &params->hash_algs[i]);
        }
        for (size_t i = 0; bytes != NULL && i < params->nb_cipher_suites; i++) {
            bytes = picoquic_frames_uint16_decode(bytes, bytes_max, &params->cipher_suites[i]);
        }
    }
    return bytes;
}

int picoquic_mcquic_is_frame_type(uint64_t frame_type)
{
    switch (frame_type) {
    case PICOQUIC_MCQUIC_FRAME_KEY:
    case PICOQUIC_MCQUIC_FRAME_JOIN:
    case PICOQUIC_MCQUIC_FRAME_LEAVE:
    case PICOQUIC_MCQUIC_FRAME_INTEGRITY:
    case PICOQUIC_MCQUIC_FRAME_INTEGRITY_LEN:
    case PICOQUIC_MCQUIC_FRAME_ACK:
    case PICOQUIC_MCQUIC_FRAME_ACK_ECN:
    case PICOQUIC_MCQUIC_FRAME_LIMITS:
    case PICOQUIC_MCQUIC_FRAME_RETIRE:
    case PICOQUIC_MCQUIC_FRAME_STATE:
    case PICOQUIC_MCQUIC_FRAME_STATE_APP:
    case PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V4:
    case PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V6:
        return 1;
    default:
        return 0;
    }
}

const uint8_t* picoquic_mcquic_frame_decode(const uint8_t* bytes, const uint8_t* bytes_max, uint64_t frame_type,
    size_t hash_length, picoquic_mcquic_frame_t* f)
{
    memset(f, 0, sizeof(picoquic_mcquic_frame_t));
    f->frame_type = frame_type;

    switch (frame_type) {
    case PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V4:
    case PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V6: {
        size_t addr_len = (frame_type == PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V4) ? 4 : 16;
        f->u.announce.is_ipv6 = (addr_len == 16);
        if ((bytes = mcquic_channel_id_decode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_fixed_skip(bytes, bytes_max, 2 * addr_len)) != NULL) {
            memcpy(f->u.announce.source, bytes - 2 * addr_len, addr_len);
            memcpy(f->u.announce.group, bytes - addr_len, addr_len);
            if ((bytes = picoquic_frames_uint16_decode(bytes, bytes_max, &f->u.announce.port)) != NULL &&
                (bytes = picoquic_frames_uint16_decode(bytes, bytes_max, &f->u.announce.header_protection_alg)) != NULL &&
                (bytes = mcquic_secret_decode(bytes, bytes_max, f->u.announce.header_secret, &f->u.announce.header_secret_len)) != NULL &&
                (bytes = picoquic_frames_uint16_decode(bytes, bytes_max, &f->u.announce.aead_alg)) != NULL &&
                (bytes = picoquic_frames_uint16_decode(bytes, bytes_max, &f->u.announce.hash_alg)) != NULL &&
                (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.announce.max_rate_kibps)) != NULL) {
                bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.announce.max_ack_delay_ms);
            }
        }
        break;
    }
    case PICOQUIC_MCQUIC_FRAME_KEY:
        if ((bytes = mcquic_channel_id_decode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.key.key_sequence)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.key.from_packet_number)) != NULL) {
            bytes = mcquic_secret_decode(bytes, bytes_max, f->u.key.secret, &f->u.key.secret_len);
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_JOIN:
        if ((bytes = mcquic_channel_id_decode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.join.limits_sequence)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.join.state_sequence)) != NULL) {
            bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.join.key_sequence);
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_LEAVE:
        if ((bytes = mcquic_channel_id_decode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.leave.state_sequence)) != NULL) {
            bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.leave.after_packet_number);
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_INTEGRITY:
    case PICOQUIC_MCQUIC_FRAME_INTEGRITY_LEN:
        if ((bytes = mcquic_channel_id_decode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.integrity.packet_number_start)) != NULL) {
            if (frame_type == PICOQUIC_MCQUIC_FRAME_INTEGRITY) {
                /* The hashes extend to the end of the packet */
                f->u.integrity.hashes = bytes;
                f->u.integrity.hashes_length = bytes_max - bytes;
                bytes = bytes_max;
            }
            else if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.integrity.hash_count)) != NULL) {
                /* draft-08 (and quiche): a hash count; draft-09 changes this to a length in bytes */
                f->u.integrity.has_count = 1;
                if (hash_length == 0 || f->u.integrity.hash_count > (uint64_t)(bytes_max - bytes) / hash_length) {
                    bytes = NULL;
                }
                else {
                    f->u.integrity.hashes = bytes;
                    f->u.integrity.hashes_length = (size_t)f->u.integrity.hash_count * hash_length;
                    bytes += f->u.integrity.hashes_length;
                }
            }
            if (bytes != NULL && hash_length > 0 &&
                (f->u.integrity.hashes_length == 0 || (f->u.integrity.hashes_length % hash_length) != 0)) {
                bytes = NULL;
            }
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_ACK:
    case PICOQUIC_MCQUIC_FRAME_ACK_ECN:
        if ((bytes = mcquic_channel_id_decode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.ack.largest)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.ack.ack_delay)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.ack.range_count)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.ack.first_range)) != NULL) {
            f->u.ack.ranges = bytes;
            for (uint64_t i = 0; bytes != NULL && i < f->u.ack.range_count; i++) {
                if ((bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL) {
                    bytes = picoquic_frames_varint_skip(bytes, bytes_max);
                }
            }
            if (bytes != NULL) {
                f->u.ack.ranges_length = bytes - f->u.ack.ranges;
                if (frame_type == PICOQUIC_MCQUIC_FRAME_ACK_ECN) {
                    f->u.ack.has_ecn = 1;
                    for (int i = 0; bytes != NULL && i < 3; i++) {
                        bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.ack.ecn[i]);
                    }
                }
            }
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_LIMITS: {
        uint8_t flags = 0;
        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.limits.sequence)) != NULL &&
            (bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &flags)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.limits.max_rate_kibps)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.limits.max_channel_ids)) != NULL) {
            bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.limits.max_joined);
            f->u.limits.ipv4_allowed = (flags & MCQUIC_IP_FLAG_V4) != 0;
            f->u.limits.ipv6_allowed = (flags & MCQUIC_IP_FLAG_V6) != 0;
        }
        break;
    }
    case PICOQUIC_MCQUIC_FRAME_RETIRE:
        if ((bytes = mcquic_channel_id_decode(bytes, bytes_max, &f->channel_id)) != NULL) {
            bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.retire.after_packet_number);
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_STATE:
    case PICOQUIC_MCQUIC_FRAME_STATE_APP: {
        uint64_t phrase_len = 0;
        if ((bytes = mcquic_channel_id_decode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.state.sequence)) != NULL &&
            (bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &f->u.state.state)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &f->u.state.reason)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &phrase_len)) != NULL) {
            if (f->u.state.state < PICOQUIC_MCQUIC_STATE_LEFT || f->u.state.state > PICOQUIC_MCQUIC_STATE_RETIRED ||
                phrase_len > (uint64_t)(bytes_max - bytes)) {
                bytes = NULL;
            }
            else {
                f->u.state.phrase = bytes;
                f->u.state.phrase_length = (size_t)phrase_len;
                bytes += phrase_len;
            }
        }
        break;
    }
    default:
        bytes = NULL;
        break;
    }
    return bytes;
}

uint8_t* picoquic_mcquic_frame_encode(uint8_t* bytes, const uint8_t* bytes_max, const picoquic_mcquic_frame_t* f)
{
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->frame_type)) == NULL) {
        return NULL;
    }
    switch (f->frame_type) {
    case PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V4:
    case PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V6: {
        size_t addr_len = (f->frame_type == PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V4) ? 4 : 16;
        if ((bytes = mcquic_channel_id_encode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_fixed_copy(bytes, bytes_max, f->u.announce.source, addr_len)) != NULL &&
            (bytes = picoquic_frames_fixed_copy(bytes, bytes_max, f->u.announce.group, addr_len)) != NULL &&
            (bytes = picoquic_frames_uint16_encode(bytes, bytes_max, f->u.announce.port)) != NULL &&
            (bytes = picoquic_frames_uint16_encode(bytes, bytes_max, f->u.announce.header_protection_alg)) != NULL &&
            (bytes = mcquic_bytes_encode(bytes, bytes_max, f->u.announce.header_secret, f->u.announce.header_secret_len)) != NULL &&
            (bytes = picoquic_frames_uint16_encode(bytes, bytes_max, f->u.announce.aead_alg)) != NULL &&
            (bytes = picoquic_frames_uint16_encode(bytes, bytes_max, f->u.announce.hash_alg)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.announce.max_rate_kibps)) != NULL) {
            bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.announce.max_ack_delay_ms);
        }
        break;
    }
    case PICOQUIC_MCQUIC_FRAME_KEY:
        if ((bytes = mcquic_channel_id_encode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.key.key_sequence)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.key.from_packet_number)) != NULL) {
            bytes = mcquic_bytes_encode(bytes, bytes_max, f->u.key.secret, f->u.key.secret_len);
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_JOIN:
        if ((bytes = mcquic_channel_id_encode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.join.limits_sequence)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.join.state_sequence)) != NULL) {
            bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.join.key_sequence);
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_LEAVE:
        if ((bytes = mcquic_channel_id_encode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.leave.state_sequence)) != NULL) {
            bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.leave.after_packet_number);
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_INTEGRITY:
    case PICOQUIC_MCQUIC_FRAME_INTEGRITY_LEN:
        if ((bytes = mcquic_channel_id_encode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.integrity.packet_number_start)) != NULL) {
            if (f->frame_type == PICOQUIC_MCQUIC_FRAME_INTEGRITY_LEN) {
                bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.integrity.hash_count);
            }
            bytes = picoquic_frames_fixed_copy(bytes, bytes_max, f->u.integrity.hashes, f->u.integrity.hashes_length);
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_ACK:
    case PICOQUIC_MCQUIC_FRAME_ACK_ECN:
        if ((bytes = mcquic_channel_id_encode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.ack.largest)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.ack.ack_delay)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.ack.range_count)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.ack.first_range)) != NULL) {
            bytes = picoquic_frames_fixed_copy(bytes, bytes_max, f->u.ack.ranges, f->u.ack.ranges_length);
            if (f->frame_type == PICOQUIC_MCQUIC_FRAME_ACK_ECN) {
                for (int i = 0; bytes != NULL && i < 3; i++) {
                    bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.ack.ecn[i]);
                }
            }
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_LIMITS:
        if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.limits.sequence)) != NULL &&
            (bytes = picoquic_frames_uint8_encode(bytes, bytes_max,
                mcquic_ip_flags(f->u.limits.ipv4_allowed, f->u.limits.ipv6_allowed))) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.limits.max_rate_kibps)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.limits.max_channel_ids)) != NULL) {
            bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.limits.max_joined);
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_RETIRE:
        if ((bytes = mcquic_channel_id_encode(bytes, bytes_max, &f->channel_id)) != NULL) {
            bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.retire.after_packet_number);
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_STATE:
    case PICOQUIC_MCQUIC_FRAME_STATE_APP:
        if ((bytes = mcquic_channel_id_encode(bytes, bytes_max, &f->channel_id)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.state.sequence)) != NULL &&
            (bytes = picoquic_frames_uint8_encode(bytes, bytes_max, f->u.state.state)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, f->u.state.reason)) != NULL) {
            bytes = mcquic_bytes_encode(bytes, bytes_max, f->u.state.phrase, f->u.state.phrase_length);
        }
        break;
    default:
        bytes = NULL;
        break;
    }
    return bytes;
}

const uint8_t* picoquic_mcquic_frame_skip(const uint8_t* bytes, const uint8_t* bytes_max, uint64_t frame_type, int* pure_ack)
{
    /* Used on frames this endpoint sent (MC_LIMITS, MC_STATE, MC_ACK), when packets
     * are acknowledged or repeated. MC_ACK, like ACK, does not elicit an acknowledgement
     * and is not repeated; quiche does the same. An MC_INTEGRITY with a hash count
     * cannot be skipped without the channel's hash length. */
    picoquic_mcquic_frame_t f;
    *pure_ack = (frame_type == PICOQUIC_MCQUIC_FRAME_ACK || frame_type == PICOQUIC_MCQUIC_FRAME_ACK_ECN);
    return picoquic_mcquic_frame_decode(bytes, bytes_max, frame_type, 0, &f);
}

/*
* Channel packet protection
*/

size_t picoquic_mcquic_hash_length(uint16_t hash_alg)
{
    switch (hash_alg) {
    case PICOQUIC_MCQUIC_HASH_SHA256: return 32;
    case PICOQUIC_MCQUIC_HASH_SHA256_128: return 16;
    case PICOQUIC_MCQUIC_HASH_SHA256_120: return 15;
    case PICOQUIC_MCQUIC_HASH_SHA256_96: return 12;
    case PICOQUIC_MCQUIC_HASH_SHA256_64: return 8;
    case PICOQUIC_MCQUIC_HASH_SHA256_32: return 4;
    case PICOQUIC_MCQUIC_HASH_SHA384: return 48;
    case PICOQUIC_MCQUIC_HASH_SHA512: return 64;
    default: return 0;
    }
}

int picoquic_mcquic_integrity_hash(uint16_t hash_alg, const uint8_t* bytes, size_t length, uint8_t* hash, size_t hash_max)
{
    uint8_t full[PTLS_MAX_DIGEST_SIZE];
    size_t hash_length = picoquic_mcquic_hash_length(hash_alg);
    ptls_cipher_suite_t* suite;
    ptls_hash_algorithm_t* algo;

    picoquic_tls_api_init();
    /* SHA-256, SHA-384 and SHA-512 are the hashes of the AES-128-GCM, AES-256-GCM
     * and AEGIS-256 suites; SHA-512 is available only where AEGIS-256 is. */
    suite = (ptls_cipher_suite_t*)picoquic_get_cipher_suite_by_id_v(
        (hash_alg == PICOQUIC_MCQUIC_HASH_SHA384) ? PICOQUIC_AES_256_GCM_SHA384 :
        (hash_alg == PICOQUIC_MCQUIC_HASH_SHA512) ? MCQUIC_AEGIS_256_SHA512 : PICOQUIC_AES_128_GCM_SHA256);
    algo = (suite == NULL) ? NULL : suite->hash;
    if (hash_length == 0 || hash_length > hash_max || algo == NULL || ptls_calc_hash(algo, full, bytes, length) != 0) {
        return -1;
    }
    /* The truncated variants keep the leading bytes of the digest */
    memcpy(hash, full, hash_length);
    return 0;
}

int picoquic_mcquic_derive(uint16_t cipher_suite_id, const uint8_t* secret, size_t secret_length, const char* label,
    uint8_t* out, size_t out_length)
{
    ptls_cipher_suite_t* cipher;

    picoquic_tls_api_init();
    cipher = (ptls_cipher_suite_t*)picoquic_get_cipher_suite_by_id_v(cipher_suite_id);
    if (cipher == NULL) {
        return -1;
    }
    /* HKDF-Expand-Label with the secret as the pseudo-random key, at its own length:
     * channel secrets are not digest-sized (the example sender uses 16 bytes). */
    return ptls_hkdf_expand_label(cipher->hash, out, out_length, ptls_iovec_init(secret, secret_length), label,
        ptls_iovec_init(NULL, 0), MCQUIC_LABEL_PREFIX);
}

void* picoquic_mcquic_hp_create(uint16_t cipher_suite_id, const uint8_t* header_secret, size_t secret_length)
{
    uint8_t hp_key[PTLS_MAX_SECRET_SIZE];
    ptls_cipher_suite_t* cipher;
    void* hp_ctx = NULL;

    picoquic_tls_api_init();
    cipher = (ptls_cipher_suite_t*)picoquic_get_cipher_suite_by_id_v(cipher_suite_id);
    if (cipher != NULL && cipher->aead->ctr_cipher != NULL && cipher->aead->ctr_cipher->key_size <= sizeof(hp_key) &&
        picoquic_mcquic_derive(cipher_suite_id, header_secret, secret_length, "quic hp", hp_key,
            cipher->aead->ctr_cipher->key_size) == 0) {
        hp_ctx = ptls_cipher_new(cipher->aead->ctr_cipher, 1, hp_key);
    }
    ptls_clear_memory(hp_key, sizeof(hp_key));
    return hp_ctx;
}

static void* mcquic_aead_create(uint16_t cipher_suite_id, const uint8_t* secret, size_t secret_length, int is_enc)
{
    uint8_t key[PTLS_MAX_SECRET_SIZE];
    uint8_t iv[PTLS_MAX_IV_SIZE];
    ptls_cipher_suite_t* cipher;
    void* aead = NULL;

    picoquic_tls_api_init();
    cipher = (ptls_cipher_suite_t*)picoquic_get_cipher_suite_by_id_v(cipher_suite_id);
    if (cipher != NULL && cipher->aead->key_size <= sizeof(key) && cipher->aead->iv_size <= sizeof(iv) &&
        picoquic_mcquic_derive(cipher_suite_id, secret, secret_length, "quic key", key, cipher->aead->key_size) == 0 &&
        picoquic_mcquic_derive(cipher_suite_id, secret, secret_length, "quic iv", iv, cipher->aead->iv_size) == 0) {
        aead = ptls_aead_new_direct(cipher->aead, is_enc, key, iv);
    }
    ptls_clear_memory(key, sizeof(key));
    ptls_clear_memory(iv, sizeof(iv));
    return aead;
}

void* picoquic_mcquic_aead_create(uint16_t cipher_suite_id, const uint8_t* secret, size_t secret_length)
{
    return mcquic_aead_create(cipher_suite_id, secret, secret_length, 0);
}

void* picoquic_mcquic_aead_create_encrypt(uint16_t cipher_suite_id, const uint8_t* secret, size_t secret_length)
{
    return mcquic_aead_create(cipher_suite_id, secret, secret_length, 1);
}

size_t picoquic_mcquic_protect(void* hp_ctx, void* aead_ctx, int key_phase, const picoquic_mcquic_channel_id_t* channel_id,
    uint64_t pn, const uint8_t* plaintext, size_t plaintext_length, uint8_t* bytes, size_t bytes_max)
{
    static const uint8_t zeros[5] = { 0, 0, 0, 0, 0 };
    uint8_t mask[5];
    size_t pn_offset = 1 + channel_id->id_len;
    size_t header_length = pn_offset + PICOQUIC_MCQUIC_PN_LENGTH;
    size_t length;

    if (hp_ctx == NULL || aead_ctx == NULL ||
        header_length + plaintext_length + ((ptls_aead_context_t*)aead_ctx)->algo->tag_size > bytes_max) {
        return 0;
    }
    /* Short header, fixed bit, key phase, four-byte packet number */
    bytes[0] = (uint8_t)(0x40 | ((key_phase & 1) << 2) | 0x03);
    memcpy(bytes + 1, channel_id->id, channel_id->id_len);
    for (size_t i = 0; i < PICOQUIC_MCQUIC_PN_LENGTH; i++) {
        bytes[pn_offset + i] = (uint8_t)(pn >> (8 * (PICOQUIC_MCQUIC_PN_LENGTH - 1 - i)));
    }
    length = header_length + ptls_aead_encrypt((ptls_aead_context_t*)aead_ctx, bytes + header_length, plaintext,
        plaintext_length, pn, bytes, header_length);
    if (length < header_length + 16) {
        return 0;
    }
    picoquic_pn_encrypt(hp_ctx, bytes + header_length, mask, zeros, 5);
    bytes[0] ^= (mask[0] & 0x1f);
    for (size_t i = 0; i < PICOQUIC_MCQUIC_PN_LENGTH; i++) {
        bytes[pn_offset + i] ^= mask[1 + i];
    }
    return length;
}

static uint64_t mcquic_decode_pn(uint64_t expected, uint64_t truncated, unsigned int nbits)
{
    /* RFC 9000, appendix A.3 */
    uint64_t pn_win = 1ull << nbits;
    uint64_t pn_hwin = pn_win / 2;
    uint64_t pn_mask = pn_win - 1;
    uint64_t candidate = (expected & ~pn_mask) | truncated;

    if (candidate + pn_hwin <= expected && candidate < (1ull << 62) - pn_win) {
        return candidate + pn_win;
    }
    if (candidate > expected + pn_hwin && candidate >= pn_win) {
        return candidate - pn_win;
    }
    return candidate;
}

size_t picoquic_mcquic_unprotect_header(void* hp_ctx, const uint8_t* bytes, size_t length, size_t channel_id_length,
    uint64_t expected_pn, uint8_t* header, uint64_t* pn)
{
    static const uint8_t zeros[5] = { 0, 0, 0, 0, 0 };
    uint8_t mask[5];
    size_t pn_offset = 1 + channel_id_length;
    size_t sample_offset = pn_offset + PICOQUIC_MCQUIC_PN_LENGTH;
    uint64_t truncated = 0;

    /* Short header with the fixed bit set, and room for the sample */
    if (hp_ctx == NULL || (bytes[0] & 0xc0) != 0x40 || length < sample_offset + 16) {
        return 0;
    }
    picoquic_pn_encrypt(hp_ctx, bytes + sample_offset, mask, zeros, 5);
    memcpy(header, bytes, pn_offset);
    header[0] = bytes[0] ^ (mask[0] & 0x1f);
    /* Channel packets always use a four-byte packet number (quiche; draft-08 does not say, draft-09 2.1 requires it) */
    if ((header[0] & 0x03) != 0x03) {
        return 0;
    }
    for (size_t i = 0; i < PICOQUIC_MCQUIC_PN_LENGTH; i++) {
        header[pn_offset + i] = bytes[pn_offset + i] ^ mask[1 + i];
        truncated = (truncated << 8) | header[pn_offset + i];
    }
    *pn = mcquic_decode_pn(expected_pn, truncated, 8 * PICOQUIC_MCQUIC_PN_LENGTH);
    return pn_offset + PICOQUIC_MCQUIC_PN_LENGTH;
}

size_t picoquic_mcquic_decrypt(void* aead_ctx, const uint8_t* bytes, size_t length, const uint8_t* header,
    size_t header_length, uint64_t pn, uint8_t* plaintext)
{
    if (aead_ctx == NULL || length <= header_length) {
        return SIZE_MAX;
    }
    return ptls_aead_decrypt((ptls_aead_context_t*)aead_ctx, plaintext, bytes + header_length, length - header_length,
        pn, header, header_length);
}

/*
* Receiver state
*/

static picoquic_mcquic_ctx_t* mcquic_ctx(picoquic_cnx_t* cnx)
{
    return (picoquic_mcquic_ctx_t*)cnx->mcquic_ctx;
}

void picoquic_mcquic_set_default_client_params(picoquic_mcquic_client_params_t* params)
{
    /* Same values as the QUICast example client */
    memset(params, 0, sizeof(picoquic_mcquic_client_params_t));
    params->ipv4_allowed = 1;
    params->max_rate_kibps = 8192;
    params->max_channel_ids = 16;
    params->max_joined = 4;
    params->nb_hash_algs = 1;
    params->hash_algs[0] = PICOQUIC_MCQUIC_HASH_SHA256;
    params->nb_cipher_suites = 1;
    params->cipher_suites[0] = PICOQUIC_AES_128_GCM_SHA256;
}

int picoquic_mcquic_enable_client(picoquic_cnx_t* cnx, const picoquic_mcquic_client_params_t* params)
{
    picoquic_mcquic_ctx_t* ctx;

    if (!cnx->client_mode || cnx->mcquic_ctx != NULL) {
        return -1;
    }
    if ((ctx = (picoquic_mcquic_ctx_t*)calloc(1, sizeof(picoquic_mcquic_ctx_t))) == NULL) {
        return PICOQUIC_ERROR_MEMORY;
    }
    if (params == NULL) {
        picoquic_mcquic_set_default_client_params(&ctx->params);
    }
    else {
        ctx->params = *params;
    }
    ctx->ack_policy.jitter = 1;
    ctx->ack_policy.jitter_first = 1;
    cnx->mcquic_ctx = ctx;
    return 0;
}

static void mcquic_free_buffers(mcquic_channel_t* ch)
{
    if (ch->packets != NULL) {
        for (size_t i = 0; i < MCQUIC_RING_SIZE; i++) {
            free(ch->packets[i].bytes);
        }
        free(ch->packets);
        ch->packets = NULL;
    }
    free(ch->hashes);
    ch->hashes = NULL;
}

static void mcquic_clear_key(mcquic_key_t* key)
{
    if (key->aead != NULL) {
        ptls_aead_free((ptls_aead_context_t*)key->aead);
    }
    ptls_clear_memory(key, sizeof(mcquic_key_t));
}

static void mcquic_channel_free(mcquic_channel_t* ch)
{
    mcquic_free_buffers(ch);
    for (int i = 0; i < 2; i++) {
        mcquic_clear_key(&ch->keys[i]);
    }
    if (ch->hp_ctx != NULL) {
        ptls_cipher_free((ptls_cipher_context_t*)ch->hp_ctx);
    }
    free(ch);
}

void picoquic_mcquic_delete(picoquic_cnx_t* cnx)
{
    picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);

    if (ctx != NULL) {
        while (ctx->first_channel != NULL) {
            mcquic_channel_t* next = ctx->first_channel->next;
            if (ctx->first_channel->loop_joined) {
                mcquic_loop_leave(cnx->quic, &ctx->first_channel->info);
            }
            mcquic_channel_free(ctx->first_channel);
            ctx->first_channel = next;
        }
        free(ctx->batch_hashes);
        free(ctx);
        cnx->mcquic_ctx = NULL;
    }
}

static mcquic_channel_t* mcquic_find_channel(picoquic_mcquic_ctx_t* ctx, const picoquic_mcquic_channel_id_t* id)
{
    mcquic_channel_t* ch = ctx->first_channel;

    while (ch != NULL && !(ch->id.id_len == id->id_len && memcmp(ch->id.id, id->id, id->id_len) == 0)) {
        ch = ch->next;
    }
    return ch;
}

static mcquic_channel_t* mcquic_find_or_add_channel(picoquic_mcquic_ctx_t* ctx, const picoquic_mcquic_channel_id_t* id)
{
    mcquic_channel_t* ch = mcquic_find_channel(ctx, id);

    if (ch == NULL && ctx->nb_channels < ctx->params.max_channel_ids &&
        (ch = (mcquic_channel_t*)calloc(1, sizeof(mcquic_channel_t))) != NULL) {
        ch->id = *id;
        ch->info.channel_id = *id;
        ch->next = ctx->first_channel;
        ctx->first_channel = ch;
        ctx->nb_channels++;
    }
    return ch;
}

static int mcquic_queue_frame(picoquic_cnx_t* cnx, const picoquic_mcquic_frame_t* f)
{
    uint8_t buffer[MCQUIC_MAX_PACKET];
    uint8_t* bytes = picoquic_mcquic_frame_encode(buffer, buffer + sizeof(buffer), f);
    int is_pure_ack = (f->frame_type == PICOQUIC_MCQUIC_FRAME_ACK || f->frame_type == PICOQUIC_MCQUIC_FRAME_ACK_ECN);

    if (bytes == NULL) {
        return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    }
    return picoquic_queue_misc_frame(cnx, buffer, bytes - buffer, is_pure_ack, picoquic_packet_context_application);
}

static int mcquic_send_state(picoquic_cnx_t* cnx, mcquic_channel_t* ch, uint8_t state, uint64_t reason)
{
    picoquic_mcquic_frame_t f;

    memset(&f, 0, sizeof(f));
    f.frame_type = PICOQUIC_MCQUIC_FRAME_STATE;
    f.channel_id = ch->id;
    f.u.state.sequence = ++ch->state_sequence;
    f.u.state.state = state;
    f.u.state.reason = reason;
    {
        char idh[2 * PICOQUIC_MCQUIC_CHANNEL_ID_MAX + 1];
        mcquic_log(mcquic_ctx(cnx), "MC_STATE sent: channel=%s sequence=%llu state=%u reason=%llu",
            mcquic_id_hex(&ch->id, idh), (unsigned long long)f.u.state.sequence, state, (unsigned long long)reason);
    }
    return mcquic_queue_frame(cnx, &f);
}

uint8_t* picoquic_mcquic_prepare_transport_parameter(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);
    uint8_t value[64];
    uint8_t* value_end;

    if (ctx == NULL || bytes == NULL) {
        return bytes;
    }
    if (ctx->is_server) {
        /* multicast_server_support is empty */
        if (cnx->client_mode || (bytes = picoquic_frames_varint_encode(bytes, bytes_max, PICOQUIC_MCQUIC_TP_SERVER_SUPPORT)) == NULL) {
            return bytes;
        }
        return picoquic_frames_varint_encode(bytes, bytes_max, 0);
    }
    if (!cnx->client_mode) {
        return bytes;
    }
    if ((value_end = picoquic_mcquic_client_params_encode(value, value + sizeof(value), &ctx->params)) == NULL) {
        return NULL;
    }
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, PICOQUIC_MCQUIC_TP_CLIENT_PARAMS)) != NULL) {
        bytes = mcquic_bytes_encode(bytes, bytes_max, value, value_end - value);
    }
    return bytes;
}

int picoquic_mcquic_receive_server_support(picoquic_cnx_t* cnx, uint64_t extension_length)
{
    picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);
    int ret = 0;

    if (ctx != NULL) {
        if (extension_length != 0) {
            ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "multicast_server_support TP");
        }
        else if (!ctx->server_support) {
            /* The QUICast server sends MC_JOIN only after it has seen MC_LIMITS, so
             * send the initial limits as MC_LIMITS 1 as soon as the server supports
             * the extension; the frame goes out in the first 1-RTT packet. */
            picoquic_mcquic_frame_t f;

            ctx->server_support = 1;
            memset(&f, 0, sizeof(f));
            f.frame_type = PICOQUIC_MCQUIC_FRAME_LIMITS;
            f.u.limits.sequence = ++ctx->limits_sequence;
            f.u.limits.ipv4_allowed = ctx->params.ipv4_allowed;
            f.u.limits.ipv6_allowed = ctx->params.ipv6_allowed;
            f.u.limits.max_rate_kibps = ctx->params.max_rate_kibps;
            f.u.limits.max_channel_ids = ctx->params.max_channel_ids;
            f.u.limits.max_joined = ctx->params.max_joined;
            mcquic_log(ctx, "server supports multicast; MC_LIMITS sent: sequence=%llu ipv4=%d ipv6=%d rate=%lluKibps channel_ids=%llu max_joined=%llu",
                (unsigned long long)f.u.limits.sequence, f.u.limits.ipv4_allowed, f.u.limits.ipv6_allowed,
                (unsigned long long)f.u.limits.max_rate_kibps, (unsigned long long)f.u.limits.max_channel_ids,
                (unsigned long long)f.u.limits.max_joined);
            ret = mcquic_queue_frame(cnx, &f);
        }
    }
    return ret;
}

/* Acknowledgement ranges, after quiche's AckTracker: ascending disjoint ranges
 * over the last ack_window packet numbers, at most max_ranges of them. */
static int mcquic_ack_contains(const mcquic_channel_t* ch, uint64_t pn)
{
    if (pn < ch->retired_before) {
        return 1;
    }
    for (size_t i = ch->nb_ranges; i > 0; i--) {
        if (ch->ranges[i - 1].start <= pn && pn <= ch->ranges[i - 1].end) {
            return 1;
        }
        if (ch->ranges[i - 1].end < pn) {
            break;
        }
    }
    return 0;
}

/* Bytes available for the ranges of one MC_ACK in a 1-RTT packet on the path:
 * short header with the largest connection ID and packet number, AEAD tag, and
 * the frame's fixed part. */
static size_t mcquic_ack_budget(picoquic_cnx_t* cnx, const mcquic_channel_t* ch)
{
    size_t mtu = (cnx->path != NULL && cnx->path[0] != NULL && cnx->path[0]->send_mtu > 0) ?
        cnx->path[0]->send_mtu : PICOQUIC_INITIAL_MTU_IPV4;
    size_t overhead = 1 + PICOQUIC_CONNECTION_ID_MAX_SIZE + 4 + 16 + MCQUIC_ACK_FIXED(ch->id.id_len);

    return (mtu > overhead) ? mtu - overhead : 0;
}

static void mcquic_ack_update_limits(picoquic_cnx_t* cnx, mcquic_channel_t* ch)
{
    /* A (gap, length) pair takes at least 2 bytes */
    size_t cap = mcquic_ack_budget(cnx, ch) / 2 + 1;
    uint64_t window = MCQUIC_ACK_WINDOW_MIN;

    ch->max_ranges = (cap < MCQUIC_MAX_TRACKED_RANGES) ? cap : MCQUIC_MAX_TRACKED_RANGES;
    if (ch->has_largest && ch->largest_recv_time > ch->rate_first_time + 100000 && ch->largest_pn > ch->rate_first_pn) {
        /* Packets per second from the packet numbers released so far */
        double rate = (double)(ch->largest_pn - ch->rate_first_pn) * 1000000.0 /
            (double)(ch->largest_recv_time - ch->rate_first_time);
        double w = 2.0 * rate * (double)ch->max_ack_delay_us / 1000000.0;
        if (w > (double)MCQUIC_ACK_WINDOW_MAX) {
            window = MCQUIC_ACK_WINDOW_MAX;
        }
        else if (w > (double)window) {
            window = (uint64_t)w;
        }
    }
    /* The window never shrinks, so that duplicate detection stays monotonic */
    if (window > ch->ack_window) {
        ch->ack_window = window;
    }
}

static void mcquic_ack_record(mcquic_channel_t* ch, uint64_t pn)
{
    uint64_t start = pn;
    uint64_t end = pn;
    size_t i = 0;
    uint64_t largest;
    uint64_t window = (ch->ack_window > 0) ? ch->ack_window : MCQUIC_ACK_WINDOW_MIN;
    size_t max_ranges = (ch->max_ranges > 0) ? ch->max_ranges : 64;

    if (mcquic_ack_contains(ch, pn)) {
        return;
    }
    /* Most packets extend the newest range: search from the end */
    i = ch->nb_ranges;
    while (i > 0 && ch->ranges[i - 1].start > end + 1) {
        i--;
    }
    while (i > 0 && ch->ranges[i - 1].end + 1 >= start) {
        i--;
    }
    while (i < ch->nb_ranges) {
        if (end + 1 < ch->ranges[i].start) {
            break;
        }
        if (ch->ranges[i].end + 1 < start) {
            i++;
            continue;
        }
        /* Overlapping or adjacent: merge and remove */
        if (ch->ranges[i].start < start) {
            start = ch->ranges[i].start;
        }
        if (ch->ranges[i].end > end) {
            end = ch->ranges[i].end;
        }
        memmove(&ch->ranges[i], &ch->ranges[i + 1], (ch->nb_ranges - i - 1) * sizeof(mcquic_range_t));
        ch->nb_ranges--;
    }
    memmove(&ch->ranges[i + 1], &ch->ranges[i], (ch->nb_ranges - i) * sizeof(mcquic_range_t));
    ch->ranges[i].start = start;
    ch->ranges[i].end = end;
    ch->nb_ranges++;

    /* Trim the history to the window */
    largest = ch->ranges[ch->nb_ranges - 1].end;
    if (largest >= window - 1 && largest - (window - 1) > ch->retired_before) {
        ch->retired_before = largest - (window - 1);
    }
    while (ch->nb_ranges > 0 && ch->ranges[0].end < ch->retired_before) {
        memmove(&ch->ranges[0], &ch->ranges[1], (ch->nb_ranges - 1) * sizeof(mcquic_range_t));
        ch->nb_ranges--;
    }
    if (ch->nb_ranges > 0 && ch->ranges[0].start < ch->retired_before) {
        ch->ranges[0].start = ch->retired_before;
    }
    if (ch->nb_ranges > max_ranges) {
        size_t remove = ch->nb_ranges - max_ranges;
        memmove(&ch->ranges[0], &ch->ranges[remove], max_ranges * sizeof(mcquic_range_t));
        ch->nb_ranges = max_ranges;
        if (ch->ranges[0].start > ch->retired_before) {
            ch->retired_before = ch->ranges[0].start;
        }
    }
    ch->stats.ack_window = window;
    ch->ack_pending = 1;
}

size_t picoquic_mcquic_ack_ranges_fit(size_t budget, const uint64_t* gaps_lengths, size_t nb_pairs)
{
    size_t used = 0;
    size_t n = 0;

    while (n < nb_pairs) {
        size_t l = picoquic_frames_varint_encode_length(gaps_lengths[2 * n]) +
            picoquic_frames_varint_encode_length(gaps_lengths[2 * n + 1]);
        if (used + l > budget) {
            break;
        }
        used += l;
        n++;
    }
    return n;
}

static int mcquic_send_ack(picoquic_cnx_t* cnx, mcquic_channel_t* ch, uint64_t current_time)
{
    picoquic_mcquic_frame_t f;
    uint8_t ranges[MCQUIC_MAX_TRACKED_RANGES * 16];
    uint8_t* bytes = ranges;
    const mcquic_range_t* newest = &ch->ranges[ch->nb_ranges - 1];
    uint64_t smallest = newest->start;
    uint64_t delay = 0;
    size_t budget = mcquic_ack_budget(cnx, ch);
    int ret;

    memset(&f, 0, sizeof(f));
    f.frame_type = PICOQUIC_MCQUIC_FRAME_ACK;
    f.channel_id = ch->id;
    f.u.ack.largest = newest->end;
    f.u.ack.first_range = newest->end - newest->start;
    /* Newest ranges first, as many as fit the packet; older ones are left out */
    for (size_t i = ch->nb_ranges - 1; i > 0 && bytes != NULL; i--) {
        const mcquic_range_t* span = &ch->ranges[i - 1];
        uint64_t gap = smallest - span->end - 2;
        uint64_t len = span->end - span->start;
        if ((size_t)(bytes - ranges) + picoquic_frames_varint_encode_length(gap) +
            picoquic_frames_varint_encode_length(len) > budget) {
            break;
        }
        if ((bytes = picoquic_frames_varint_encode(bytes, ranges + sizeof(ranges), gap)) != NULL) {
            bytes = picoquic_frames_varint_encode(bytes, ranges + sizeof(ranges), len);
        }
        smallest = span->start;
        f.u.ack.range_count++;
    }
    if (bytes == NULL) {
        return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    }
    /* ACK Delay is encoded as in RFC 9000 ACK frames (draft-08 10.6, draft-09 10.6). quiche always sends 0. */
    if (current_time > ch->largest_recv_time) {
        delay = (current_time - ch->largest_recv_time) >> cnx->local_parameters.ack_delay_exponent;
    }
    f.u.ack.ack_delay = delay;
    f.u.ack.ranges = ranges;
    f.u.ack.ranges_length = bytes - ranges;
    if ((ret = mcquic_queue_frame(cnx, &f)) == 0) {
        uint8_t tmp[MCQUIC_MAX_PACKET];
        uint8_t* e = picoquic_mcquic_frame_encode(tmp, tmp + sizeof(tmp), &f);
        ch->ack_pending = 0;
        ch->ack_sent_once = 1;
        ch->ack_scheduled = 0;
        ch->last_ack_time = current_time;
        ch->stats.acks_sent++;
        if (e != NULL) {
            ch->stats.ack_bytes += (uint64_t)(e - tmp);
        }
        if (f.u.ack.range_count + 1 > ch->stats.ack_ranges_max) {
            ch->stats.ack_ranges_max = f.u.ack.range_count + 1;
        }
    }
    return ret;
}

/* Time the next MC_ACK of a channel with pending acknowledgements is due.
 * Draws it on first use after each MC_ACK when the policy jitters. */
static uint64_t mcquic_ack_due(picoquic_mcquic_ctx_t* ctx, mcquic_channel_t* ch, uint64_t current_time)
{
    const picoquic_mcquic_ack_policy_t* pol = &ctx->ack_policy;

    if (!pol->jitter) {
        /* The first MC_ACK of a channel goes without delay (draft-08 10.1, Max ACK Delay; draft-09 4.4) */
        return (!ch->ack_sent_once) ? current_time : ch->last_ack_time + ch->max_ack_delay_us;
    }
    if (!ch->ack_scheduled) {
        if (!ch->ack_sent_once) {
            ch->next_ack_time = (pol->jitter_first && ch->max_ack_delay_us > 0) ?
                current_time + picoquic_public_uniform_random(ch->max_ack_delay_us + 1) : current_time;
        }
        else {
            /* Uniform in [0.5, 1.0] x Max ACK Delay after the previous MC_ACK */
            uint64_t half = ch->max_ack_delay_us / 2;
            ch->next_ack_time = ch->last_ack_time + (ch->max_ack_delay_us - half) +
                ((half > 0) ? picoquic_public_uniform_random(half + 1) : 0);
        }
        ch->ack_scheduled = 1;
    }
    return ch->next_ack_time;
}

int picoquic_mcquic_set_ack_policy(picoquic_cnx_t* cnx, const picoquic_mcquic_ack_policy_t* policy)
{
    picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);

    if (ctx == NULL || ctx->is_server || policy->test_drop < 0.0 || policy->test_drop >= 1.0) {
        return -1;
    }
    ctx->ack_policy = *policy;
    return 0;
}

int picoquic_mcquic_get_ack_policy(picoquic_cnx_t* cnx, picoquic_mcquic_ack_policy_t* policy)
{
    picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);

    if (ctx == NULL || ctx->is_server) {
        return -1;
    }
    *policy = ctx->ack_policy;
    return 0;
}

void picoquic_mcquic_send_acks(picoquic_cnx_t* cnx, uint64_t current_time, int force)
{
    picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);

    if (ctx == NULL) {
        return;
    }
    for (mcquic_channel_t* ch = ctx->first_channel; ch != NULL; ch = ch->next) {
        if (ch->joined && ch->ack_pending && ch->nb_ranges > 0 &&
            (force || current_time >= mcquic_ack_due(ctx, ch, current_time))) {
            (void)mcquic_send_ack(cnx, ch, current_time);
        }
    }
}

static void mcquic_derive_keys(mcquic_channel_t* ch)
{
    if (!ch->has_announce) {
        return;
    }
    for (int i = 0; i < 2; i++) {
        if (ch->keys[i].valid && ch->keys[i].aead == NULL) {
            ch->keys[i].aead = picoquic_mcquic_aead_create(ch->cipher_suite, ch->keys[i].secret, ch->keys[i].secret_length);
        }
    }
}

static int mcquic_param_contains(const uint16_t* list, size_t nb, uint16_t v)
{
    for (size_t i = 0; i < nb; i++) {
        if (list[i] == v) {
            return 1;
        }
    }
    return 0;
}

static int mcquic_on_announce(picoquic_cnx_t* cnx, picoquic_mcquic_ctx_t* ctx, const picoquic_mcquic_frame_t* f)
{
    mcquic_channel_t* ch;

    /* quiche derives header and packet protection with one cipher and rejects
     * an announce whose two algorithms differ. */
    if (f->u.announce.header_protection_alg != f->u.announce.aead_alg ||
        !mcquic_param_contains(ctx->params.cipher_suites, ctx->params.nb_cipher_suites, f->u.announce.aead_alg) ||
        !mcquic_param_contains(ctx->params.hash_algs, ctx->params.nb_hash_algs, f->u.announce.hash_alg) ||
        picoquic_mcquic_hash_length(f->u.announce.hash_alg) == 0) {
        return picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
            f->frame_type, "MC_ANNOUNCE with unsupported algorithms");
    }
    if ((ch = mcquic_find_or_add_channel(ctx, &f->channel_id)) == NULL) {
        return picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
            f->frame_type, "MC_ANNOUNCE beyond the channel ID limit");
    }
    if (ch->hp_ctx != NULL) {
        ptls_cipher_free((ptls_cipher_context_t*)ch->hp_ctx);
    }
    ch->hp_ctx = picoquic_mcquic_hp_create(f->u.announce.aead_alg, f->u.announce.header_secret, f->u.announce.header_secret_len);
    if (ch->hp_ctx == NULL) {
        return PICOQUIC_ERROR_MEMORY;
    }
    ch->has_announce = 1;
    ch->cipher_suite = f->u.announce.aead_alg;
    ch->hash_alg = f->u.announce.hash_alg;
    ch->hash_length = picoquic_mcquic_hash_length(f->u.announce.hash_alg);
    /* Max ACK Delay: milliseconds in draft-08 (and quiche); draft-09 changes this to microseconds */
    ch->max_ack_delay_us = f->u.announce.max_ack_delay_ms * 1000;
    ch->info.is_ipv6 = f->u.announce.is_ipv6;
    memcpy(ch->info.source, f->u.announce.source, 16);
    memcpy(ch->info.group, f->u.announce.group, 16);
    ch->info.port = f->u.announce.port;
    ch->info.max_rate_kibps = f->u.announce.max_rate_kibps;
    mcquic_derive_keys(ch);
    {
        char idh[2 * PICOQUIC_MCQUIC_CHANNEL_ID_MAX + 1];
        mcquic_log(ctx, "MC_ANNOUNCE: channel=%s source=%u.%u.%u.%u group=%u.%u.%u.%u port=%u hp=0x%04x aead=0x%04x hash=%u rate=%lluKibps max_ack_delay=%llums",
            mcquic_id_hex(&ch->id, idh), ch->info.source[0], ch->info.source[1], ch->info.source[2], ch->info.source[3],
            ch->info.group[0], ch->info.group[1], ch->info.group[2], ch->info.group[3], ch->info.port,
            f->u.announce.header_protection_alg, f->u.announce.aead_alg, f->u.announce.hash_alg,
            (unsigned long long)f->u.announce.max_rate_kibps, (unsigned long long)f->u.announce.max_ack_delay_ms);
    }
    return 0;
}

static int mcquic_on_key(picoquic_cnx_t* cnx, picoquic_mcquic_ctx_t* ctx, const picoquic_mcquic_frame_t* f)
{
    mcquic_channel_t* ch;
    mcquic_key_t* key;

    if (f->u.key.key_sequence == 0) {
        return picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, f->frame_type, "MC_KEY sequence 0");
    }
    if ((ch = mcquic_find_or_add_channel(ctx, &f->channel_id)) == NULL) {
        return picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
            f->frame_type, "MC_KEY beyond the channel ID limit");
    }
    /* Odd key sequence numbers use key phase 1 (draft-08 10.2, draft-09 4.2) */
    key = &ch->keys[f->u.key.key_sequence & 1];
    if (key->valid && key->key_sequence == f->u.key.key_sequence) {
        if (key->secret_length != f->u.key.secret_len || memcmp(key->secret, f->u.key.secret, key->secret_length) != 0) {
            return picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
                f->frame_type, "MC_KEY with two secrets for one sequence");
        }
        return 0;
    }
    if (key->valid && key->key_sequence > f->u.key.key_sequence) {
        /* Older than the key already held for this phase */
        return 0;
    }
    mcquic_clear_key(key);
    key->valid = 1;
    key->key_sequence = f->u.key.key_sequence;
    key->from_pn = f->u.key.from_packet_number;
    key->secret_length = f->u.key.secret_len;
    memcpy(key->secret, f->u.key.secret, f->u.key.secret_len);
    mcquic_derive_keys(ch);
    {
        char idh[2 * PICOQUIC_MCQUIC_CHANNEL_ID_MAX + 1];
        mcquic_log(ctx, "MC_KEY: channel=%s key_sequence=%llu from_pn=%llu secret_len=%zu phase=%d",
            mcquic_id_hex(&ch->id, idh), (unsigned long long)key->key_sequence, (unsigned long long)key->from_pn,
            key->secret_length, (int)(key->key_sequence & 1));
    }
    return 0;
}

static int mcquic_on_join(picoquic_cnx_t* cnx, picoquic_mcquic_ctx_t* ctx, const picoquic_mcquic_frame_t* f)
{
    mcquic_channel_t* ch = mcquic_find_channel(ctx, &f->channel_id);
    mcquic_key_t* key;
    int accept;

    if (f->u.join.key_sequence == 0) {
        return picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, f->frame_type, "MC_JOIN key sequence 0");
    }
    if (ch == NULL) {
        if ((ch = mcquic_find_or_add_channel(ctx, &f->channel_id)) == NULL) {
            return picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
                f->frame_type, "MC_JOIN beyond the channel ID limit");
        }
    }
    {
        char idh[2 * PICOQUIC_MCQUIC_CHANNEL_ID_MAX + 1];
        mcquic_log(ctx, "MC_JOIN: channel=%s limits_sequence=%llu state_sequence=%llu key_sequence=%llu",
            mcquic_id_hex(&ch->id, idh), (unsigned long long)f->u.join.limits_sequence,
            (unsigned long long)f->u.join.state_sequence, (unsigned long long)f->u.join.key_sequence);
    }
    if (ch->joined || ch->retired || f->u.join.state_sequence < ch->state_sequence) {
        /* Already joined, retired, or a join based on stale state */
        return 0;
    }
    key = &ch->keys[f->u.join.key_sequence & 1];
    if (!ch->has_announce || ch->info.is_ipv6 || !key->valid || key->key_sequence != f->u.join.key_sequence ||
        key->aead == NULL) {
        return mcquic_send_state(cnx, ch, PICOQUIC_MCQUIC_STATE_DECLINED_JOIN, PICOQUIC_MCQUIC_REASON_UNSYNCHRONIZED_PROPERTIES);
    }
    if (mcquic_loop_enabled(cnx->quic)) {
        /* The packet loop owns the socket; the application is notified and can still decline */
        if (mcquic_loop_join(cnx->quic, &ch->info) != 0) {
            mcquic_log(ctx, "cannot join the channel's (S,G) on the configured interface");
            accept = 0;
        }
        else {
            ch->loop_joined = 1;
            accept = (cnx->callback_fn == NULL ||
                cnx->callback_fn(cnx, 0, (uint8_t*)&ch->info, sizeof(ch->info), picoquic_callback_mc_join,
                    cnx->callback_ctx, (void*)&ch->id) == 0);
        }
    }
    else {
        accept = (cnx->callback_fn != NULL &&
            cnx->callback_fn(cnx, 0, (uint8_t*)&ch->info, sizeof(ch->info), picoquic_callback_mc_join,
                cnx->callback_ctx, (void*)&ch->id) == 0);
    }
    if (accept && ch->packets == NULL) {
        ch->packets = (mcquic_pending_packet_t*)calloc(MCQUIC_RING_SIZE, sizeof(mcquic_pending_packet_t));
        ch->hashes = (mcquic_pending_hash_t*)calloc(MCQUIC_RING_SIZE, sizeof(mcquic_pending_hash_t));
        if (ch->packets == NULL || ch->hashes == NULL) {
            mcquic_free_buffers(ch);
            accept = 0;
        }
    }
    if (!accept) {
        if (ch->loop_joined) {
            mcquic_loop_leave(cnx->quic, &ch->info);
            ch->loop_joined = 0;
        }
        return mcquic_send_state(cnx, ch, PICOQUIC_MCQUIC_STATE_DECLINED_JOIN, PICOQUIC_MCQUIC_REASON_ADMINISTRATIVE_BLOCK);
    }
    ch->joined = 1;
    /* Packet numbers are decoded relative to the key's From Packet Number until
     * one packet has been authenticated (draft-08 10.2, From Packet Number; draft-09 2.1) */
    ch->has_largest = 0;
    return mcquic_send_state(cnx, ch, PICOQUIC_MCQUIC_STATE_JOINED, PICOQUIC_MCQUIC_REASON_REQUESTED_BY_SERVER);
}

static int mcquic_leave(picoquic_cnx_t* cnx, mcquic_channel_t* ch, uint8_t state)
{
    if (ch->joined && cnx->callback_fn != NULL) {
        (void)cnx->callback_fn(cnx, 0, (uint8_t*)&ch->info, sizeof(ch->info), picoquic_callback_mc_leave,
            cnx->callback_ctx, (void*)&ch->id);
    }
    ch->joined = 0;
    if (ch->loop_joined) {
        mcquic_loop_leave(cnx->quic, &ch->info);
        ch->loop_joined = 0;
    }
    mcquic_free_buffers(ch);
    return mcquic_send_state(cnx, ch, state, PICOQUIC_MCQUIC_REASON_REQUESTED_BY_SERVER);
}

static void mcquic_release_packet(picoquic_cnx_t* cnx, mcquic_channel_t* ch, mcquic_pending_packet_t* p, uint64_t current_time);

static void mcquic_try_release(picoquic_cnx_t* cnx, mcquic_channel_t* ch, uint64_t pn, uint64_t current_time)
{
    mcquic_pending_packet_t* p = &ch->packets[pn % MCQUIC_RING_SIZE];
    mcquic_pending_hash_t* h = &ch->hashes[pn % MCQUIC_RING_SIZE];
    uint8_t hash[PICOQUIC_MCQUIC_HASH_MAX];

    if (p->bytes == NULL || p->pn != pn || !h->in_use || h->pn != pn) {
        return;
    }
    /* The hash covers the packet as received, with its protection */
    if (picoquic_mcquic_integrity_hash(ch->hash_alg, p->bytes, p->length, hash, sizeof(hash)) != 0 ||
        picoquic_constant_time_memcmp(hash, h->hash, ch->hash_length) != 0) {
        ch->stats.integrity_failures++;
        mcquic_log(mcquic_ctx(cnx), "integrity check failed: pn=%llu", (unsigned long long)pn);
    }
    else {
        mcquic_release_packet(cnx, ch, p, current_time);
    }
    free(p->bytes);
    p->bytes = NULL;
    h->in_use = 0;
}

static void mcquic_release_packet(picoquic_cnx_t* cnx, mcquic_channel_t* ch, mcquic_pending_packet_t* p, uint64_t current_time)
{
    uint8_t plaintext[MCQUIC_MAX_PACKET];
    mcquic_key_t* key = &ch->keys[(p->header[0] >> 2) & 1];
    const uint8_t* bytes = plaintext;
    const uint8_t* bytes_max;
    size_t length;
    int complete = 1;

    if (!key->valid || key->aead == NULL || p->pn < key->from_pn) {
        ch->stats.no_key++;
        return;
    }
    length = picoquic_mcquic_decrypt(key->aead, p->bytes, p->length, p->header, p->header_length, p->pn, plaintext);
    if (length == SIZE_MAX || length == 0) {
        ch->stats.decrypt_failures++;
        mcquic_log(mcquic_ctx(cnx), "decrypt failed: pn=%llu", (unsigned long long)p->pn);
        return;
    }
    bytes_max = plaintext + length;
    /* Channel frames are decoded here, not by picoquic_decode_frames(): the packet
     * number belongs to the channel's own space. Only the frames a DATAGRAM channel
     * carries are accepted: PADDING, PING, DATAGRAM. */
    while (bytes != NULL && bytes < bytes_max) {
        uint64_t frame_type = 0;
        uint64_t data_length = 0;

        if (*bytes == picoquic_frame_type_padding || *bytes == picoquic_frame_type_ping) {
            bytes++;
        }
        else if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_type)) == NULL) {
            complete = 0;
        }
        else if (frame_type == picoquic_frame_type_datagram || frame_type == picoquic_frame_type_datagram_l) {
            if (frame_type == picoquic_frame_type_datagram_l) {
                if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &data_length)) == NULL ||
                    data_length > (uint64_t)(bytes_max - bytes)) {
                    complete = 0;
                    bytes = NULL;
                    break;
                }
            }
            else {
                data_length = bytes_max - bytes;
            }
            ch->stats.datagrams++;
            if (cnx->callback_fn != NULL) {
                (void)cnx->callback_fn(cnx, p->pn, (uint8_t*)bytes, (size_t)data_length, picoquic_callback_mc_datagram,
                    cnx->callback_ctx, (void*)&ch->id);
            }
            bytes += data_length;
        }
        else {
            /* STREAM, RESET_STREAM and MC_* frames on the channel are not supported here */
            ch->stats.unsupported_frames++;
            complete = 0;
            bytes = NULL;
        }
    }
    if (!complete) {
        /* Not acknowledged: the packet was not fully processed */
        return;
    }
    ch->stats.packets_released++;
    {
        uint64_t delay = current_time - p->arrival_time;
        uint64_t bucket = (delay < 100000) ? delay / 100 : 1000 + (delay - 100000) / 1000;
        ch->stats.release_delay[(bucket < PICOQUIC_MCQUIC_DELAY_BUCKETS) ? bucket : PICOQUIC_MCQUIC_DELAY_BUCKETS - 1]++;
    }
    if (!ch->has_largest) {
        ch->rate_first_pn = p->pn;
        ch->rate_first_time = current_time;
    }
    if (!ch->has_largest || p->pn > ch->largest_pn) {
        ch->has_largest = 1;
        ch->largest_pn = p->pn;
        ch->largest_recv_time = current_time;
        ch->stats.largest_released = p->pn;
    }
    mcquic_ack_update_limits(cnx, ch);
    mcquic_ack_record(ch, p->pn);
}

static int mcquic_on_integrity(picoquic_cnx_t* cnx, picoquic_mcquic_ctx_t* ctx, const picoquic_mcquic_frame_t* f,
    uint64_t current_time)
{
    mcquic_channel_t* ch = mcquic_find_channel(ctx, &f->channel_id);
    size_t nb_hashes;

    if (ch == NULL || !ch->has_announce) {
        return picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
            f->frame_type, "MC_INTEGRITY for an unannounced channel");
    }
    if (!ch->joined) {
        return 0;
    }
    nb_hashes = f->u.integrity.hashes_length / ch->hash_length;
    for (size_t i = 0; i < nb_hashes; i++) {
        uint64_t pn = f->u.integrity.packet_number_start + i;
        mcquic_pending_hash_t* h = &ch->hashes[pn % MCQUIC_RING_SIZE];
        const uint8_t* hash = f->u.integrity.hashes + i * ch->hash_length;

        ch->stats.integrity_hashes++;
        if (mcquic_ack_contains(ch, pn)) {
            continue;
        }
        if (h->in_use && h->pn == pn) {
            if (memcmp(h->hash, hash, ch->hash_length) != 0) {
                return picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
                    f->frame_type, "conflicting MC_INTEGRITY");
            }
            continue;
        }
        h->in_use = 1;
        h->pn = pn;
        memcpy(h->hash, hash, ch->hash_length);
        mcquic_try_release(cnx, ch, pn, current_time);
    }
    picoquic_mcquic_send_acks(cnx, current_time, 0);
    return 0;
}

static int mcquic_server_control_frame(picoquic_cnx_t* cnx, picoquic_mcquic_ctx_t* ctx, const picoquic_mcquic_frame_t* f);

const uint8_t* picoquic_mcquic_decode_control_frame(picoquic_cnx_t* cnx, const uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t frame_type, uint64_t current_time)
{
    picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);
    picoquic_mcquic_frame_t f;
    const uint8_t* frame_start = bytes;
    size_t hash_length = 0;
    int ret = 0;

    if (ctx == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, frame_type);
        return NULL;
    }
    if (frame_type == PICOQUIC_MCQUIC_FRAME_INTEGRITY_LEN) {
        /* The hash length comes from the channel's MC_ANNOUNCE */
        picoquic_mcquic_channel_id_t id;
        mcquic_channel_t* ch;
        if (mcquic_channel_id_decode(bytes, bytes_max, &id) != NULL && (ch = mcquic_find_channel(ctx, &id)) != NULL) {
            hash_length = ch->hash_length;
        }
    }
    if ((bytes = picoquic_mcquic_frame_decode(bytes, bytes_max, frame_type, hash_length, &f)) == NULL) {
        picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type, "MC frame format");
        return NULL;
    }
    if (ctx->is_server) {
        return (mcquic_server_control_frame(cnx, ctx, &f) == 0) ? bytes : NULL;
    }
    switch (frame_type) {
    case PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V4:
    case PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V6:
        ret = mcquic_on_announce(cnx, ctx, &f);
        break;
    case PICOQUIC_MCQUIC_FRAME_KEY:
        ret = mcquic_on_key(cnx, ctx, &f);
        break;
    case PICOQUIC_MCQUIC_FRAME_JOIN:
        ret = mcquic_on_join(cnx, ctx, &f);
        break;
    case PICOQUIC_MCQUIC_FRAME_LEAVE: {
        mcquic_channel_t* ch = mcquic_find_channel(ctx, &f.channel_id);
        if (ch != NULL && ch->joined && f.u.leave.state_sequence >= ch->state_sequence) {
            ret = mcquic_leave(cnx, ch, PICOQUIC_MCQUIC_STATE_LEFT);
        }
        break;
    }
    case PICOQUIC_MCQUIC_FRAME_RETIRE: {
        mcquic_channel_t* ch = mcquic_find_channel(ctx, &f.channel_id);
        if (ch != NULL && !ch->retired) {
            ret = mcquic_leave(cnx, ch, PICOQUIC_MCQUIC_STATE_RETIRED);
            ch->retired = 1;
            mcquic_clear_key(&ch->keys[0]);
            mcquic_clear_key(&ch->keys[1]);
        }
        break;
    }
    case PICOQUIC_MCQUIC_FRAME_INTEGRITY:
    case PICOQUIC_MCQUIC_FRAME_INTEGRITY_LEN: {
        mcquic_channel_t* ch = mcquic_find_channel(ctx, &f.channel_id);
        if (ch != NULL) {
            ch->stats.integrity_frames++;
            ch->stats.integrity_bytes += (bytes - frame_start) + picoquic_frames_varint_encode_length(frame_type);
        }
        ret = mcquic_on_integrity(cnx, ctx, &f, current_time);
        break;
    }
    default:
        /* MC_ACK, MC_LIMITS and MC_STATE are sent by clients only */
        ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, frame_type, "client-only MC frame");
        break;
    }
    return (ret == 0) ? bytes : NULL;
}

static void mcquic_channel_packet(picoquic_cnx_t* cnx, mcquic_channel_t* ch, const uint8_t* bytes, size_t length,
    uint64_t current_time)
{
    uint8_t header[1 + PICOQUIC_MCQUIC_CHANNEL_ID_MAX + PICOQUIC_MCQUIC_PN_LENGTH];
    uint64_t expected;
    uint64_t pn = 0;
    size_t header_length;
    mcquic_pending_packet_t* p;

    if (mcquic_ctx(cnx)->ack_policy.test_drop > 0.0 &&
        (double)picoquic_public_uniform_random(1000000) < mcquic_ctx(cnx)->ack_policy.test_drop * 1000000.0) {
        ch->stats.test_dropped++;
        return;
    }
    ch->stats.packets_received++;
    if (ch->has_largest) {
        expected = ch->largest_pn + 1;
    }
    else {
        mcquic_key_t* k0 = &ch->keys[0];
        mcquic_key_t* k1 = &ch->keys[1];
        expected = (k1->valid && (!k0->valid || k1->key_sequence > k0->key_sequence)) ? k1->from_pn : k0->from_pn;
    }
    if (length > MCQUIC_MAX_PACKET ||
        (header_length = picoquic_mcquic_unprotect_header(ch->hp_ctx, bytes, length, ch->id.id_len, expected, header, &pn)) == 0) {
        ch->stats.header_failures++;
        return;
    }
    if (mcquic_ack_contains(ch, pn)) {
        ch->stats.packets_duplicate++;
        return;
    }
    p = &ch->packets[pn % MCQUIC_RING_SIZE];
    if (p->bytes != NULL) {
        if (p->pn == pn) {
            ch->stats.packets_duplicate++;
            return;
        }
        /* The ring slot holds an older packet that never got its hash */
        free(p->bytes);
        p->bytes = NULL;
        ch->stats.packets_evicted++;
    }
    if ((p->bytes = (uint8_t*)malloc(length)) == NULL) {
        return;
    }
    memcpy(p->bytes, bytes, length);
    p->length = length;
    p->pn = pn;
    p->arrival_time = current_time;
    p->header_length = header_length;
    memcpy(p->header, header, header_length);
    ch->stats.packets_buffered++;
    mcquic_try_release(cnx, ch, pn, current_time);
    picoquic_mcquic_send_acks(cnx, current_time, 0);
}

int picoquic_incoming_multicast_packet(picoquic_quic_t* quic, const uint8_t* bytes, size_t length,
    const struct sockaddr* addr_from, uint64_t current_time)
{
    int nb_matched = 0;

    if (length < 2) {
        return 0;
    }
    /* Every joined connection gets the packet: each has its own channel state */
    for (picoquic_cnx_t* cnx = picoquic_get_first_cnx(quic); cnx != NULL; cnx = picoquic_get_next_cnx(cnx)) {
        picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);
        if (ctx == NULL) {
            continue;
        }
        for (mcquic_channel_t* ch = ctx->first_channel; ch != NULL; ch = ch->next) {
            if (!ch->joined || length < (size_t)1 + ch->id.id_len || memcmp(bytes + 1, ch->id.id, ch->id.id_len) != 0) {
                continue;
            }
            if (addr_from != NULL && addr_from->sa_family == AF_INET && !ch->info.is_ipv6 &&
                memcmp(&((const struct sockaddr_in*)addr_from)->sin_addr, ch->info.source, 4) != 0) {
                /* Source-specific: the packet must come from the announced source */
                continue;
            }
            mcquic_channel_packet(cnx, ch, bytes, length, current_time);
            nb_matched++;
            break;
        }
    }
    return nb_matched;
}

uint64_t picoquic_mcquic_delay_bucket_limit(size_t bucket)
{
    return (bucket < 1000) ? (bucket + 1) * 100 : 100000 + (bucket - 999) * 1000;
}

void picoquic_mcquic_set_log(picoquic_cnx_t* cnx, FILE* f)
{
    picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);
    if (ctx != NULL) {
        ctx->log_file = f;
    }
}

int picoquic_mcquic_get_stats(picoquic_cnx_t* cnx, const picoquic_mcquic_channel_id_t* channel_id,
    picoquic_mcquic_stats_t* stats)
{
    picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);
    mcquic_channel_t* ch;

    if (ctx == NULL || (ch = mcquic_find_channel(ctx, channel_id)) == NULL) {
        return -1;
    }
    *stats = ch->stats;
    return 0;
}

/*
* Sender
*/

#define MCQUIC_SENDER_STALL_US 2000000

typedef struct st_picoquic_mcquic_sender_t {
    picoquic_mcquic_sender_config_t config;
    void* hp_ctx;
    void* aead_ctx;
    uint64_t next_pn;
    size_t hash_length;
    size_t batch_max;
    uint64_t batch_hold_us;
    FILE* log_file;
    uint64_t nb_clients;
    picoquic_mcquic_sender_stats_t stats;
} picoquic_mcquic_sender_t;

void picoquic_mcquic_set_default_sender_config(picoquic_mcquic_sender_config_t* config)
{
    /* Same constants as the QUICast example file server */
    static const uint8_t channel_id[8] = { 'q', 'm', 'c', 'f', 'i', 'l', 'e', '1' };

    memset(config, 0, sizeof(picoquic_mcquic_sender_config_t));
    config->channel_id.id_len = sizeof(channel_id);
    memcpy(config->channel_id.id, channel_id, sizeof(channel_id));
    config->group[0] = 232;
    config->group[1] = 1;
    config->group[2] = 2;
    config->group[3] = 3;
    config->port = 4444;
    config->cipher_suite = PICOQUIC_AES_128_GCM_SHA256;
    config->hash_alg = PICOQUIC_MCQUIC_HASH_SHA256;
    config->header_secret_len = 16;
    memset(config->header_secret, 0xaa, 16);
    config->key_sequence = 1;
    config->from_pn = 0;
    config->key_secret_len = 16;
    memset(config->key_secret, 0xcc, 16);
    config->max_rate_kibps = 1024;
    config->max_ack_delay_ms = 25;
}

int picoquic_mcquic_sender_create(picoquic_quic_t* quic, const picoquic_mcquic_sender_config_t* config)
{
    picoquic_mcquic_sender_t* sender;

    if (quic->mcquic_sender != NULL || config->header_secret_len > PICOQUIC_MCQUIC_SECRET_MAX ||
        config->key_secret_len > PICOQUIC_MCQUIC_SECRET_MAX ||
        (sender = (picoquic_mcquic_sender_t*)calloc(1, sizeof(picoquic_mcquic_sender_t))) == NULL) {
        return -1;
    }
    sender->config = *config;
    sender->next_pn = config->from_pn;
    sender->batch_max = 1;
    sender->batch_hold_us = 10000;
    sender->hash_length = picoquic_mcquic_hash_length(config->hash_alg);
    sender->hp_ctx = picoquic_mcquic_hp_create(config->cipher_suite, config->header_secret, config->header_secret_len);
    sender->aead_ctx = picoquic_mcquic_aead_create_encrypt(config->cipher_suite, config->key_secret, config->key_secret_len);
    if (sender->hash_length == 0 || sender->hp_ctx == NULL || sender->aead_ctx == NULL) {
        quic->mcquic_sender = sender;
        picoquic_mcquic_sender_delete(quic);
        return -1;
    }
    quic->mcquic_sender = sender;
    return 0;
}

void picoquic_mcquic_sender_delete(picoquic_quic_t* quic)
{
    picoquic_mcquic_sender_t* sender = quic->mcquic_sender;

    if (sender != NULL) {
        if (sender->hp_ctx != NULL) {
            ptls_cipher_free((ptls_cipher_context_t*)sender->hp_ctx);
        }
        if (sender->aead_ctx != NULL) {
            ptls_aead_free((ptls_aead_context_t*)sender->aead_ctx);
        }
        ptls_clear_memory(sender, sizeof(picoquic_mcquic_sender_t));
        free(sender);
        quic->mcquic_sender = NULL;
    }
}

void picoquic_mcquic_sender_set_log(picoquic_quic_t* quic, FILE* f)
{
    if (quic->mcquic_sender != NULL) {
        quic->mcquic_sender->log_file = f;
    }
}

int picoquic_mcquic_sender_get_stats(picoquic_quic_t* quic, picoquic_mcquic_sender_stats_t* stats)
{
    if (quic->mcquic_sender == NULL) {
        return -1;
    }
    *stats = quic->mcquic_sender->stats;
    return 0;
}

void picoquic_mcquic_sender_frame(const picoquic_mcquic_sender_config_t* config, uint64_t frame_type,
    picoquic_mcquic_frame_t* f)
{
    memset(f, 0, sizeof(picoquic_mcquic_frame_t));
    f->frame_type = frame_type;
    f->channel_id = config->channel_id;
    switch (frame_type) {
    case PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V4:
        memcpy(f->u.announce.source, config->source, 4);
        memcpy(f->u.announce.group, config->group, 4);
        f->u.announce.port = config->port;
        f->u.announce.header_protection_alg = config->cipher_suite;
        f->u.announce.header_secret_len = config->header_secret_len;
        memcpy(f->u.announce.header_secret, config->header_secret, config->header_secret_len);
        f->u.announce.aead_alg = config->cipher_suite;
        f->u.announce.hash_alg = config->hash_alg;
        f->u.announce.max_rate_kibps = config->max_rate_kibps;
        f->u.announce.max_ack_delay_ms = config->max_ack_delay_ms;
        break;
    case PICOQUIC_MCQUIC_FRAME_KEY:
        f->u.key.key_sequence = config->key_sequence;
        f->u.key.from_packet_number = config->from_pn;
        f->u.key.secret_len = config->key_secret_len;
        memcpy(f->u.key.secret, config->key_secret, config->key_secret_len);
        break;
    case PICOQUIC_MCQUIC_FRAME_JOIN:
        f->u.join.key_sequence = config->key_sequence;
        break;
    default:
        break;
    }
}

int picoquic_mcquic_receive_client_params(picoquic_cnx_t* cnx, const uint8_t* bytes, size_t length)
{
    picoquic_mcquic_ctx_t* ctx;
    picoquic_mcquic_client_params_t params;

    if (cnx->client_mode || cnx->quic->mcquic_sender == NULL || cnx->mcquic_ctx != NULL) {
        /* Not a multicast sender: ignore the parameter */
        return 0;
    }
    if (picoquic_mcquic_client_params_decode(bytes, bytes + length, &params) != bytes + length) {
        return picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "multicast_client_params TP");
    }
    if ((ctx = (picoquic_mcquic_ctx_t*)calloc(1, sizeof(picoquic_mcquic_ctx_t))) == NULL) {
        return PICOQUIC_ERROR_MEMORY;
    }
    ctx->params = params;
    ctx->is_server = 1;
    ctx->log_file = cnx->quic->mcquic_sender->log_file;
    ctx->client_index = ++cnx->quic->mcquic_sender->nb_clients;
    cnx->mcquic_ctx = ctx;
    return 0;
}

uint64_t picoquic_mcquic_max_rate_kibps(size_t payload_bytes, uint64_t interval_us, unsigned int headroom_percent)
{
    /* bits per second x headroom, over 1024 bits per Kibit */
    uint64_t num = (uint64_t)payload_bytes * 8 * 1000000ull * headroom_percent;
    uint64_t den = interval_us * 100 * 1024;

    return (den == 0) ? 0 : (num + den - 1) / den;
}

int picoquic_mcquic_get_client_ack_stats(picoquic_cnx_t* cnx, picoquic_mcquic_client_ack_stats_t* stats)
{
    picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);
    uint64_t seen = 0;

    if (ctx == NULL || !ctx->is_server) {
        return -1;
    }
    memset(stats, 0, sizeof(*stats));
    stats->client_index = ctx->client_index;
    stats->hash_alg = ctx->hash_alg;
    stats->acks = ctx->acks_received;
    stats->ack_bytes = ctx->ack_bytes;
    stats->first_ack_time = ctx->ack_first_time;
    stats->last_ack_time = ctx->ack_last_time;
    for (size_t i = 0; i < MCQUIC_MAX_TRACKED_RANGES + 2; i++) {
        if (ctx->ack_ranges_hist[i] == 0) {
            continue;
        }
        stats->ranges_max = i;
        if (stats->ranges_p50 == 0 && (seen + ctx->ack_ranges_hist[i]) * 2 >= ctx->acks_received) {
            stats->ranges_p50 = i;
        }
        seen += ctx->ack_ranges_hist[i];
    }
    return 0;
}

static int mcquic_hash_supported(uint16_t hash_alg)
{
    uint8_t hash[PICOQUIC_MCQUIC_HASH_MAX];
    static const uint8_t probe[1] = { 0 };

    /* Id 8 depends on the AEGIS-256 suite being registered: try it */
    return picoquic_mcquic_hash_length(hash_alg) != 0 &&
        picoquic_mcquic_integrity_hash(hash_alg, probe, sizeof(probe), hash, sizeof(hash)) == 0;
}

uint16_t picoquic_mcquic_choose_aead_alg(uint16_t configured, const picoquic_mcquic_client_params_t* params)
{
    /* The channel packets are protected once, with the configured suite, for
     * every client: there is no other suite to fall back to */
    return mcquic_param_contains(params->cipher_suites, params->nb_cipher_suites, configured) ? configured : 0;
}

uint16_t picoquic_mcquic_choose_hash_alg(uint16_t configured, const picoquic_mcquic_client_params_t* params)
{
    if (mcquic_param_contains(params->hash_algs, params->nb_hash_algs, configured) && mcquic_hash_supported(configured)) {
        return configured;
    }
    /* The client's list is in its order of preference (draft-08 3) */
    for (size_t i = 0; i < params->nb_hash_algs; i++) {
        if (mcquic_hash_supported(params->hash_algs[i])) {
            return params->hash_algs[i];
        }
    }
    return 0;
}

/* The client's algorithm ids, comma-separated, for the log */
static void mcquic_alg_list(char* list, size_t list_max, const uint16_t* algs, size_t nb_algs, int hex)
{
    size_t l = 0;

    list[0] = 0;
    for (size_t i = 0; i < nb_algs && l + 8 < list_max; i++) {
        if (i > 0) {
            list[l++] = ',';
        }
        l += (size_t)snprintf(list + l, list_max - l, hex ? "0x%04x" : "%u", algs[i]);
    }
}

int picoquic_mcquic_server_start(picoquic_cnx_t* cnx)
{
    picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);
    picoquic_mcquic_sender_t* sender = cnx->quic->mcquic_sender;
    picoquic_mcquic_frame_t f;
    char idh[2 * PICOQUIC_MCQUIC_CHANNEL_ID_MAX + 1];
    int ret;

    if (ctx == NULL || !ctx->is_server || sender == NULL || ctx->announced) {
        return 0;
    }
    if (!ctx->params.ipv4_allowed) {
        mcquic_log(ctx, "client does not allow IPv4 channels; not announcing");
        return 0;
    }
    ctx->announced = 1;
    if (picoquic_mcquic_choose_aead_alg(sender->config.cipher_suite, &ctx->params) == 0) {
        char list[8 * PICOQUIC_MCQUIC_ALGS_MAX + 1];
        mcquic_alg_list(list, sizeof(list), ctx->params.cipher_suites, ctx->params.nb_cipher_suites, 1);
        mcquic_log(ctx, "client lists no supported AEAD (%s; the channel uses 0x%04x); not announcing", list,
            sender->config.cipher_suite);
        return 0;
    }
    if ((ctx->hash_alg = picoquic_mcquic_choose_hash_alg(sender->config.hash_alg, &ctx->params)) == 0) {
        char list[8 * PICOQUIC_MCQUIC_ALGS_MAX + 1];
        mcquic_alg_list(list, sizeof(list), ctx->params.hash_algs, ctx->params.nb_hash_algs, 0);
        mcquic_log(ctx, "client lists no supported integrity hash (%s); not announcing", list);
        return 0;
    }
    ctx->hash_length = picoquic_mcquic_hash_length(ctx->hash_alg);
    picoquic_mcquic_sender_frame(&sender->config, PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V4, &f);
    f.u.announce.hash_alg = ctx->hash_alg;
    if ((ret = mcquic_queue_frame(cnx, &f)) == 0) {
        picoquic_mcquic_sender_frame(&sender->config, PICOQUIC_MCQUIC_FRAME_KEY, &f);
        ret = mcquic_queue_frame(cnx, &f);
    }
    mcquic_log(ctx, "MC_ANNOUNCE and MC_KEY sent: channel=%s key_sequence=%llu aead=0x%04x hash=%u", mcquic_id_hex(&sender->config.channel_id, idh),
        (unsigned long long)sender->config.key_sequence, sender->config.cipher_suite, ctx->hash_alg);
    return ret;
}

static int mcquic_server_control_frame(picoquic_cnx_t* cnx, picoquic_mcquic_ctx_t* ctx, const picoquic_mcquic_frame_t* f)
{
    picoquic_mcquic_sender_t* sender = cnx->quic->mcquic_sender;
    char idh[2 * PICOQUIC_MCQUIC_CHANNEL_ID_MAX + 1];
    int ret = 0;

    switch (f->frame_type) {
    case PICOQUIC_MCQUIC_FRAME_LIMITS:
        mcquic_log(ctx, "MC_LIMITS received: sequence=%llu ipv4=%d ipv6=%d rate=%lluKibps channel_ids=%llu max_joined=%llu",
            (unsigned long long)f->u.limits.sequence, f->u.limits.ipv4_allowed, f->u.limits.ipv6_allowed,
            (unsigned long long)f->u.limits.max_rate_kibps, (unsigned long long)f->u.limits.max_channel_ids,
            (unsigned long long)f->u.limits.max_joined);
        ctx->params.ipv4_allowed = f->u.limits.ipv4_allowed;
        ctx->limits_sequence = f->u.limits.sequence;
        /* As the example server: join once the client has sent its limits */
        if (sender != NULL && ctx->announced && !ctx->join_sent && f->u.limits.ipv4_allowed && f->u.limits.max_joined > 0) {
            picoquic_mcquic_frame_t join;
            picoquic_mcquic_sender_frame(&sender->config, PICOQUIC_MCQUIC_FRAME_JOIN, &join);
            join.u.join.limits_sequence = f->u.limits.sequence;
            join.u.join.state_sequence = 0;
            ctx->join_sent = 1;
            mcquic_log(ctx, "MC_JOIN sent: channel=%s limits_sequence=%llu key_sequence=%llu",
                mcquic_id_hex(&join.channel_id, idh), (unsigned long long)join.u.join.limits_sequence,
                (unsigned long long)join.u.join.key_sequence);
            ret = mcquic_queue_frame(cnx, &join);
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_STATE:
    case PICOQUIC_MCQUIC_FRAME_STATE_APP:
        mcquic_log(ctx, "MC_STATE received: channel=%s sequence=%llu state=%u reason=%llu",
            mcquic_id_hex(&f->channel_id, idh), (unsigned long long)f->u.state.sequence, f->u.state.state,
            (unsigned long long)f->u.state.reason);
        if (sender != NULL && f->channel_id.id_len == sender->config.channel_id.id_len &&
            memcmp(f->channel_id.id, sender->config.channel_id.id, f->channel_id.id_len) == 0) {
            ctx->sender_joined = (f->u.state.state == PICOQUIC_MCQUIC_STATE_JOINED);
        }
        break;
    case PICOQUIC_MCQUIC_FRAME_ACK:
    case PICOQUIC_MCQUIC_FRAME_ACK_ECN:
        /* Counted and logged only: there is no multicast retransmission */
    {
        uint8_t tmp[MCQUIC_MAX_PACKET];
        uint8_t* e = picoquic_mcquic_frame_encode(tmp, tmp + sizeof(tmp), f);
        uint64_t now = picoquic_get_quic_time(cnx->quic);
        uint64_t nb_ranges = f->u.ack.range_count + 1;
        uint64_t frame_bytes = (e != NULL) ? (uint64_t)(e - tmp) : 0;

        ctx->ack_bytes += frame_bytes;
        ctx->ack_ranges_hist[(nb_ranges <= MCQUIC_MAX_TRACKED_RANGES) ? nb_ranges : MCQUIC_MAX_TRACKED_RANGES + 1]++;
        if (ctx->acks_received == 0) {
            ctx->ack_first_time = now;
        }
        ctx->ack_last_time = now;
        mcquic_log(ctx, "MC_ACK arrival: client=%llu t_us=%llu ranges=%llu bytes=%llu", (unsigned long long)ctx->client_index,
            (unsigned long long)now, (unsigned long long)nb_ranges, (unsigned long long)frame_bytes);
    }
        ctx->acks_received++;
        if (f->u.ack.largest > ctx->largest_acked || ctx->acks_received == 1) {
            ctx->largest_acked = f->u.ack.largest;
        }
        if (sender != NULL) {
            sender->stats.acks_received++;
            if (f->u.ack.largest > sender->stats.largest_acked) {
                sender->stats.largest_acked = f->u.ack.largest;
            }
        }
        mcquic_log(ctx, "MC_ACK received: channel=%s largest=%llu first_range=%llu ranges=%llu ack_delay=%llu",
            mcquic_id_hex(&f->channel_id, idh), (unsigned long long)f->u.ack.largest,
            (unsigned long long)f->u.ack.first_range, (unsigned long long)f->u.ack.range_count,
            (unsigned long long)f->u.ack.ack_delay);
        break;
    default:
        ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, f->frame_type, "server-only MC frame");
        break;
    }
    return ret;
}

static void mcquic_drop_queued_integrity(picoquic_cnx_t* cnx, picoquic_mcquic_ctx_t* ctx)
{
    picoquic_misc_frame_header_t* misc = cnx->first_misc_frame;

    while (misc != NULL) {
        picoquic_misc_frame_header_t* next = misc->next_misc_frame;
        const uint8_t* frame = ((const uint8_t*)misc) + sizeof(picoquic_misc_frame_header_t);
        uint64_t frame_type = 0;

        if (picoquic_frames_varint_decode(frame, frame + misc->length, &frame_type) != NULL &&
            (frame_type == PICOQUIC_MCQUIC_FRAME_INTEGRITY || frame_type == PICOQUIC_MCQUIC_FRAME_INTEGRITY_LEN)) {
            picoquic_delete_misc_or_dg(&cnx->first_misc_frame, &cnx->last_misc_frame, misc);
            ctx->integrity_dropped++;
        }
        misc = next;
    }
}

/* Hashes per MC_INTEGRITY: the configured maximum, capped so that the frame fits
 * in a 1-RTT packet on the connection's path */
static size_t mcquic_batch_limit(picoquic_cnx_t* cnx, picoquic_mcquic_sender_t* sender, size_t hash_length)
{
    size_t mtu = (cnx->path != NULL && cnx->path[0] != NULL && cnx->path[0]->send_mtu > 0) ?
        cnx->path[0]->send_mtu : PICOQUIC_INITIAL_MTU_IPV4;
    /* Short header (1 + 20-byte CID + 4-byte PN), AEAD tag, then the frame header:
     * type (4), channel ID (1 + 20), packet number start (8), count (8) */
    size_t overhead = 1 + 20 + 4 + 16 + 4 + 1 + PICOQUIC_MCQUIC_CHANNEL_ID_MAX + 8 + 8;
    size_t cap = (mtu > overhead) ? (mtu - overhead) / hash_length : 1;
    size_t limit = (sender->batch_max < cap) ? sender->batch_max : cap;

    if (limit > MCQUIC_INTEGRITY_BATCH_MAX) {
        limit = MCQUIC_INTEGRITY_BATCH_MAX;
    }
    return (limit == 0) ? 1 : limit;
}

static void mcquic_flush_batch(picoquic_cnx_t* cnx, picoquic_mcquic_ctx_t* ctx, picoquic_mcquic_sender_t* sender)
{
    picoquic_mcquic_frame_t f;
    uint8_t buffer[MCQUIC_MAX_PACKET];
    uint8_t* bytes;

    if (ctx->batch_count == 0) {
        return;
    }
    memset(&f, 0, sizeof(f));
    f.frame_type = PICOQUIC_MCQUIC_FRAME_INTEGRITY_LEN;
    f.channel_id = sender->config.channel_id;
    f.u.integrity.packet_number_start = ctx->batch_pn_start;
    f.u.integrity.has_count = 1;
    f.u.integrity.hash_count = ctx->batch_count;
    f.u.integrity.hashes = ctx->batch_hashes;
    f.u.integrity.hashes_length = ctx->batch_count * ctx->hash_length;
    if ((bytes = picoquic_mcquic_frame_encode(buffer, buffer + sizeof(buffer), &f)) != NULL &&
        picoquic_queue_misc_frame(cnx, buffer, bytes - buffer, 0, picoquic_packet_context_application) == 0) {
        sender->stats.integrity_sent += ctx->batch_count;
        sender->stats.integrity_frames++;
        sender->stats.integrity_bytes += bytes - buffer;
    }
    ctx->batch_count = 0;
}

int picoquic_mcquic_sender_get_integrity_batch(picoquic_quic_t* quic, size_t* max_hashes, uint64_t* max_hold_us)
{
    if (quic->mcquic_sender == NULL) {
        return -1;
    }
    *max_hashes = quic->mcquic_sender->batch_max;
    *max_hold_us = quic->mcquic_sender->batch_hold_us;
    return 0;
}

int picoquic_mcquic_sender_set_integrity_batch(picoquic_quic_t* quic, size_t max_hashes, uint64_t max_hold_us)
{
    if (quic->mcquic_sender == NULL || max_hashes == 0 || max_hashes > MCQUIC_INTEGRITY_BATCH_MAX) {
        return -1;
    }
    quic->mcquic_sender->batch_max = max_hashes;
    quic->mcquic_sender->batch_hold_us = max_hold_us;
    return 0;
}

uint64_t picoquic_mcquic_sender_flush(picoquic_quic_t* quic, uint64_t current_time, int force)
{
    picoquic_mcquic_sender_t* sender = quic->mcquic_sender;
    uint64_t next = UINT64_MAX;

    if (sender == NULL) {
        return next;
    }
    for (picoquic_cnx_t* cnx = picoquic_get_first_cnx(quic); cnx != NULL; cnx = picoquic_get_next_cnx(cnx)) {
        picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);
        if (ctx == NULL || !ctx->is_server || ctx->batch_count == 0) {
            continue;
        }
        if (force || current_time >= ctx->batch_oldest + sender->batch_hold_us) {
            mcquic_flush_batch(cnx, ctx, sender);
        }
        else if (ctx->batch_oldest + sender->batch_hold_us < next) {
            next = ctx->batch_oldest + sender->batch_hold_us;
        }
    }
    return next;
}

size_t picoquic_mcquic_sender_prepare(picoquic_quic_t* quic, const uint8_t* payload, size_t payload_length,
    uint64_t current_time, uint8_t* bytes, size_t bytes_max, uint64_t* pn)
{
    picoquic_mcquic_sender_t* sender = quic->mcquic_sender;
    uint8_t plaintext[MCQUIC_MAX_PACKET];
    uint8_t* p;
    size_t length;
    uint8_t hash[PICOQUIC_MCQUIC_HASH_MAX];
    uint8_t alg_hash[PICOQUIC_MCQUIC_ALGS_MAX + 1][PICOQUIC_MCQUIC_HASH_MAX];
    int alg_done[PICOQUIC_MCQUIC_ALGS_MAX + 1];

    if (sender == NULL || payload_length + 16 > sizeof(plaintext)) {
        return 0;
    }
    /* One DATAGRAM frame with a length */
    if ((p = picoquic_frames_varint_encode(plaintext, plaintext + sizeof(plaintext), picoquic_frame_type_datagram_l)) == NULL ||
        (p = picoquic_frames_varint_encode(p, plaintext + sizeof(plaintext), payload_length)) == NULL) {
        return 0;
    }
    memcpy(p, payload, payload_length);
    p += payload_length;
    length = picoquic_mcquic_protect(sender->hp_ctx, sender->aead_ctx, (int)(sender->config.key_sequence & 1),
        &sender->config.channel_id, sender->next_pn, plaintext, p - plaintext, bytes, bytes_max);
    if (length == 0 || picoquic_mcquic_integrity_hash(sender->config.hash_alg, bytes, length, hash, sizeof(hash)) != 0) {
        return 0;
    }
    *pn = sender->next_pn++;
    sender->stats.packets_sent++;

    /* Each joined connection gets the hash, in the algorithm announced to it, in
     * its MC_INTEGRITY batch; each other algorithm is computed once per packet */
    memset(alg_done, 0, sizeof(alg_done));
    if (sender->config.hash_alg <= PICOQUIC_MCQUIC_ALGS_MAX) {
        memcpy(alg_hash[sender->config.hash_alg], hash, sender->hash_length);
        alg_done[sender->config.hash_alg] = 1;
    }
    for (picoquic_cnx_t* cnx = picoquic_get_first_cnx(quic); cnx != NULL; cnx = picoquic_get_next_cnx(cnx)) {
        picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);
        if (ctx == NULL || !ctx->is_server || !ctx->sender_joined) {
            continue;
        }
        if (cnx->cnx_state != picoquic_state_ready || current_time > cnx->latest_receive_time + MCQUIC_SENDER_STALL_US) {
            /* A client that went silent must not accumulate frames: drop what is
             * queued and stop sending it hashes until it is heard from again. */
            if (ctx->sender_joined == 1) {
                mcquic_log(ctx, "client silent or closing; dropping queued MC_INTEGRITY frames");
                mcquic_drop_queued_integrity(cnx, ctx);
                ctx->sender_joined = 2;
            }
            ctx->batch_count = 0;
            sender->stats.integrity_dropped++;
            continue;
        }
        ctx->sender_joined = 1;
        if (ctx->hash_alg == 0 || ctx->hash_alg > PICOQUIC_MCQUIC_ALGS_MAX) {
            continue;
        }
        if (!alg_done[ctx->hash_alg]) {
            if (picoquic_mcquic_integrity_hash(ctx->hash_alg, bytes, length, alg_hash[ctx->hash_alg], PICOQUIC_MCQUIC_HASH_MAX) != 0) {
                continue;
            }
            alg_done[ctx->hash_alg] = 1;
        }
        if (ctx->batch_hashes == NULL &&
            (ctx->batch_hashes = (uint8_t*)malloc(MCQUIC_INTEGRITY_BATCH_MAX * PICOQUIC_MCQUIC_HASH_MAX)) == NULL) {
            continue;
        }
        if (ctx->batch_count > 0 && ctx->batch_pn_start + ctx->batch_count != *pn) {
            mcquic_flush_batch(cnx, ctx, sender);
        }
        if (ctx->batch_count == 0) {
            ctx->batch_pn_start = *pn;
            ctx->batch_oldest = current_time;
        }
        memcpy(ctx->batch_hashes + ctx->batch_count * ctx->hash_length, alg_hash[ctx->hash_alg], ctx->hash_length);
        ctx->batch_count++;
        if (ctx->batch_count >= mcquic_batch_limit(cnx, sender, ctx->hash_length)) {
            mcquic_flush_batch(cnx, ctx, sender);
        }
    }
    return length;
}

int picoquic_mcquic_sender_get_config(picoquic_quic_t* quic, picoquic_mcquic_sender_config_t* config)
{
    if (quic->mcquic_sender == NULL) {
        return -1;
    }
    *config = quic->mcquic_sender->config;
    return 0;
}

int picoquic_mcquic_sender_publish(picoquic_quic_t* quic, const uint8_t* payload, size_t payload_length,
    uint64_t current_time)
{
    size_t slot_size = 0;
    uint8_t* slot;
    size_t length;
    uint64_t pn = 0;

    if (quic->mcquic_sender == NULL || (slot = mcquic_loop_queue_slot(quic, &slot_size)) == NULL) {
        return -1;
    }
    if ((length = picoquic_mcquic_sender_prepare(quic, payload, payload_length, current_time, slot, slot_size, &pn)) == 0) {
        return -1;
    }
    mcquic_loop_queue_commit(quic, length);
    return 0;
}

uint64_t picoquic_mcquic_service(picoquic_quic_t* quic, uint64_t current_time)
{
    uint64_t next = UINT64_MAX;

    for (picoquic_cnx_t* cnx = picoquic_get_first_cnx(quic); cnx != NULL; cnx = picoquic_get_next_cnx(cnx)) {
        picoquic_mcquic_ctx_t* ctx = mcquic_ctx(cnx);
        if (ctx == NULL || ctx->is_server) {
            continue;
        }
        picoquic_mcquic_send_acks(cnx, current_time, 0);
        for (mcquic_channel_t* ch = ctx->first_channel; ch != NULL; ch = ch->next) {
            if (ch->joined && ch->ack_pending && ch->nb_ranges > 0) {
                uint64_t due = mcquic_ack_due(ctx, ch, current_time);
                if (due < next) {
                    next = due;
                }
            }
        }
    }
    if (quic->mcquic_sender != NULL) {
        uint64_t next_flush = picoquic_mcquic_sender_flush(quic, current_time, 0);
        if (next_flush < next) {
            next = next_flush;
        }
    }
    return next;
}
