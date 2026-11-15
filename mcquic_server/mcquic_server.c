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
* mcquic_server: sends a file over a multicast QUIC channel.
*
* Counterpart of mcquic_client, and of the QUICast tokio-quiche example
* async_multicast_file_server, with the same constants: channel ID
* "qmcfile1", 232.1.2.3:4444, AES-128-GCM, SHA-256 integrity hashes, fixed
* header and payload secrets. One publisher per process sends, every 20 ms,
* the next "QMCF" datagram of the file (a manifest every 32 chunks, 1024-byte
* chunks, looping) as one channel packet to (S,G). Each unicast client that
* sends the multicast client transport parameter (ALPN "h3") gets MC_ANNOUNCE
* and MC_KEY, then MC_JOIN after its MC_LIMITS, then one MC_INTEGRITY per
* channel packet once it reports Joined. Its MC_ACKs are logged.
*
* The server runs picoquic's packet loop, which also owns the channel socket:
* the publisher queues channel packets from the loop's time check callback.
*
* Usage: mcquic_server [options] port
*   -a addr   IPv4 address to listen on, also the default channel source and interface
*   -c file   certificate (PEM)
*   -k file   private key (PEM)
*   -f file   file to send
*   -S addr   channel source address (default: -a)
*   -I addr   address of the interface to send the channel on (default: -a)
*   -g addr   group address (default 232.1.2.3)
*   -P port   group port (default 4444)
*   -i ms     publish interval (default 20)
*   -t secs   stop after this many seconds (default 600)
*   -s secs   statistics interval (default 5)
*   -H n      maximum hashes per MC_INTEGRITY frame (default 1; capped to fit the path MTU)
*   -T ms     maximum time a hash waits for its MC_INTEGRITY frame (default 10)
*   -A id     integrity hash algorithm (1-8, default 1)
*/

#ifdef _WINDOWS
#error "mcquic_server is written for POSIX systems"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_packet_loop.h"
#include "mcquic.h"

#define QMCF_KIND_MANIFEST 1
#define QMCF_KIND_CHUNK 2
#define MCS_MAX_PACKET 2048
#define MCS_CHUNK_LENGTH 1024
#define MCS_MANIFEST_INTERVAL 32

typedef struct st_mcs_file_t {
    const char* name;
    uint8_t* bytes;
    uint64_t length;
    uint32_t total_chunks;
    uint64_t transfer_id;
    uint32_t next_chunk;
    uint32_t since_manifest;
} mcs_file_t;

static volatile sig_atomic_t mcs_stop = 0;

static void mcs_on_signal(int sig)
{
    (void)sig;
    mcs_stop = 1;
}

static uint8_t* mcs_u16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return p + 2; }
static uint8_t* mcs_u32(uint8_t* p, uint32_t v) { return mcs_u16(mcs_u16(p, (uint16_t)(v >> 16)), (uint16_t)v); }
static uint8_t* mcs_u64(uint8_t* p, uint64_t v) { return mcs_u32(mcs_u32(p, (uint32_t)(v >> 32)), (uint32_t)v); }

static void mcs_print_time(void)
{
    uint64_t now = picoquic_current_time();
    printf("%llu.%06llu ", (unsigned long long)(now / 1000000), (unsigned long long)(now % 1000000));
}

static int mcs_load(mcs_file_t* f, const char* path)
{
    FILE* fp = fopen(path, "rb");
    const char* slash = strrchr(path, '/');
    uint64_t h = 0xcbf29ce484222325ull;
    long length;

    memset(f, 0, sizeof(mcs_file_t));
    f->name = (slash == NULL) ? path : slash + 1;
    if (fp == NULL || fseek(fp, 0, SEEK_END) != 0 || (length = ftell(fp)) < 0 || fseek(fp, 0, SEEK_SET) != 0 ||
        (f->bytes = (uint8_t*)malloc((size_t)length + 1)) == NULL ||
        fread(f->bytes, 1, (size_t)length, fp) != (size_t)length || strlen(f->name) > 0xffff) {
        if (fp != NULL) {
            fclose(fp);
        }
        return -1;
    }
    fclose(fp);
    f->length = (uint64_t)length;
    f->total_chunks = (uint32_t)((f->length + MCS_CHUNK_LENGTH - 1) / MCS_CHUNK_LENGTH);
    /* The transfer ID only has to change with the content: FNV-1a over the
     * name, length, chunk size and bytes (the example uses Rust's DefaultHasher) */
    for (const char* c = f->name; *c != 0; c++) {
        h = (h ^ (uint8_t)*c) * 0x100000001b3ull;
    }
    for (int i = 0; i < 8; i++) {
        h = (h ^ (uint8_t)(f->length >> (8 * i))) * 0x100000001b3ull;
        h = (h ^ (uint8_t)((uint64_t)MCS_CHUNK_LENGTH >> (8 * i))) * 0x100000001b3ull;
    }
    for (uint64_t i = 0; i < f->length; i++) {
        h = (h ^ f->bytes[i]) * 0x100000001b3ull;
    }
    f->transfer_id = h;
    f->since_manifest = MCS_MANIFEST_INTERVAL;
    return 0;
}

/* The QMCF format of the QUICast example (multicast_file.rs), and its looping
 * order: a manifest, then MCS_MANIFEST_INTERVAL chunks, and so on. */
static size_t mcs_next_datagram(mcs_file_t* f, uint8_t* out)
{
    uint8_t* p = out;

    memcpy(p, "QMCF", 4);
    p[4] = 1;
    if (f->total_chunks == 0 || f->since_manifest >= MCS_MANIFEST_INTERVAL) {
        size_t name_len = strlen(f->name);
        f->since_manifest = 0;
        p[5] = QMCF_KIND_MANIFEST;
        p = mcs_u64(p + 6, f->transfer_id);
        p = mcs_u64(p, f->length);
        p = mcs_u32(p, MCS_CHUNK_LENGTH);
        p = mcs_u32(p, f->total_chunks);
        p = mcs_u16(p, (uint16_t)name_len);
        memcpy(p, f->name, name_len);
        return (p + name_len) - out;
    }
    else {
        uint32_t index = f->next_chunk;
        uint64_t start = (uint64_t)index * MCS_CHUNK_LENGTH;
        uint32_t length = (uint32_t)((f->length - start < MCS_CHUNK_LENGTH) ? f->length - start : MCS_CHUNK_LENGTH);
        f->next_chunk = (index + 1) % f->total_chunks;
        f->since_manifest++;
        p[5] = QMCF_KIND_CHUNK;
        p = mcs_u64(p + 6, f->transfer_id);
        p = mcs_u32(p, index);
        p = mcs_u32(p, length);
        memcpy(p, f->bytes + start, length);
        return (p + length) - out;
    }
}

static int mcs_callback(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t event, void* callback_ctx, void* v_stream_ctx)
{
    (void)stream_id; (void)bytes; (void)length; (void)callback_ctx; (void)v_stream_ctx;
    switch (event) {
    case picoquic_callback_ready:
        mcs_print_time();
        printf("connection ready; starting multicast on it\n");
        fflush(stdout);
        return picoquic_mcquic_server_start(cnx);
    case picoquic_callback_close:
    case picoquic_callback_application_close:
    case picoquic_callback_stateless_reset:
        mcs_print_time();
        printf("connection closed (event %d)\n", (int)event);
        fflush(stdout);
        return 0;
    default:
        return 0;
    }
}

static long mcs_rss_kb(void)
{
    struct rusage ru;
    return (getrusage(RUSAGE_SELF, &ru) == 0) ? ru.ru_maxrss : -1;
}

static void mcs_print_stats(picoquic_quic_t* quic, uint64_t start_time)
{
    picoquic_mcquic_sender_stats_t st;
    struct rusage ru;
    int nb_cnx = 0;

    for (picoquic_cnx_t* c = picoquic_get_first_cnx(quic); c != NULL; c = picoquic_get_next_cnx(c)) {
        nb_cnx++;
    }
    if (picoquic_mcquic_sender_get_stats(quic, &st) == 0 && getrusage(RUSAGE_SELF, &ru) == 0) {
        mcs_print_time();
        printf("stats: uptime=%llus packets=%llu integrity_sent=%llu integrity_frames=%llu integrity_bytes=%llu "
            "integrity_skipped=%llu acks=%llu largest_acked=%llu connections=%d cpu_user=%ld.%03lds cpu_sys=%ld.%03lds max_rss=%ldKB\n",
            (unsigned long long)((picoquic_current_time() - start_time) / 1000000),
            (unsigned long long)st.packets_sent, (unsigned long long)st.integrity_sent,
            (unsigned long long)st.integrity_frames, (unsigned long long)st.integrity_bytes,
            (unsigned long long)st.integrity_dropped, (unsigned long long)st.acks_received,
            (unsigned long long)st.largest_acked, nb_cnx, (long)ru.ru_utime.tv_sec, (long)ru.ru_utime.tv_usec / 1000,
            (long)ru.ru_stime.tv_sec, (long)ru.ru_stime.tv_usec / 1000, mcs_rss_kb());
        fflush(stdout);
    }
}

static void usage(void)
{
    fprintf(stderr, "usage: mcquic_server -a addr -c cert -k key -f file [-S source] [-I if_addr] [-g group] [-P port] [-i ms] "
        "[-t secs] [-s secs] [-H n] [-T ms] [-A id] port\n");
    exit(1);
}

typedef struct st_mcs_loop_ctx_t {
    mcs_file_t* file;
    uint64_t start_time;
    uint64_t max_run_us;
    uint64_t interval_us;
    uint64_t stats_us;
    uint64_t next_publish;
    uint64_t next_stats;
    uint64_t publish_failures;
} mcs_loop_ctx_t;

/* Publishes the file from the loop's time check: every interval, the next QMCF
 * datagram goes into the sender's queue, which the loop sends to (S,G). */
static int mcs_loop_callback(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, void* callback_ctx, void* callback_arg)
{
    mcs_loop_ctx_t* lc = (mcs_loop_ctx_t*)callback_ctx;

    switch (cb_mode) {
    case picoquic_packet_loop_ready:
        ((picoquic_packet_loop_options_t*)callback_arg)->do_time_check = 1;
        return 0;
    case picoquic_packet_loop_time_check: {
        packet_loop_time_check_arg_t* arg = (packet_loop_time_check_arg_t*)callback_arg;
        uint64_t now = arg->current_time;

        if (mcs_stop || now >= lc->start_time + lc->max_run_us) {
            return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
        }
        if (now >= lc->next_publish) {
            uint8_t datagram[MCS_MAX_PACKET];
            size_t dg_length = mcs_next_datagram(lc->file, datagram);
            if (picoquic_mcquic_sender_publish(quic, datagram, dg_length, now) != 0) {
                lc->publish_failures++;
            }
            lc->next_publish += lc->interval_us;
            if (lc->next_publish < now) {
                lc->next_publish = now + lc->interval_us;
            }
        }
        if (now >= lc->next_stats) {
            mcs_print_stats(quic, lc->start_time);
            lc->next_stats = now + lc->stats_us;
        }
        if ((int64_t)(lc->next_publish - now) < arg->delta_t) {
            arg->delta_t = (int64_t)(lc->next_publish - now);
        }
        return 0;
    }
    default:
        return 0;
    }
}

int main(int argc, char** argv)
{
    picoquic_mcquic_sender_config_t config;
    struct in_addr addr = { 0 };
    struct in_addr source = { 0 };
    struct in_addr if_addr = { 0 };
    struct in_addr group;
    struct sockaddr_in if_sa;
    const char* cert = NULL;
    const char* key = NULL;
    const char* path = NULL;
    uint64_t interval_us = 20000;
    uint64_t max_run_us = 600 * 1000000ull;
    uint64_t stats_us = 5 * 1000000ull;
    size_t batch_max = 1;
    uint64_t batch_hold_us = 10000;
    picoquic_packet_loop_param_t param;
    mcs_loop_ctx_t lc;
    mcs_file_t file;
    picoquic_quic_t* quic;
    picoquic_mcquic_loop_stats_t ls;
    uint64_t start_time;
    int opt;
    int ret = 0;

    picoquic_mcquic_set_default_sender_config(&config);
    memcpy(&group, config.group, 4);
    while ((opt = getopt(argc, argv, "a:c:k:f:S:I:g:P:i:t:s:H:T:A:")) != -1) {
        switch (opt) {
        case 'a': if (inet_pton(AF_INET, optarg, &addr) != 1) usage(); break;
        case 'c': cert = optarg; break;
        case 'k': key = optarg; break;
        case 'f': path = optarg; break;
        case 'S': if (inet_pton(AF_INET, optarg, &source) != 1) usage(); break;
        case 'I': if (inet_pton(AF_INET, optarg, &if_addr) != 1) usage(); break;
        case 'g': if (inet_pton(AF_INET, optarg, &group) != 1) usage(); break;
        case 'P': config.port = (uint16_t)atoi(optarg); break;
        case 'i': interval_us = (uint64_t)atoi(optarg) * 1000ull; break;
        case 't': max_run_us = (uint64_t)atoi(optarg) * 1000000ull; break;
        case 's': stats_us = (uint64_t)atoi(optarg) * 1000000ull; break;
        case 'H': batch_max = (size_t)atoi(optarg); break;
        case 'T': batch_hold_us = (uint64_t)atoi(optarg) * 1000ull; break;
        case 'A': config.hash_alg = (uint16_t)atoi(optarg); if (picoquic_mcquic_hash_length(config.hash_alg) == 0) usage(); break;
        default: usage();
        }
    }
    if (argc - optind != 1 || cert == NULL || key == NULL || path == NULL || addr.s_addr == 0 || interval_us == 0) {
        usage();
    }
    if (source.s_addr == 0) {
        source = addr;
    }
    if (if_addr.s_addr == 0) {
        if_addr = addr;
    }
    memcpy(config.source, &source, 4);
    memcpy(config.group, &group, 4);
    if (mcs_load(&file, path) != 0) {
        fprintf(stderr, "cannot read %s\n", path);
        return 1;
    }

    start_time = picoquic_current_time();
    quic = picoquic_create(16, cert, key, NULL, "h3", mcs_callback, NULL, NULL, NULL, NULL, start_time, NULL, NULL, NULL, 0);
    memset(&if_sa, 0, sizeof(if_sa));
    if_sa.sin_family = AF_INET;
    if_sa.sin_addr = if_addr;
    if (quic == NULL || picoquic_mcquic_sender_create(quic, &config) != 0 ||
        picoquic_mcquic_sender_set_integrity_batch(quic, batch_max, batch_hold_us) != 0 ||
        picoquic_mcquic_loop_config(quic, (struct sockaddr*)&if_sa, 1, 1) != 0) {
        fprintf(stderr, "cannot create the QUIC context, the sender or the multicast loop configuration\n");
        return 1;
    }
    picoquic_mcquic_sender_set_log(quic, stdout);
    /* A client that vanishes is dropped after 30 s of silence */
    picoquic_set_default_idle_timeout(quic, 30000);
    signal(SIGINT, mcs_on_signal);
    signal(SIGTERM, mcs_on_signal);

    mcs_print_time();
    printf("listening on %s:%s; file=%s bytes=%llu chunks=%u transfer=%llu\n", inet_ntoa(addr), argv[optind], file.name,
        (unsigned long long)file.length, file.total_chunks, (unsigned long long)file.transfer_id);
    mcs_print_time();
    printf("channel qmcfile1: source=%s ", inet_ntoa(source));
    printf("group=%s:%u ", inet_ntoa(group), config.port);
    printf("interface=%s interval=%llums hash_alg=%u hashes_per_integrity=%zu max_hold=%llums\n", inet_ntoa(if_addr),
        (unsigned long long)(interval_us / 1000), config.hash_alg, batch_max, (unsigned long long)(batch_hold_us / 1000));
    fflush(stdout);

    memset(&param, 0, sizeof(param));
    param.local_port = (uint16_t)atoi(argv[optind]);
    param.local_af = AF_INET;
    param.local_addr[0].ss_family = AF_INET;
    ((struct sockaddr_in*)&param.local_addr[0])->sin_addr = addr;
    memset(&lc, 0, sizeof(lc));
    lc.file = &file;
    lc.start_time = start_time;
    lc.max_run_us = max_run_us;
    lc.interval_us = interval_us;
    lc.stats_us = stats_us;
    lc.next_publish = start_time;
    lc.next_stats = start_time + stats_us;
    ret = picoquic_packet_loop_v2(quic, &param, mcs_loop_callback, &lc);
    if (mcs_stop && ret != 0) {
        /* A signal interrupts the loop's wait */
        ret = 0;
    }
    mcs_print_stats(quic, start_time);
    if (picoquic_mcquic_loop_get_stats(quic, &ls) == 0) {
        mcs_print_time();
        printf("loop: channel_packets_sent=%llu send_errors=%llu queue_full=%llu publish_failures=%llu\n",
            (unsigned long long)ls.packets_sent, (unsigned long long)ls.send_errors, (unsigned long long)ls.queue_full,
            (unsigned long long)lc.publish_failures);
    }
    mcs_print_time();
    printf("stopping (loop returned %d)\n", ret);
    fflush(stdout);
    picoquic_free(quic);
    free(file.bytes);
    return ret;
}
