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
* mcquic_client: receives a file sent over a multicast QUIC channel.
*
* Counterpart of the QUICast tokio-quiche example async_multicast_file_server.
* The client opens a unicast QUIC connection (ALPN "h3", no certificate
* verification) with the multicast client transport parameter, and runs
* picoquic's packet loop. When the server asks it to join a channel, the loop
* opens a UDP socket, joins (S,G) with MCAST_JOIN_SOURCE_GROUP on the chosen
* interface and polls it next to the unicast one; channel packets go to
* picoquic_incoming_multicast_packet(), never through the normal receive path. Authenticated DATAGRAM frames carry
* the example's "QMCF" chunk format: a manifest (file name, length, chunk
* size, chunk count) and chunks. When every chunk has arrived the file is
* written and its SHA-256 printed.
*
* Usage: mcquic_client [options] server_address port
*   -i addr   IPv4 address of the interface to join the channel on
*   -o file   output file (default: the name in the manifest)
*   -n sni    server name (default test.com)
*   -t secs   stop after this many seconds (default 120)
*   -k        keep running after the file is complete (until -t), for soak tests
*   -s secs   statistics interval (default 5)
*   -A id     integrity hash algorithm to advertise (1-8, default 1)
*/

#ifdef _WINDOWS
#error "mcquic_client is written for POSIX systems"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <picotls.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_packet_loop.h"
#include "tls_api.h"
#include "mcquic.h"

#define QMCF_KIND_MANIFEST 1
#define QMCF_KIND_CHUNK 2
#define MCQ_MAX_PACKET 2048

typedef struct st_mcq_file_t {
    int has_manifest;
    uint64_t transfer_id;
    uint64_t file_length;
    uint32_t chunk_length;
    uint32_t total_chunks;
    char name[256];
    uint8_t* bytes;
    uint8_t* received;
    uint32_t received_count;
    int complete;
    int completions;
} mcq_file_t;

typedef struct st_mcq_client_t {
    struct in_addr if_addr;
    int if_index;
    uint16_t mc_port;
    int joined;
    const char* output;
    mcq_file_t file;
    uint64_t datagrams;
    uint64_t decode_errors;
    int closed;
} mcq_client_t;

static uint32_t mcq_u32(const uint8_t* p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static uint64_t mcq_u64(const uint8_t* p) { return ((uint64_t)mcq_u32(p) << 32) | mcq_u32(p + 4); }

static void mcq_print_time(void)
{
    uint64_t t = picoquic_current_time();
    printf("[%llu.%06llu] ", (unsigned long long)(t / 1000000), (unsigned long long)(t % 1000000));
}

static int mcq_file_complete(mcq_client_t* c)
{
    mcq_file_t* f = &c->file;
    const char* out = (c->output != NULL) ? c->output : f->name;
    uint8_t digest[32];
    ptls_cipher_suite_t* suite = (ptls_cipher_suite_t*)picoquic_get_cipher_suite_by_id_v(PICOQUIC_AES_128_GCM_SHA256);
    FILE* F = fopen(out, "wb");

    if (F == NULL || fwrite(f->bytes, 1, (size_t)f->file_length, F) != f->file_length) {
        fprintf(stderr, "cannot write %s\n", out);
        if (F != NULL) {
            fclose(F);
        }
        return -1;
    }
    fclose(F);
    f->complete = 1;
    f->completions++;
    mcq_print_time();
    printf("file complete: transfer=%llu bytes=%llu saved_to=%s sha256=",
        (unsigned long long)f->transfer_id, (unsigned long long)f->file_length, out);
    if (suite != NULL && ptls_calc_hash(suite->hash, digest, f->bytes, (size_t)f->file_length) == 0) {
        for (int i = 0; i < 32; i++) {
            printf("%02x", digest[i]);
        }
    }
    printf("\n");
    fflush(stdout);
    return 0;
}

/* The QMCF format of the QUICast example (multicast_file.rs): "QMCF", version 1,
 * kind; manifest = transfer ID, file length, chunk payload length, chunk count,
 * name; chunk = transfer ID, index, length, payload. Big endian. */
static void mcq_file_datagram(mcq_client_t* c, const uint8_t* data, size_t len)
{
    mcq_file_t* f = &c->file;

    c->datagrams++;
    if (len < 6 || memcmp(data, "QMCF", 4) != 0) {
        return;
    }
    if (data[4] != 1) {
        c->decode_errors++;
        return;
    }
    if (data[5] == QMCF_KIND_MANIFEST) {
        uint64_t transfer_id;
        size_t name_len;
        if (len < 6 + 8 + 8 + 4 + 4 + 2) {
            c->decode_errors++;
            return;
        }
        transfer_id = mcq_u64(data + 6);
        name_len = ((size_t)data[30] << 8) | data[31];
        if (len != 32 + name_len) {
            c->decode_errors++;
            return;
        }
        if (f->has_manifest && f->transfer_id == transfer_id) {
            return;
        }
        free(f->bytes);
        free(f->received);
        memset(f, 0, sizeof(mcq_file_t));
        f->transfer_id = transfer_id;
        f->file_length = mcq_u64(data + 14);
        f->chunk_length = mcq_u32(data + 22);
        f->total_chunks = mcq_u32(data + 26);
        if (name_len >= sizeof(f->name) || f->chunk_length == 0 || f->file_length > (1ull << 32) ||
            (uint64_t)f->total_chunks * f->chunk_length < f->file_length) {
            c->decode_errors++;
            return;
        }
        memcpy(f->name, data + 32, name_len);
        f->name[name_len] = 0;
        /* Keep only the last path component */
        for (char* p = f->name; *p != 0; p++) {
            if (*p == '/') {
                memmove(f->name, p + 1, strlen(p + 1) + 1);
                p = f->name - 1;
            }
        }
        f->bytes = (uint8_t*)calloc(1, (size_t)f->file_length + 1);
        f->received = (uint8_t*)calloc(1, (size_t)f->total_chunks + 1);
        if (f->bytes == NULL || f->received == NULL) {
            c->decode_errors++;
            return;
        }
        f->has_manifest = 1;
        mcq_print_time();
        printf("file manifest: transfer=%llu name=%s bytes=%llu chunks=%u chunk_payload=%u\n",
            (unsigned long long)f->transfer_id, f->name, (unsigned long long)f->file_length,
            f->total_chunks, f->chunk_length);
        fflush(stdout);
        if (f->total_chunks == 0) {
            (void)mcq_file_complete(c);
        }
    }
    else if (data[5] == QMCF_KIND_CHUNK) {
        uint64_t start;
        uint32_t index;
        uint32_t payload_len;
        uint64_t expected;

        if (len < 6 + 8 + 4 + 4) {
            c->decode_errors++;
            return;
        }
        index = mcq_u32(data + 14);
        payload_len = mcq_u32(data + 18);
        if (len != 22 + (size_t)payload_len) {
            c->decode_errors++;
            return;
        }
        if (!f->has_manifest || f->transfer_id != mcq_u64(data + 6)) {
            return;
        }
        if (index >= f->total_chunks) {
            c->decode_errors++;
            return;
        }
        start = (uint64_t)index * f->chunk_length;
        expected = (index + 1 == f->total_chunks) ? f->file_length - start : f->chunk_length;
        if (payload_len != expected) {
            c->decode_errors++;
            return;
        }
        if (f->received[index]) {
            return;
        }
        memcpy(f->bytes + start, data + 22, payload_len);
        f->received[index] = 1;
        f->received_count++;
        if ((f->received_count % 128) == 0 || f->received_count == f->total_chunks) {
            mcq_print_time();
            printf("progress: %u/%u chunks\n", f->received_count, f->total_chunks);
            fflush(stdout);
        }
        if (f->received_count == f->total_chunks && !f->complete) {
            (void)mcq_file_complete(c);
        }
    }
    else {
        c->decode_errors++;
    }
}

/* The packet loop has joined (S,G): a notification */
static int mcq_join(mcq_client_t* c, const picoquic_mcquic_channel_info_t* info)
{
    c->joined = 1;
    c->mc_port = info->port;
    mcq_print_time();
    printf("joined (S,G)=(%u.%u.%u.%u, %u.%u.%u.%u) port %u on interface index %d\n",
        info->source[0], info->source[1], info->source[2], info->source[3],
        info->group[0], info->group[1], info->group[2], info->group[3], info->port, c->if_index);
    fflush(stdout);
    return 0;
}

static void mcq_leave(mcq_client_t* c)
{
    c->joined = 0;
    mcq_print_time();
    printf("left the channel\n");
    fflush(stdout);
}

static int mcq_callback(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    mcq_client_t* c = (mcq_client_t*)callback_ctx;

    (void)cnx;
    (void)stream_id;
    (void)v_stream_ctx;
    switch (fin_or_event) {
    case picoquic_callback_mc_join:
        return mcq_join(c, (const picoquic_mcquic_channel_info_t*)bytes);
    case picoquic_callback_mc_leave:
        mcq_leave(c);
        return 0;
    case picoquic_callback_mc_datagram:
        mcq_file_datagram(c, bytes, length);
        return 0;
    case picoquic_callback_close:
    case picoquic_callback_application_close:
    case picoquic_callback_stateless_reset:
        c->closed = 1;
        return 0;
    case picoquic_callback_ready:
        mcq_print_time();
        printf("connection ready\n");
        fflush(stdout);
        return 0;
    default:
        return 0;
    }
}

static int mcq_find_if_index(struct in_addr addr)
{
    struct ifaddrs* ifa_list = NULL;
    int index = 0;

    if (getifaddrs(&ifa_list) != 0) {
        return 0;
    }
    for (struct ifaddrs* ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET &&
            ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr == addr.s_addr) {
            index = (int)if_nametoindex(ifa->ifa_name);
            break;
        }
    }
    freeifaddrs(ifa_list);
    return index;
}

static long mcq_rss_kb(void)
{
    long rss = -1;
    FILE* F = fopen("/proc/self/status", "r");
    char line[256];

    if (F != NULL) {
        while (fgets(line, sizeof(line), F) != NULL) {
            if (strncmp(line, "VmRSS:", 6) == 0) {
                rss = strtol(line + 6, NULL, 10);
                break;
            }
        }
        fclose(F);
    }
    return rss;
}

/* Upper bound, in ms, of the histogram bucket holding the given fraction of released packets */
static double mcq_delay_percentile(const picoquic_mcquic_stats_t* st, double fraction)
{
    uint64_t total = 0;
    uint64_t seen = 0;

    for (size_t i = 0; i < PICOQUIC_MCQUIC_DELAY_BUCKETS; i++) {
        total += st->release_delay[i];
    }
    for (size_t i = 0; i < PICOQUIC_MCQUIC_DELAY_BUCKETS && total > 0; i++) {
        seen += st->release_delay[i];
        if ((double)seen >= fraction * (double)total) {
            return (double)picoquic_mcquic_delay_bucket_limit(i) / 1000.0;
        }
    }
    return 0.0;
}

static void mcq_print_stats(picoquic_cnx_t* cnx, mcq_client_t* c)
{
    picoquic_mcquic_stats_t st;
    picoquic_mcquic_channel_id_t id;

    id.id_len = 8;
    memcpy(id.id, "qmcfile1", 8);
    memset(&st, 0, sizeof(st));
    (void)picoquic_mcquic_get_stats(cnx, &id, &st);
    mcq_print_time();
    printf("[stats] rx=%llu dup=%llu released=%llu evicted=%llu hashes=%llu integrity_fail=%llu header_fail=%llu "
        "decrypt_fail=%llu no_key=%llu unsupported=%llu datagrams=%llu acks_sent=%llu largest=%llu "
        "files_complete=%d chunks=%u/%u qmcf_errors=%llu rss_kb=%ld integrity_frames=%llu integrity_bytes=%llu "
        "release_delay_p50_ms=%.1f release_delay_p99_ms=%.1f\n",
        (unsigned long long)st.packets_received, (unsigned long long)st.packets_duplicate,
        (unsigned long long)st.packets_released, (unsigned long long)st.packets_evicted,
        (unsigned long long)st.integrity_hashes, (unsigned long long)st.integrity_failures,
        (unsigned long long)st.header_failures, (unsigned long long)st.decrypt_failures,
        (unsigned long long)st.no_key, (unsigned long long)st.unsupported_frames,
        (unsigned long long)st.datagrams, (unsigned long long)st.acks_sent,
        (unsigned long long)st.largest_released, c->file.completions, c->file.received_count,
        c->file.total_chunks, (unsigned long long)c->decode_errors, mcq_rss_kb(),
        (unsigned long long)st.integrity_frames, (unsigned long long)st.integrity_bytes,
        mcq_delay_percentile(&st, 0.50), mcq_delay_percentile(&st, 0.99));
    fflush(stdout);
}

static void usage(void)
{
    fprintf(stderr, "Usage: mcquic_client [-i if_addr] [-o file] [-n sni] [-t secs] [-k] [-s secs] server_address port\n");
    exit(1);
}

typedef struct st_mcq_loop_ctx_t {
    mcq_client_t* c;
    picoquic_cnx_t* cnx;
    uint64_t start_time;
    uint64_t max_run_us;
    uint64_t stats_us;
    uint64_t next_stats;
    int keep_running;
    int closing;
    uint64_t close_deadline;
    int ret;
} mcq_loop_ctx_t;

/* Ends the run from the loop's time check: closes the connection once the file
 * is complete (or at the time limit), then leaves the loop when the close is out. */
static int mcq_loop_callback(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, void* callback_ctx, void* callback_arg)
{
    mcq_loop_ctx_t* lc = (mcq_loop_ctx_t*)callback_ctx;

    (void)quic;
    switch (cb_mode) {
    case picoquic_packet_loop_ready:
        ((picoquic_packet_loop_options_t*)callback_arg)->do_time_check = 1;
        return 0;
    case picoquic_packet_loop_time_check: {
        packet_loop_time_check_arg_t* arg = (packet_loop_time_check_arg_t*)callback_arg;
        uint64_t now = arg->current_time;

        if (picoquic_get_cnx_state(lc->cnx) == picoquic_state_disconnected) {
            if (!lc->closing) {
                printf("connection closed\n");
                if (!lc->c->file.complete) {
                    lc->ret = 2;
                }
            }
            return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
        }
        if (!lc->closing && (now >= lc->start_time + lc->max_run_us || (lc->c->file.complete && !lc->keep_running))) {
            if (!lc->c->file.complete) {
                printf("timed out before the file was complete\n");
                lc->ret = 2;
            }
            mcq_print_stats(lc->cnx, lc->c);
            (void)picoquic_close(lc->cnx, 0);
            lc->closing = 1;
            lc->close_deadline = now + 500000;
        }
        if (lc->closing && now >= lc->close_deadline) {
            return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
        }
        if (now >= lc->next_stats) {
            mcq_print_stats(lc->cnx, lc->c);
            lc->next_stats = now + lc->stats_us;
        }
        if ((int64_t)(lc->next_stats - now) < arg->delta_t) {
            arg->delta_t = (int64_t)(lc->next_stats - now);
        }
        if (lc->closing && (int64_t)(lc->close_deadline - now) < arg->delta_t) {
            arg->delta_t = (int64_t)(lc->close_deadline - now);
        }
        return 0;
    }
    default:
        return 0;
    }
}

int main(int argc, char** argv)
{
    mcq_client_t c;
    const char* sni = "test.com";
    uint64_t max_run_us = 120 * 1000000ull;
    uint64_t stats_us = 5 * 1000000ull;
    int keep_running = 0;
    int hash_alg = PICOQUIC_MCQUIC_HASH_SHA256;
    picoquic_mcquic_client_params_t params;
    struct sockaddr_in server;
    struct sockaddr_in if_sa;
    picoquic_packet_loop_param_t param;
    mcq_loop_ctx_t lc;
    picoquic_quic_t* quic;
    picoquic_cnx_t* cnx;
    uint64_t start_time;
    int opt;
    int ret = 0;

    memset(&c, 0, sizeof(c));
    while ((opt = getopt(argc, argv, "i:o:n:t:ks:A:")) != -1) {
        switch (opt) {
        case 'i':
            if (inet_pton(AF_INET, optarg, &c.if_addr) != 1) {
                usage();
            }
            break;
        case 'o': c.output = optarg; break;
        case 'n': sni = optarg; break;
        case 't': max_run_us = (uint64_t)atoi(optarg) * 1000000ull; break;
        case 'k': keep_running = 1; break;
        case 's': stats_us = (uint64_t)atoi(optarg) * 1000000ull; break;
        case 'A': hash_alg = atoi(optarg); if (picoquic_mcquic_hash_length((uint16_t)hash_alg) == 0) usage(); break;
        default: usage();
        }
    }
    if (argc - optind != 2) {
        usage();
    }
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons((uint16_t)atoi(argv[optind + 1]));
    if (inet_pton(AF_INET, argv[optind], &server.sin_addr) != 1) {
        usage();
    }
    if (c.if_addr.s_addr != 0 && (c.if_index = mcq_find_if_index(c.if_addr)) == 0) {
        fprintf(stderr, "no interface with address %s\n", inet_ntoa(c.if_addr));
        return 1;
    }

    start_time = picoquic_current_time();
    quic = picoquic_create(1, NULL, NULL, NULL, "h3", NULL, NULL, NULL, NULL, NULL, start_time, NULL, NULL, NULL, 0);
    if (quic == NULL) {
        fprintf(stderr, "cannot create the QUIC context\n");
        return 1;
    }
    /* The packet loop joins channels on the chosen interface */
    memset(&if_sa, 0, sizeof(if_sa));
    if_sa.sin_family = AF_INET;
    if_sa.sin_addr = c.if_addr;
    if (picoquic_mcquic_loop_config(quic, (c.if_addr.s_addr != 0) ? (struct sockaddr*)&if_sa : NULL, 1, 1) != 0) {
        fprintf(stderr, "cannot configure multicast on the packet loop\n");
        return 1;
    }
    /* The example server uses a self-signed certificate */
    picoquic_set_null_verifier(quic);
    picoquic_set_default_idle_timeout(quic, 300000);
    cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*)&server, start_time, 0, sni, "h3", 1);
    picoquic_mcquic_set_default_client_params(&params);
    params.hash_algs[0] = (uint16_t)hash_alg;
    if (cnx == NULL || picoquic_mcquic_enable_client(cnx, &params) != 0) {
        fprintf(stderr, "cannot create the connection\n");
        return 1;
    }
    picoquic_mcquic_set_log(cnx, stdout);
    picoquic_set_callback(cnx, mcq_callback, &c);
    picoquic_enable_keep_alive(cnx, 0);
    if (picoquic_start_client_cnx(cnx) != 0) {
        fprintf(stderr, "cannot start the connection\n");
        return 1;
    }
    mcq_print_time();
    printf("connecting to %s:%s from %s\n", argv[optind], argv[optind + 1],
        (c.if_addr.s_addr != 0) ? inet_ntoa(c.if_addr) : "any address");
    fflush(stdout);

    memset(&param, 0, sizeof(param));
    param.local_af = AF_INET;
    if (c.if_addr.s_addr != 0) {
        /* Unicast on the multicast interface's address */
        param.local_addr[0].ss_family = AF_INET;
        ((struct sockaddr_in*)&param.local_addr[0])->sin_addr = c.if_addr;
    }
    memset(&lc, 0, sizeof(lc));
    lc.c = &c;
    lc.cnx = cnx;
    lc.start_time = start_time;
    lc.max_run_us = max_run_us;
    lc.stats_us = stats_us;
    lc.next_stats = start_time + stats_us;
    lc.keep_running = keep_running;
    ret = picoquic_packet_loop_v2(quic, &param, mcq_loop_callback, &lc);
    if (ret == 0) {
        ret = lc.ret;
    }
    mcq_print_stats(cnx, &c);
    picoquic_free(quic);
    free(c.file.bytes);
    free(c.file.received);
    return ret;
}
