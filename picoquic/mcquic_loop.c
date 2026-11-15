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
* Multicast sockets owned by the packet loop.
*
* When picoquic_mcquic_loop_config() has been called, the packet loop owns the
* channel sockets, as it owns the unicast ones:
*   - receiver: on MC_JOIN, the library opens a UDP socket on the channel's
*     group and port, joins (S,G) with MCAST_JOIN_SOURCE_GROUP on the configured
*     interface, and the loop polls it; packets read from it go to
*     picoquic_incoming_multicast_packet(). Connections joining the same channel
*     share the socket; the last leave (or connection close) closes it.
*   - sender: picoquic_mcquic_sender_publish() builds a channel packet and queues
*     it; the loop sends the queue to (S,G) from a socket bound to the source
*     address, with IP_MULTICAST_IF, the configured TTL and loopback.
* The loop also sends due MC_ACK and MC_INTEGRITY frames and wakes up for them.
* Without picoquic_mcquic_loop_config(), the application owns the sockets as
* before (see mcquic.h). Loop-owned sockets are supported on POSIX systems with
* the poll and select loops, not with io_uring or on Windows.
*/

#include <stdlib.h>
#include <string.h>
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquic_packet_loop.h"
#include "mcquic.h"
#include "mcquic_loop.h"

#if !defined(_WINDOWS) && !defined(PICOQUIC_WITH_IO_URING)
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#define MCQUIC_LOOP_SUPPORTED 1
#endif

#define MCQUIC_LOOP_CHANNELS_MAX 4
#define MCQUIC_LOOP_QUEUE_MAX 64
#define MCQUIC_LOOP_PACKET_MAX 1536

typedef struct st_mcquic_loop_channel_t {
    int fd;
    int refcount; /* 0 with fd >= 0: to be removed from the loop's sockets and closed */
    int in_loop;
    uint8_t source[4];
    uint8_t group[4];
    uint16_t port;
} mcquic_loop_channel_t;

typedef struct st_picoquic_mcquic_loop_t {
    struct sockaddr_in if_addr;
    unsigned int if_index;
    int ttl;
    int loopback;
    mcquic_loop_channel_t channels[MCQUIC_LOOP_CHANNELS_MAX];
    int send_fd;
    uint8_t* queue;
    size_t queue_length[MCQUIC_LOOP_QUEUE_MAX];
    size_t queue_first;
    size_t queue_count;
    picoquic_mcquic_loop_stats_t stats;
} picoquic_mcquic_loop_t;

int picoquic_mcquic_loop_config(picoquic_quic_t* quic, const struct sockaddr* if_addr, int ttl, int loopback)
{
#ifdef MCQUIC_LOOP_SUPPORTED
    picoquic_mcquic_loop_t* loop = quic->mcquic_loop;

    if (if_addr != NULL && if_addr->sa_family != AF_INET) {
        return -1;
    }
    if (loop == NULL) {
        if ((loop = (picoquic_mcquic_loop_t*)calloc(1, sizeof(picoquic_mcquic_loop_t))) == NULL) {
            return PICOQUIC_ERROR_MEMORY;
        }
        for (int i = 0; i < MCQUIC_LOOP_CHANNELS_MAX; i++) {
            loop->channels[i].fd = -1;
        }
        loop->send_fd = -1;
        quic->mcquic_loop = loop;
    }
    memset(&loop->if_addr, 0, sizeof(loop->if_addr));
    loop->if_addr.sin_family = AF_INET;
    loop->if_index = 0;
    if (if_addr != NULL) {
        struct ifaddrs* ifa_list = NULL;
        loop->if_addr.sin_addr = ((const struct sockaddr_in*)if_addr)->sin_addr;
        if (getifaddrs(&ifa_list) == 0) {
            for (struct ifaddrs* ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET &&
                    ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr == loop->if_addr.sin_addr.s_addr) {
                    loop->if_index = if_nametoindex(ifa->ifa_name);
                    break;
                }
            }
            freeifaddrs(ifa_list);
        }
        if (loop->if_index == 0 && loop->if_addr.sin_addr.s_addr != htonl(INADDR_ANY)) {
            return -1;
        }
    }
    loop->ttl = (ttl <= 0) ? 1 : ttl;
    loop->loopback = loopback;
    return 0;
#else
    (void)quic; (void)if_addr; (void)ttl; (void)loopback;
    return -1;
#endif
}

void picoquic_mcquic_loop_delete(picoquic_quic_t* quic)
{
    picoquic_mcquic_loop_t* loop = quic->mcquic_loop;

    if (loop != NULL) {
#ifdef MCQUIC_LOOP_SUPPORTED
        for (int i = 0; i < MCQUIC_LOOP_CHANNELS_MAX; i++) {
            if (loop->channels[i].fd >= 0) {
                close(loop->channels[i].fd);
            }
        }
        if (loop->send_fd >= 0) {
            close(loop->send_fd);
        }
#endif
        free(loop->queue);
        free(loop);
        quic->mcquic_loop = NULL;
    }
}

int picoquic_mcquic_loop_get_stats(picoquic_quic_t* quic, picoquic_mcquic_loop_stats_t* stats)
{
    if (quic->mcquic_loop == NULL) {
        return -1;
    }
    *stats = quic->mcquic_loop->stats;
    return 0;
}

int mcquic_loop_enabled(picoquic_quic_t* quic)
{
    return quic->mcquic_loop != NULL;
}

int mcquic_loop_join(picoquic_quic_t* quic, const picoquic_mcquic_channel_info_t* info)
{
#ifdef MCQUIC_LOOP_SUPPORTED
    picoquic_mcquic_loop_t* loop = quic->mcquic_loop;
    mcquic_loop_channel_t* free_slot = NULL;
    struct sockaddr_in local;
    struct group_source_req gsr;
    struct sockaddr_in* group = (struct sockaddr_in*)&gsr.gsr_group;
    struct sockaddr_in* source = (struct sockaddr_in*)&gsr.gsr_source;
    int one = 1;
    int s;

    if (loop == NULL || info->is_ipv6) {
        return -1;
    }
    for (int i = 0; i < MCQUIC_LOOP_CHANNELS_MAX; i++) {
        mcquic_loop_channel_t* c = &loop->channels[i];
        if (c->fd >= 0 && c->refcount > 0 && c->port == info->port && memcmp(c->group, info->group, 4) == 0 &&
            memcmp(c->source, info->source, 4) == 0) {
            c->refcount++;
            return 0;
        }
        if (c->fd < 0 && free_slot == NULL) {
            free_slot = c;
        }
    }
    if (free_slot == NULL || (s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }
    (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(info->port);
    /* Bound to the group, so the socket gets only this group's traffic */
    memcpy(&local.sin_addr, info->group, 4);
    memset(&gsr, 0, sizeof(gsr));
    gsr.gsr_interface = loop->if_index;
    group->sin_family = AF_INET;
    memcpy(&group->sin_addr, info->group, 4);
    source->sin_family = AF_INET;
    memcpy(&source->sin_addr, info->source, 4);
    if (bind(s, (struct sockaddr*)&local, sizeof(local)) != 0 ||
        setsockopt(s, IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP, &gsr, sizeof(gsr)) != 0) {
        close(s);
        loop->stats.join_failures++;
        return -1;
    }
    free_slot->fd = s;
    free_slot->refcount = 1;
    free_slot->in_loop = 0;
    memcpy(free_slot->source, info->source, 4);
    memcpy(free_slot->group, info->group, 4);
    free_slot->port = info->port;
    loop->stats.sockets_opened++;
    return 0;
#else
    (void)quic; (void)info;
    return -1;
#endif
}

void mcquic_loop_leave(picoquic_quic_t* quic, const picoquic_mcquic_channel_info_t* info)
{
    picoquic_mcquic_loop_t* loop = quic->mcquic_loop;

    if (loop == NULL) {
        return;
    }
    for (int i = 0; i < MCQUIC_LOOP_CHANNELS_MAX; i++) {
        mcquic_loop_channel_t* c = &loop->channels[i];
        if (c->fd >= 0 && c->refcount > 0 && c->port == info->port && memcmp(c->group, info->group, 4) == 0 &&
            memcmp(c->source, info->source, 4) == 0) {
            /* The socket is closed by the loop once it is out of its poll set */
            c->refcount--;
            return;
        }
    }
}

uint8_t* mcquic_loop_queue_slot(picoquic_quic_t* quic, size_t* slot_size)
{
    picoquic_mcquic_loop_t* loop = quic->mcquic_loop;

    if (loop == NULL || loop->queue_count >= MCQUIC_LOOP_QUEUE_MAX) {
        if (loop != NULL) {
            loop->stats.queue_full++;
        }
        return NULL;
    }
    if (loop->queue == NULL && (loop->queue = (uint8_t*)malloc(MCQUIC_LOOP_QUEUE_MAX * MCQUIC_LOOP_PACKET_MAX)) == NULL) {
        return NULL;
    }
    *slot_size = MCQUIC_LOOP_PACKET_MAX;
    return loop->queue + ((loop->queue_first + loop->queue_count) % MCQUIC_LOOP_QUEUE_MAX) * MCQUIC_LOOP_PACKET_MAX;
}

void mcquic_loop_queue_commit(picoquic_quic_t* quic, size_t length)
{
    picoquic_mcquic_loop_t* loop = quic->mcquic_loop;

    loop->queue_length[(loop->queue_first + loop->queue_count) % MCQUIC_LOOP_QUEUE_MAX] = length;
    loop->queue_count++;
}

#ifdef MCQUIC_LOOP_SUPPORTED
static int mcquic_loop_open_send_socket(picoquic_mcquic_loop_t* loop, const uint8_t* source)
{
    struct sockaddr_in src;
    struct in_addr mc_if;
    unsigned char ttl = (unsigned char)loop->ttl;
    unsigned char mc_loop = (unsigned char)(loop->loopback != 0);
    int s;

    memset(&src, 0, sizeof(src));
    src.sin_family = AF_INET;
    memcpy(&src.sin_addr, source, 4);
    mc_if = (loop->if_addr.sin_addr.s_addr != htonl(INADDR_ANY)) ? loop->if_addr.sin_addr : src.sin_addr;
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }
    if (bind(s, (struct sockaddr*)&src, sizeof(src)) != 0 ||
        setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, &mc_if, sizeof(mc_if)) != 0 ||
        setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) != 0 ||
        setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &mc_loop, sizeof(mc_loop)) != 0) {
        close(s);
        return -1;
    }
    return s;
}
#endif

void picoquic_mcquic_loop_send(picoquic_quic_t* quic, uint64_t current_time)
{
    picoquic_mcquic_loop_t* loop = quic->mcquic_loop;
    picoquic_mcquic_sender_config_t config;

    (void)current_time;
    if (loop == NULL || loop->queue_count == 0) {
        return;
    }
#ifdef MCQUIC_LOOP_SUPPORTED
    if (picoquic_mcquic_sender_get_config(quic, &config) == 0) {
        struct sockaddr_in dest;
        if (loop->send_fd < 0) {
            loop->send_fd = mcquic_loop_open_send_socket(loop, config.source);
        }
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        memcpy(&dest.sin_addr, config.group, 4);
        dest.sin_port = htons(config.port);
        while (loop->queue_count > 0) {
            const uint8_t* packet = loop->queue + loop->queue_first * MCQUIC_LOOP_PACKET_MAX;
            if (loop->send_fd < 0 ||
                sendto(loop->send_fd, packet, loop->queue_length[loop->queue_first], 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
                loop->stats.send_errors++;
            }
            else {
                loop->stats.packets_sent++;
            }
            loop->queue_first = (loop->queue_first + 1) % MCQUIC_LOOP_QUEUE_MAX;
            loop->queue_count--;
        }
    }
#else
    (void)config;
#endif
    loop->queue_count = 0;
}

void picoquic_mcquic_loop_prepare(picoquic_quic_t* quic, picoquic_socket_ctx_t* s_ctx, int* nb_sockets,
    int* nb_sockets_available, int max_sockets, uint64_t current_time, int64_t* delta_t)
{
    picoquic_mcquic_loop_t* loop = quic->mcquic_loop;

    if (loop == NULL) {
        return;
    }
#ifdef MCQUIC_LOOP_SUPPORTED
    /* Drop the sockets of channels nobody is joined to any more */
    for (int i = 0; i < *nb_sockets_available; i++) {
        if (s_ctx[i].is_multicast) {
            int keep = 0;
            for (int j = 0; j < MCQUIC_LOOP_CHANNELS_MAX; j++) {
                mcquic_loop_channel_t* c = &loop->channels[j];
                if (c->fd >= 0 && c->fd == (int)s_ctx[i].fd && c->refcount > 0) {
                    keep = 1;
                    break;
                }
            }
            if (!keep) {
                for (int j = 0; j < MCQUIC_LOOP_CHANNELS_MAX; j++) {
                    if (loop->channels[j].fd == (int)s_ctx[i].fd) {
                        loop->channels[j].fd = -1;
                        loop->channels[j].in_loop = 0;
                    }
                }
                picoquic_packet_loop_close_socket(&s_ctx[i]);
                loop->stats.sockets_closed++;
                if (i < *nb_sockets_available - 1) {
                    memmove(&s_ctx[i], &s_ctx[i + 1], sizeof(picoquic_socket_ctx_t) * (size_t)(*nb_sockets_available - i - 1));
                }
                (*nb_sockets_available)--;
                (*nb_sockets)--;
                i--;
            }
        }
    }
    /* Channels left before the loop picked them up */
    for (int j = 0; j < MCQUIC_LOOP_CHANNELS_MAX; j++) {
        mcquic_loop_channel_t* c = &loop->channels[j];
        if (c->fd >= 0 && c->refcount == 0 && !c->in_loop) {
            close(c->fd);
            c->fd = -1;
            loop->stats.sockets_closed++;
        }
    }
    /* Add the sockets of newly joined channels */
    for (int j = 0; j < MCQUIC_LOOP_CHANNELS_MAX; j++) {
        mcquic_loop_channel_t* c = &loop->channels[j];
        if (c->fd >= 0 && c->refcount > 0 && !c->in_loop && *nb_sockets_available < max_sockets &&
            *nb_sockets == *nb_sockets_available) {
            picoquic_socket_ctx_t* sc = &s_ctx[*nb_sockets_available];
            memset(sc, 0, sizeof(picoquic_socket_ctx_t));
            sc->fd = c->fd;
            sc->af = AF_INET;
            sc->port = c->port;
            sc->n_port = htons(c->port);
            sc->is_multicast = 1;
            c->in_loop = 1;
            (*nb_sockets_available)++;
            (*nb_sockets)++;
        }
    }
#else
    (void)s_ctx; (void)nb_sockets; (void)nb_sockets_available; (void)max_sockets;
#endif
    if (delta_t != NULL) {
        /* Due MC_ACK and MC_INTEGRITY frames are queued now; the loop then
         * wakes up for the next ones. */
        uint64_t next = picoquic_mcquic_service(quic, current_time);
        int64_t wake = picoquic_get_next_wake_delay(quic, current_time, *delta_t);

        if (wake < *delta_t) {
            *delta_t = wake;
        }
        if (next != UINT64_MAX && (next <= current_time || (int64_t)(next - current_time) < *delta_t)) {
            *delta_t = (next <= current_time) ? 0 : (int64_t)(next - current_time);
        }
        if (loop->queue_count > 0) {
            *delta_t = 0;
        }
    }
}

int picoquic_mcquic_loop_incoming(picoquic_quic_t* quic, const uint8_t* bytes, size_t length,
    const struct sockaddr* addr_from, uint64_t current_time)
{
    picoquic_mcquic_loop_t* loop = quic->mcquic_loop;

    if (loop != NULL) {
        loop->stats.packets_received++;
    }
    return picoquic_incoming_multicast_packet(quic, bytes, length, addr_from, current_time);
}
