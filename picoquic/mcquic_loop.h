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

/* Internal interface between mcquic.c and mcquic_loop.c */
#ifndef PICOQUIC_MCQUIC_LOOP_H
#define PICOQUIC_MCQUIC_LOOP_H

#include "picoquic.h"
#include "mcquic.h"

#ifdef __cplusplus
extern "C" {
#endif

int mcquic_loop_enabled(picoquic_quic_t* quic);
int mcquic_loop_join(picoquic_quic_t* quic, const picoquic_mcquic_channel_info_t* info);
void mcquic_loop_leave(picoquic_quic_t* quic, const picoquic_mcquic_channel_info_t* info);
uint8_t* mcquic_loop_queue_slot(picoquic_quic_t* quic, size_t* slot_size);
void mcquic_loop_queue_commit(picoquic_quic_t* quic, size_t length);

/* Packet loop hooks (sockloop.c). prepare: brings the channel sockets into or out
 * of the loop's socket table, queues due MC_ACK and MC_INTEGRITY frames and
 * shortens delta_t (if not NULL) to the next one. send: sends queued channel
 * packets. incoming: a packet read from a channel socket. */
struct st_picoquic_socket_ctx_t;
void picoquic_mcquic_loop_prepare(picoquic_quic_t* quic, struct st_picoquic_socket_ctx_t* s_ctx, int* nb_sockets,
    int* nb_sockets_available, int max_sockets, uint64_t current_time, int64_t* delta_t);
void picoquic_mcquic_loop_send(picoquic_quic_t* quic, uint64_t current_time);
int picoquic_mcquic_loop_incoming(picoquic_quic_t* quic, const uint8_t* bytes, size_t length,
    const struct sockaddr* addr_from, uint64_t current_time);
void picoquic_mcquic_loop_delete(picoquic_quic_t* quic);

#ifdef __cplusplus
}
#endif

#endif
