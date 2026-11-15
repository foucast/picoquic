/*
* Copyright (c) 2026 Marc E. Fiuczynski
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

/* Known-answer tests for the multicast receiver (mcquic.c).
 *
 * The vectors come from a capture of the QUICast quiche example pair
 * (tokio-quiche async_multicast_file_server and _client, quiche f208164): the
 * server sends a file over a channel with the example's fixed secrets
 * (header secret 0xaa x 16, payload secret 0xcc x 16, channel ID "qmcfile1",
 * AES-128-GCM, sha256-32 integrity). Packets are copied from the wire; the
 * control frames from the decrypted unicast connection; the derived keys and
 * plaintexts were computed independently and open every packet of the capture.
 */

#include <stdlib.h>
#include <string.h>
#include <picotls.h>
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "tls_api.h"
#include "mcquic.h"
#include "picoquictest_internal.h"

static const uint8_t mcquic_kat_header_secret[16] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
static const uint8_t mcquic_kat_payload_secret[16] = {
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc };
static const uint8_t mcquic_kat_channel_id[8] = { 'q', 'm', 'c', 'f', 'i', 'l', 'e', '1' };
static const uint8_t mcquic_kat_key[] = {
    0x44, 0xb4, 0x7a, 0x06, 0xef, 0xbe, 0xb3, 0x30, 0xa3, 0xdd, 0x34, 0x0f, 0xa8, 0x82, 0x85, 0xfb
};
static const uint8_t mcquic_kat_iv[] = {
    0x1a, 0xba, 0xf9, 0x71, 0x00, 0x17, 0x4f, 0xb0, 0xbf, 0xf7, 0x29, 0x02
};
static const uint8_t mcquic_kat_hp[] = {
    0xe8, 0xaf, 0x8d, 0xc9, 0x81, 0xa6, 0x11, 0x92, 0x6d, 0x73, 0xc3, 0x7f, 0x86, 0x0a, 0x2b, 0xa4
};
/* Channel packet 0: DATAGRAM carrying the file manifest */
static const uint8_t mcquic_kat_packet0[] = {
    0x42, 0x71, 0x6d, 0x63, 0x66, 0x69, 0x6c, 0x65, 0x31, 0x37, 0xd8, 0x1f, 0x4d, 0x31, 0x24, 0x19,
    0xeb, 0x74, 0x02, 0x81, 0xc6, 0x81, 0xe6, 0x49, 0x61, 0x79, 0xde, 0xb9, 0x27, 0x5e, 0x8e, 0xb2,
    0x6b, 0x86, 0x99, 0x6e, 0x5b, 0xe4, 0xb1, 0xad, 0x5e, 0x5e, 0xe4, 0x83, 0x73, 0x8e, 0xf2, 0xb9,
    0xf7, 0x60, 0x99, 0xf5, 0x85, 0xdd, 0xa1, 0x5f, 0x78, 0x4d, 0x37, 0x03, 0x65, 0x4e, 0xca, 0xd4,
    0x75, 0x9b, 0xa3, 0x1f, 0x16, 0x76, 0x53, 0x69, 0x2c, 0xe2, 0x60, 0xf2
};
static const uint8_t mcquic_kat_header0[] = {
    0x47, 0x71, 0x6d, 0x63, 0x66, 0x69, 0x6c, 0x65, 0x31, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t mcquic_kat_plaintext0[] = {
    0x31, 0x40, 0x2c, 0x51, 0x4d, 0x43, 0x46, 0x01, 0x01, 0x9c, 0xa3, 0x1b, 0x12, 0x69, 0x12, 0x75,
    0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x0c, 0x74, 0x65, 0x73, 0x74, 0x66, 0x69, 0x6c, 0x65, 0x2e, 0x62, 0x69, 0x6e
};
static const uint8_t mcquic_kat_hash0[] = {
    0xd0, 0x3b, 0xf7, 0xb3, 0x6a, 0x98, 0x56, 0x92, 0x99, 0x9f, 0xc7, 0xe9, 0xb8, 0xf3, 0x5b, 0x23,
    0xc8, 0xeb, 0x64, 0x4b, 0xd3, 0xa0, 0x7b, 0xda, 0xd7, 0xcd, 0x42, 0xdd, 0x1d, 0xf0, 0xe6, 0x48
};
/* Channel packet 1115: DATAGRAM carrying a 1024-byte chunk */
static const uint8_t mcquic_kat_packet1115[] = {
    0x52, 0x71, 0x6d, 0x63, 0x66, 0x69, 0x6c, 0x65, 0x31, 0xec, 0xf7, 0xa0, 0x73, 0x39, 0x86, 0xde,
    0x2e, 0x00, 0xe6, 0xbb, 0x6c, 0x6a, 0xf9, 0x2c, 0x6c, 0xe9, 0x83, 0x8a, 0x04, 0x40, 0x7b, 0x00,
    0x54, 0x93, 0x2f, 0xe4, 0xd3, 0x91, 0x23, 0x9f, 0xe6, 0xfa, 0x70, 0xd9, 0x53, 0x45, 0xf3, 0x93,
    0x1d, 0x78, 0xa3, 0xf2, 0xab, 0xbf, 0xac, 0xaa, 0xcd, 0xd7, 0x37, 0xa2, 0x2f, 0xe0, 0xf5, 0xb7,
    0xdd, 0x6f, 0xed, 0xed, 0xb6, 0x1f, 0xf0, 0x4d, 0x29, 0x69, 0xca, 0x36, 0x29, 0x08, 0x1c, 0x1d,
    0x9c, 0xc1, 0xe5, 0x34, 0x91, 0xe8, 0xc8, 0xf6, 0x9a, 0x42, 0xf2, 0x51, 0x01, 0x57, 0x40, 0x68,
    0x78, 0x82, 0x42, 0x18, 0x5b, 0xa2, 0x82, 0x01, 0x38, 0xa4, 0x0b, 0xe5, 0xc3, 0x8d, 0x7c, 0xa1,
    0x1f, 0x6a, 0x03, 0x3a, 0x50, 0x34, 0xbf, 0xea, 0xf6, 0x9c, 0x35, 0xa7, 0xe1, 0x33, 0x17, 0xa1,
    0x9e, 0xd3, 0x19, 0xfc, 0xe1, 0xa2, 0xbb, 0x7e, 0xfd, 0xc7, 0xa7, 0x87, 0x42, 0x52, 0x5d, 0x60,
    0x94, 0xeb, 0x8b, 0x1b, 0x41, 0x91, 0xa8, 0x35, 0xa0, 0x60, 0x7c, 0x28, 0x46, 0xff, 0x11, 0x8d,
    0xde, 0x26, 0x19, 0xa1, 0x0d, 0xf1, 0x48, 0xf0, 0xe0, 0x2d, 0xa2, 0x4b, 0xbe, 0x5b, 0x7f, 0xdc,
    0xe3, 0x30, 0x9c, 0xad, 0xe0, 0x90, 0x2f, 0x97, 0x54, 0xe0, 0x18, 0x91, 0x85, 0x88, 0x5f, 0xc9,
    0x45, 0x1c, 0xc1, 0xbe, 0xac, 0x5b, 0x48, 0xa4, 0xfb, 0xa7, 0x35, 0xfb, 0x7c, 0xbb, 0xe8, 0x73,
    0x60, 0x61, 0x0b, 0x12, 0x72, 0x09, 0xfa, 0x6a, 0x11, 0x01, 0xaf, 0xda, 0x02, 0x06, 0xaf, 0x23,
    0x79, 0xdb, 0x8d, 0x86, 0x3a, 0x38, 0xbf, 0x18, 0x74, 0xb0, 0x74, 0x77, 0x13, 0x2d, 0x1f, 0x97,
    0x92, 0x4a, 0x28, 0xf5, 0x27, 0x0f, 0x31, 0x84, 0x86, 0x92, 0x17, 0x7c, 0x28, 0x07, 0x07, 0xbf,
    0xed, 0x82, 0x47, 0x42, 0xaf, 0x94, 0xbe, 0x84, 0xac, 0x7a, 0xba, 0xa4, 0x0a, 0x33, 0x8e, 0xa0,
    0x17, 0xa6, 0x71, 0xff, 0xf7, 0x4d, 0x9d, 0xab, 0x90, 0x35, 0x28, 0xa9, 0x50, 0x40, 0x41, 0x7c,
    0x69, 0x17, 0xf5, 0xca, 0xff, 0xc9, 0xb2, 0xdf, 0x30, 0xf6, 0x4c, 0xc2, 0xfa, 0x8f, 0x1c, 0xd5,
    0x1f, 0x5e, 0xa4, 0x4b, 0xed, 0xec, 0xc7, 0x1a, 0xc3, 0x1c, 0x3f, 0xec, 0x50, 0x2f, 0x20, 0xe6,
    0xd6, 0x15, 0x8a, 0x8f, 0x1a, 0x2b, 0x34, 0x6a, 0x69, 0xf9, 0x17, 0xfa, 0xe9, 0x92, 0x25, 0x10,
    0xa4, 0xda, 0x47, 0x57, 0x23, 0xef, 0x13, 0xd5, 0x8b, 0x53, 0x11, 0x2a, 0xbb, 0x5e, 0x29, 0x48,
    0xa0, 0x7d, 0xd4, 0xc3, 0x42, 0x48, 0x67, 0x99, 0xaf, 0x14, 0xa3, 0xa6, 0x1b, 0x68, 0x10, 0x65,
    0xa4, 0xb1, 0x6c, 0x1b, 0x0f, 0xee, 0xc7, 0xf3, 0xcd, 0xd1, 0x18, 0xc2, 0xf2, 0xdf, 0x40, 0xad,
    0x9c, 0xb9, 0xd8, 0x42, 0x4c, 0xa9, 0x90, 0x3c, 0x0f, 0x13, 0x43, 0xb7, 0x8e, 0xcc, 0x34, 0x67,
    0xa8, 0x20, 0x18, 0x71, 0x77, 0x22, 0x35, 0xd8, 0x8b, 0x88, 0xdc, 0x6b, 0x03, 0x94, 0xc0, 0x89,
    0x5f, 0x24, 0x92, 0x70, 0xd6, 0x5a, 0xca, 0xb4, 0x29, 0xe7, 0x2b, 0x18, 0xc4, 0xb6, 0xac, 0xd1,
    0x6d, 0xdf, 0xc5, 0x17, 0x20, 0x81, 0x08, 0x72, 0x62, 0x3d, 0x47, 0xc6, 0x8e, 0x1c, 0x8a, 0xc6,
    0x1a, 0x3a, 0x26, 0x58, 0x05, 0xda, 0x89, 0x48, 0x76, 0xab, 0x1a, 0x10, 0x15, 0x0b, 0x54, 0xd1,
    0xb7, 0x68, 0x8b, 0xab, 0x74, 0xad, 0xc4, 0x4c, 0x4c, 0x8b, 0xbf, 0x13, 0x87, 0x75, 0x9b, 0x1d,
    0x26, 0x8d, 0x6f, 0xa8, 0x87, 0x2d, 0xb0, 0x9c, 0x39, 0xfa, 0x67, 0x13, 0x5c, 0x39, 0xef, 0x4c,
    0xc6, 0xf6, 0xab, 0x22, 0x27, 0xe5, 0x69, 0x6b, 0x55, 0x6f, 0x85, 0xa3, 0x4b, 0xff, 0xff, 0x2c,
    0x90, 0xc2, 0x03, 0x2f, 0xad, 0x62, 0x79, 0x2c, 0x87, 0xf3, 0xec, 0xcf, 0x1c, 0x50, 0xa2, 0x8f,
    0xda, 0x32, 0xd9, 0x9a, 0xd5, 0xfb, 0x36, 0x75, 0xfe, 0x11, 0x2c, 0xfd, 0xd9, 0xf1, 0xd3, 0x29,
    0xfc, 0x31, 0x7d, 0xf8, 0x60, 0xb5, 0xcf, 0x94, 0x32, 0x92, 0x6f, 0x95, 0x8d, 0x4a, 0x0f, 0x99,
    0x6b, 0x29, 0xd1, 0x22, 0xb2, 0xe6, 0x51, 0x19, 0x93, 0x5d, 0xb2, 0x62, 0x62, 0x28, 0x66, 0xce,
    0x25, 0x6d, 0x20, 0xb9, 0xc6, 0x49, 0xaf, 0x7f, 0x84, 0xd2, 0x14, 0xa8, 0xb0, 0xd8, 0xe3, 0x67,
    0xa9, 0x91, 0xb4, 0x85, 0xcd, 0x55, 0x90, 0x83, 0x31, 0xa2, 0xf1, 0x41, 0x1a, 0x18, 0x9a, 0x9b,
    0xca, 0x0b, 0xd2, 0x93, 0x48, 0xa3, 0x5c, 0xa1, 0xf1, 0xfb, 0xbb, 0x2d, 0xcf, 0x4c, 0x7c, 0xc7,
    0x08, 0xda, 0xe2, 0xce, 0x84, 0xbd, 0xb8, 0xb8, 0xd0, 0x54, 0x6e, 0xdf, 0x1f, 0x19, 0x13, 0xe1,
    0x4d, 0x1a, 0x2e, 0x41, 0x74, 0x64, 0xe5, 0x12, 0x9c, 0x6c, 0xdf, 0xca, 0x23, 0x2e, 0x72, 0x63,
    0x34, 0x5b, 0x6a, 0x41, 0x81, 0xa8, 0xe8, 0x0f, 0xea, 0xe9, 0x95, 0x17, 0x67, 0x1e, 0xb5, 0xc7,
    0x83, 0xc0, 0x75, 0xdf, 0xb5, 0xca, 0xbe, 0xcf, 0xcc, 0x41, 0xab, 0x63, 0x16, 0x52, 0x66, 0xcc,
    0xd5, 0x70, 0x6b, 0xec, 0x3e, 0x40, 0xc7, 0xf3, 0xd1, 0xb2, 0x35, 0xbd, 0xe1, 0xbc, 0x22, 0x23,
    0x4a, 0xab, 0x59, 0xdf, 0x0a, 0xa0, 0x05, 0x7b, 0xf2, 0xa5, 0xb5, 0x51, 0xf2, 0x53, 0x3a, 0x85,
    0xb3, 0xb4, 0xf9, 0xcd, 0x54, 0x14, 0x06, 0x81, 0x3a, 0x81, 0x45, 0xf2, 0xfb, 0xc0, 0xba, 0xed,
    0x38, 0x73, 0x0d, 0x98, 0xe6, 0x7c, 0xec, 0xac, 0x66, 0x4e, 0xb7, 0xde, 0xaa, 0x97, 0x26, 0xd7,
    0xbb, 0x5c, 0x77, 0x91, 0xe1, 0xf8, 0x16, 0xdd, 0xa6, 0x07, 0x0a, 0xcf, 0xd1, 0xb3, 0x4b, 0xde,
    0xff, 0x8f, 0xa7, 0x2b, 0xd7, 0x74, 0x4d, 0xd0, 0xe6, 0x9c, 0x32, 0xb5, 0x2c, 0x4b, 0xc1, 0xd2,
    0x45, 0x7a, 0xe5, 0x42, 0x2f, 0x63, 0xa4, 0x5b, 0x6c, 0x5c, 0x8f, 0x10, 0x85, 0x27, 0x71, 0xb1,
    0x3e, 0x3a, 0x92, 0x84, 0x92, 0x7f, 0x7d, 0x75, 0x67, 0xe5, 0x70, 0xee, 0xf2, 0x22, 0xa7, 0x33,
    0xae, 0xb5, 0xc4, 0x1a, 0xfe, 0xdb, 0x76, 0x28, 0x65, 0xc3, 0xba, 0xeb, 0x23, 0xdc, 0x09, 0x50,
    0x04, 0xe9, 0xe3, 0xd7, 0x20, 0x56, 0x09, 0x0d, 0xb2, 0xcc, 0xed, 0x16, 0xb3, 0x31, 0x55, 0x86,
    0xde, 0xca, 0x79, 0x4d, 0xd4, 0xf8, 0xd1, 0x70, 0x0a, 0x15, 0xbb, 0xb1, 0xaf, 0xc6, 0xf2, 0x7f,
    0x15, 0xeb, 0x1d, 0x34, 0x14, 0x18, 0x9b, 0x52, 0x79, 0xb3, 0xc9, 0x59, 0xf6, 0xc6, 0xbf, 0xb7,
    0x7c, 0x60, 0xd1, 0xa7, 0x77, 0x8b, 0x4e, 0xa8, 0x70, 0xc9, 0xbf, 0xcf, 0x11, 0x92, 0xa3, 0x71,
    0x42, 0x23, 0xbc, 0x5b, 0x4c, 0x9b, 0x9f, 0xae, 0xc1, 0xb6, 0xb6, 0xb9, 0x4a, 0x4c, 0xde, 0x3b,
    0xc0, 0x52, 0xa9, 0x79, 0xfd, 0xf5, 0x8a, 0x8d, 0x44, 0xc9, 0x16, 0xa5, 0x7b, 0x60, 0x04, 0x26,
    0x49, 0x44, 0x17, 0x67, 0xd3, 0x14, 0xb8, 0x95, 0x6c, 0xca, 0x11, 0x5f, 0xfb, 0x22, 0x1e, 0xc7,
    0x23, 0x97, 0x13, 0x49, 0xb3, 0x43, 0x5e, 0xf6, 0xfd, 0xf8, 0x29, 0xa2, 0x7c, 0x25, 0x0a, 0xc8,
    0xf9, 0x73, 0x9f, 0xb7, 0x12, 0x70, 0x60, 0x2d, 0x4e, 0xc0, 0xcc, 0xc7, 0xa2, 0xa6, 0xdc, 0x1e,
    0x54, 0x75, 0xfa, 0x18, 0xa5, 0xdf, 0x7c, 0x05, 0x69, 0x4f, 0xd7, 0x09, 0xf2, 0xf3, 0xaf, 0x5c,
    0x08, 0xf2, 0x46, 0x0f, 0x04, 0x2b, 0xc2, 0x7e, 0xe7, 0x0f, 0x12, 0x6b, 0x1a, 0xe3, 0x30, 0xcb,
    0xdf, 0xa7, 0x5f, 0x42, 0x9c, 0x44, 0x9f, 0x70, 0x7f, 0xab, 0x3e, 0x72, 0x71, 0xb6, 0xbc, 0xae,
    0x10, 0xee, 0xc7, 0x96, 0xb5, 0xc8, 0x33, 0xdf, 0x22, 0xb4, 0x43, 0x2d, 0x70, 0x49, 0xb9, 0x0f,
    0x69, 0x53, 0xe6, 0x38, 0x7b, 0x5b, 0x35, 0xff, 0x1a, 0x86, 0x22, 0x73, 0x76, 0x79, 0xb4, 0x41,
    0x31, 0x90, 0xcd, 0x12, 0xf8, 0xd6, 0x78, 0x6c, 0x09, 0x6e, 0xd0, 0xbc, 0x95, 0xcd, 0x56, 0xba,
    0x3f, 0x91, 0x78, 0x39, 0xc9, 0x8f
};
static const uint8_t mcquic_kat_header1115[] = {
    0x47, 0x71, 0x6d, 0x63, 0x66, 0x69, 0x6c, 0x65, 0x31, 0x00, 0x00, 0x04, 0x5b
};
static const uint8_t mcquic_kat_plaintext1115_head[] = {
    0x31, 0x44, 0x16, 0x51, 0x4d, 0x43, 0x46, 0x01, 0x02, 0x9c, 0xa3, 0x1b, 0x12, 0x69, 0x12, 0x75,
    0x53, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x04, 0x00, 0x07, 0xff, 0xe4, 0xc2, 0x2b, 0x44, 0xdd
};
static const uint8_t mcquic_kat_plaintext1115_sha256[] = {
    0x9f, 0x13, 0x30, 0xdf, 0x4c, 0x30, 0x11, 0xea, 0x9d, 0x13, 0x12, 0xfb, 0x13, 0x5b, 0x51, 0xa1,
    0x36, 0x61, 0x8a, 0x6f, 0x03, 0xb4, 0x5a, 0x6e, 0xe2, 0xb6, 0xe6, 0x5e, 0xfe, 0x40, 0xa9, 0x21
};
/* sha256-32 of packet 1115, as sent by the server in MC_INTEGRITY */
static const uint8_t mcquic_kat_hash1115[] = {
    0xf0, 0xbb, 0x4a, 0x7f, 0xda, 0x82, 0x95, 0x21, 0x6e, 0x1b, 0xa8, 0x45, 0x0f, 0x48, 0xb5, 0x6a,
    0x76, 0x1e, 0x22, 0xab, 0xd4, 0x11, 0x32, 0x7c, 0x8f, 0xd1, 0x07, 0xa1, 0x67, 0x73, 0x8f, 0xda
};
/* Control frames: server (ANNOUNCE, KEY, JOIN, INTEGRITY) and client (LIMITS, STATE, ACK) */
static const uint8_t mcquic_kat_frame_announce[] = {
    0x8f, 0xf3, 0xe8, 0x11, 0x08, 0x71, 0x6d, 0x63, 0x66, 0x69, 0x6c, 0x65, 0x31, 0xc0, 0x00, 0x02,
    0x01, 0xe8, 0x01, 0x02, 0x03, 0x11, 0x5c, 0x13, 0x01, 0x10, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x13, 0x01, 0x00, 0x01, 0x44, 0x00,
    0x19
};
static const uint8_t mcquic_kat_frame_key[] = {
    0x8f, 0xf3, 0xe8, 0x01, 0x08, 0x71, 0x6d, 0x63, 0x66, 0x69, 0x6c, 0x65, 0x31, 0x01, 0x00, 0x10,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};
static const uint8_t mcquic_kat_frame_join[] = {
    0x8f, 0xf3, 0xe8, 0x02, 0x08, 0x71, 0x6d, 0x63, 0x66, 0x69, 0x6c, 0x65, 0x31, 0x01, 0x00, 0x01
};
static const uint8_t mcquic_kat_frame_integrity[] = {
    0x8f, 0xf3, 0xe8, 0x05, 0x08, 0x71, 0x6d, 0x63, 0x66, 0x69, 0x6c, 0x65, 0x31, 0x44, 0x5b, 0x01,
    0xf0, 0xbb, 0x4a, 0x7f, 0xda, 0x82, 0x95, 0x21, 0x6e, 0x1b, 0xa8, 0x45, 0x0f, 0x48, 0xb5, 0x6a,
    0x76, 0x1e, 0x22, 0xab, 0xd4, 0x11, 0x32, 0x7c, 0x8f, 0xd1, 0x07, 0xa1, 0x67, 0x73, 0x8f, 0xda
};
static const uint8_t mcquic_kat_frame_limits[] = {
    0x8f, 0xf3, 0xe8, 0x09, 0x01, 0x01, 0x60, 0x00, 0x10, 0x04
};
static const uint8_t mcquic_kat_frame_state[] = {
    0x8f, 0xf3, 0xe8, 0x0b, 0x08, 0x71, 0x6d, 0x63, 0x66, 0x69, 0x6c, 0x65, 0x31, 0x01, 0x03, 0x01,
    0x00
};
static const uint8_t mcquic_kat_frame_ack[] = {
    0x8f, 0xf3, 0xe8, 0x06, 0x08, 0x71, 0x6d, 0x63, 0x66, 0x69, 0x6c, 0x65, 0x31, 0x44, 0x5c, 0x00,
    0x00, 0x01
};
static const uint8_t mcquic_kat_client_params[] = {
    0x01, 0x60, 0x00, 0x10, 0x01, 0x01, 0x00, 0x01, 0x13, 0x01
};
#define MCQUIC_KAT_PLAINTEXT1115_LENGTH 1049

#define MCQUIC_TEST_CHECK(c) if (!(c)) { DBG_PRINTF("mcquic test failed: %s, line %d", #c, __LINE__); return -1; }

static int mcquic_kat_bytes_equal(const uint8_t* x, size_t x_len, const uint8_t* y, size_t y_len)
{
    return x_len == y_len && memcmp(x, y, x_len) == 0;
}

/* Channel packet protection keys, derived from the example's 16-byte secrets */
int mcquic_kat_keys_test(void)
{
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t hp[16];

    MCQUIC_TEST_CHECK(picoquic_mcquic_derive(PICOQUIC_AES_128_GCM_SHA256, mcquic_kat_payload_secret,
        sizeof(mcquic_kat_payload_secret), "quic key", key, sizeof(key)) == 0);
    MCQUIC_TEST_CHECK(memcmp(key, mcquic_kat_key, sizeof(key)) == 0);
    MCQUIC_TEST_CHECK(picoquic_mcquic_derive(PICOQUIC_AES_128_GCM_SHA256, mcquic_kat_payload_secret,
        sizeof(mcquic_kat_payload_secret), "quic iv", iv, sizeof(iv)) == 0);
    MCQUIC_TEST_CHECK(memcmp(iv, mcquic_kat_iv, sizeof(iv)) == 0);
    /* The header protection key comes from the MC_ANNOUNCE header secret, not the MC_KEY secret */
    MCQUIC_TEST_CHECK(picoquic_mcquic_derive(PICOQUIC_AES_128_GCM_SHA256, mcquic_kat_header_secret,
        sizeof(mcquic_kat_header_secret), "quic hp", hp, sizeof(hp)) == 0);
    MCQUIC_TEST_CHECK(memcmp(hp, mcquic_kat_hp, sizeof(hp)) == 0);
    return 0;
}

/* Header protection removal and packet number decoding */
int mcquic_kat_header_test(void)
{
    uint8_t header[32];
    uint64_t pn = UINT64_MAX;
    size_t header_length;
    int ret = 0;
    void* hp_ctx = picoquic_mcquic_hp_create(PICOQUIC_AES_128_GCM_SHA256, mcquic_kat_header_secret,
        sizeof(mcquic_kat_header_secret));

    if (hp_ctx == NULL) {
        return -1;
    }
    /* First packet: expected packet number is the key's From Packet Number, 0 */
    header_length = picoquic_mcquic_unprotect_header(hp_ctx, mcquic_kat_packet0, sizeof(mcquic_kat_packet0),
        sizeof(mcquic_kat_channel_id), 0, header, &pn);
    if (header_length != sizeof(mcquic_kat_header0) || memcmp(header, mcquic_kat_header0, header_length) != 0 || pn != 0) {
        ret = -1;
    }
    /* Unprotected first byte 0x47: short header, key phase 1 (key sequence 1 is odd), 4-byte packet number */
    if (ret == 0 && header[0] != 0x47) {
        ret = -1;
    }
    /* Packet 1115, decoded both next to the largest packet seen and from a cold start */
    if (ret == 0) {
        header_length = picoquic_mcquic_unprotect_header(hp_ctx, mcquic_kat_packet1115, sizeof(mcquic_kat_packet1115),
            sizeof(mcquic_kat_channel_id), 1114, header, &pn);
        if (header_length != sizeof(mcquic_kat_header1115) || memcmp(header, mcquic_kat_header1115, header_length) != 0 ||
            pn != 1115) {
            ret = -1;
        }
    }
    if (ret == 0) {
        header_length = picoquic_mcquic_unprotect_header(hp_ctx, mcquic_kat_packet1115, sizeof(mcquic_kat_packet1115),
            sizeof(mcquic_kat_channel_id), 0, header, &pn);
        if (header_length == 0 || pn != 1115) {
            ret = -1;
        }
    }
    /* Packet number reconstruction across a 32-bit wrap: truncated 0x0000045b near 2^32 + 1000 */
    if (ret == 0) {
        header_length = picoquic_mcquic_unprotect_header(hp_ctx, mcquic_kat_packet1115, sizeof(mcquic_kat_packet1115),
            sizeof(mcquic_kat_channel_id), 0x100000000ull + 1000, header, &pn);
        if (header_length == 0 || pn != 0x100000000ull + 1115) {
            ret = -1;
        }
    }
    /* A long header packet is not a channel packet */
    if (ret == 0) {
        uint8_t bad[sizeof(mcquic_kat_packet0)];
        memcpy(bad, mcquic_kat_packet0, sizeof(bad));
        bad[0] |= 0x80;
        if (picoquic_mcquic_unprotect_header(hp_ctx, bad, sizeof(bad), sizeof(mcquic_kat_channel_id), 0, header, &pn) != 0) {
            ret = -1;
        }
    }
    picoquic_cipher_free(hp_ctx);
    return ret;
}

/* AEAD decryption of the two packets, and rejection of a modified one */
int mcquic_kat_decrypt_test(void)
{
    uint8_t plaintext[2048];
    uint8_t digest[32];
    uint8_t bad[sizeof(mcquic_kat_packet1115)];
    size_t length;
    int ret = 0;
    void* aead = picoquic_mcquic_aead_create(PICOQUIC_AES_128_GCM_SHA256, mcquic_kat_payload_secret,
        sizeof(mcquic_kat_payload_secret));

    if (aead == NULL) {
        return -1;
    }
    length = picoquic_mcquic_decrypt(aead, mcquic_kat_packet0, sizeof(mcquic_kat_packet0), mcquic_kat_header0,
        sizeof(mcquic_kat_header0), 0, plaintext);
    if (!mcquic_kat_bytes_equal(plaintext, length, mcquic_kat_plaintext0, sizeof(mcquic_kat_plaintext0))) {
        ret = -1;
    }
    if (ret == 0) {
        length = picoquic_mcquic_decrypt(aead, mcquic_kat_packet1115, sizeof(mcquic_kat_packet1115), mcquic_kat_header1115,
            sizeof(mcquic_kat_header1115), 1115, plaintext);
        if (length != MCQUIC_KAT_PLAINTEXT1115_LENGTH ||
            memcmp(plaintext, mcquic_kat_plaintext1115_head, sizeof(mcquic_kat_plaintext1115_head)) != 0 ||
            ptls_calc_hash(((ptls_cipher_suite_t*)picoquic_get_cipher_suite_by_id_v(PICOQUIC_AES_128_GCM_SHA256))->hash, digest, plaintext, length) != 0 ||
            memcmp(digest, mcquic_kat_plaintext1115_sha256, sizeof(digest)) != 0) {
            ret = -1;
        }
    }
    if (ret == 0) {
        /* Same packet with the wrong packet number in the nonce */
        length = picoquic_mcquic_decrypt(aead, mcquic_kat_packet1115, sizeof(mcquic_kat_packet1115), mcquic_kat_header1115,
            sizeof(mcquic_kat_header1115), 1116, plaintext);
        if (length != SIZE_MAX) {
            ret = -1;
        }
    }
    if (ret == 0) {
        memcpy(bad, mcquic_kat_packet1115, sizeof(bad));
        bad[500] ^= 1;
        length = picoquic_mcquic_decrypt(aead, bad, sizeof(bad), mcquic_kat_header1115,
            sizeof(mcquic_kat_header1115), 1115, plaintext);
        if (length != SIZE_MAX) {
            ret = -1;
        }
    }
    picoquic_aead_free(aead);
    return ret;
}

/* sha256-32 integrity hash over the protected packet, as sent in MC_INTEGRITY */
int mcquic_kat_integrity_test(void)
{
    uint8_t hash[PICOQUIC_MCQUIC_HASH_MAX];

    MCQUIC_TEST_CHECK(picoquic_mcquic_hash_length(PICOQUIC_MCQUIC_HASH_SHA256) == 32);
    MCQUIC_TEST_CHECK(picoquic_mcquic_integrity_hash(PICOQUIC_MCQUIC_HASH_SHA256, mcquic_kat_packet1115,
        sizeof(mcquic_kat_packet1115), hash, sizeof(hash)) == 0);
    MCQUIC_TEST_CHECK(memcmp(hash, mcquic_kat_hash1115, 32) == 0);
    MCQUIC_TEST_CHECK(picoquic_mcquic_integrity_hash(PICOQUIC_MCQUIC_HASH_SHA256, mcquic_kat_packet0,
        sizeof(mcquic_kat_packet0), hash, sizeof(hash)) == 0);
    MCQUIC_TEST_CHECK(memcmp(hash, mcquic_kat_hash0, 32) == 0);
    /* Truncated variant keeps the leading bytes */
    MCQUIC_TEST_CHECK(picoquic_mcquic_integrity_hash(PICOQUIC_MCQUIC_HASH_SHA256_128, mcquic_kat_packet1115,
        sizeof(mcquic_kat_packet1115), hash, sizeof(hash)) == 0);
    MCQUIC_TEST_CHECK(memcmp(hash, mcquic_kat_hash1115, 16) == 0);
    /* The same hash in the captured MC_INTEGRITY frame */
    MCQUIC_TEST_CHECK(memcmp(mcquic_kat_frame_integrity + sizeof(mcquic_kat_frame_integrity) - 32, mcquic_kat_hash1115, 32) == 0);
    return 0;
}

/* Transport parameter value, byte for byte as the QUICast client sends it */
int mcquic_kat_tp_test(void)
{
    picoquic_mcquic_client_params_t params;
    picoquic_mcquic_client_params_t decoded;
    uint8_t buffer[64];
    uint8_t* bytes;
    uint8_t draft09[sizeof(mcquic_kat_client_params) + 1];

    picoquic_mcquic_set_default_client_params(&params);
    bytes = picoquic_mcquic_client_params_encode(buffer, buffer + sizeof(buffer), &params);
    MCQUIC_TEST_CHECK(bytes != NULL && mcquic_kat_bytes_equal(buffer, bytes - buffer, mcquic_kat_client_params, sizeof(mcquic_kat_client_params)));
    MCQUIC_TEST_CHECK(picoquic_mcquic_client_params_decode(mcquic_kat_client_params,
        mcquic_kat_client_params + sizeof(mcquic_kat_client_params), &decoded) != NULL);
    MCQUIC_TEST_CHECK(decoded.ipv4_allowed && !decoded.ipv6_allowed && decoded.max_rate_kibps == 8192 &&
        decoded.max_channel_ids == 16 && decoded.nb_hash_algs == 1 && decoded.hash_algs[0] == 1 &&
        decoded.nb_cipher_suites == 1 && decoded.cipher_suites[0] == 0x1301);
    /* A value with the Max Joined Count field that draft-09 adds does not match the counts */
    memcpy(draft09, mcquic_kat_client_params, 4);
    draft09[4] = 4;
    memcpy(draft09 + 5, mcquic_kat_client_params + 4, sizeof(mcquic_kat_client_params) - 4);
    MCQUIC_TEST_CHECK(picoquic_mcquic_client_params_decode(draft09, draft09 + sizeof(draft09), &decoded) == NULL);
    return 0;
}

static int mcquic_kat_frame_roundtrip(const uint8_t* wire, size_t wire_length, size_t hash_length, picoquic_mcquic_frame_t* f)
{
    uint64_t frame_type = 0;
    const uint8_t* bytes = picoquic_frames_varint_decode(wire, wire + wire_length, &frame_type);
    uint8_t buffer[256];
    uint8_t* encoded;

    if (bytes == NULL || !picoquic_mcquic_is_frame_type(frame_type) ||
        picoquic_mcquic_frame_decode(bytes, wire + wire_length, frame_type, hash_length, f) != wire + wire_length) {
        return -1;
    }
    encoded = picoquic_mcquic_frame_encode(buffer, buffer + sizeof(buffer), f);
    return (encoded != NULL && mcquic_kat_bytes_equal(buffer, encoded - buffer, wire, wire_length)) ? 0 : -1;
}

/* Control frames: decode what the quiche server and client sent, re-encode identically */
int mcquic_kat_frames_test(void)
{
    picoquic_mcquic_frame_t f;
    int pure_ack = 0;

    MCQUIC_TEST_CHECK(mcquic_kat_frame_roundtrip(mcquic_kat_frame_announce, sizeof(mcquic_kat_frame_announce), 0, &f) == 0);
    MCQUIC_TEST_CHECK(f.channel_id.id_len == 8 && memcmp(f.channel_id.id, mcquic_kat_channel_id, 8) == 0);
    MCQUIC_TEST_CHECK(!f.u.announce.is_ipv6 && f.u.announce.source[0] == 192 && f.u.announce.source[3] == 1 &&
        f.u.announce.group[0] == 232 && f.u.announce.group[3] == 3 && f.u.announce.port == 4444);
    MCQUIC_TEST_CHECK(f.u.announce.header_protection_alg == 0x1301 && f.u.announce.aead_alg == 0x1301 &&
        f.u.announce.hash_alg == 1 && f.u.announce.max_rate_kibps == 1024 && f.u.announce.max_ack_delay_ms == 25);
    MCQUIC_TEST_CHECK(mcquic_kat_bytes_equal(f.u.announce.header_secret, f.u.announce.header_secret_len,
        mcquic_kat_header_secret, sizeof(mcquic_kat_header_secret)));

    MCQUIC_TEST_CHECK(mcquic_kat_frame_roundtrip(mcquic_kat_frame_key, sizeof(mcquic_kat_frame_key), 0, &f) == 0);
    MCQUIC_TEST_CHECK(f.u.key.key_sequence == 1 && f.u.key.from_packet_number == 0 &&
        mcquic_kat_bytes_equal(f.u.key.secret, f.u.key.secret_len, mcquic_kat_payload_secret, sizeof(mcquic_kat_payload_secret)));

    MCQUIC_TEST_CHECK(mcquic_kat_frame_roundtrip(mcquic_kat_frame_join, sizeof(mcquic_kat_frame_join), 0, &f) == 0);
    MCQUIC_TEST_CHECK(f.u.join.limits_sequence == 1 && f.u.join.state_sequence == 0 && f.u.join.key_sequence == 1);

    /* MC_INTEGRITY with a hash count needs the channel's hash length */
    MCQUIC_TEST_CHECK(mcquic_kat_frame_roundtrip(mcquic_kat_frame_integrity, sizeof(mcquic_kat_frame_integrity), 0, &f) != 0);
    MCQUIC_TEST_CHECK(mcquic_kat_frame_roundtrip(mcquic_kat_frame_integrity, sizeof(mcquic_kat_frame_integrity), 32, &f) == 0);
    MCQUIC_TEST_CHECK(f.u.integrity.packet_number_start == 1115 && f.u.integrity.has_count && f.u.integrity.hash_count == 1 &&
        mcquic_kat_bytes_equal(f.u.integrity.hashes, f.u.integrity.hashes_length, mcquic_kat_hash1115, 32));

    MCQUIC_TEST_CHECK(mcquic_kat_frame_roundtrip(mcquic_kat_frame_limits, sizeof(mcquic_kat_frame_limits), 0, &f) == 0);
    MCQUIC_TEST_CHECK(f.u.limits.sequence == 1 && f.u.limits.ipv4_allowed && !f.u.limits.ipv6_allowed &&
        f.u.limits.max_rate_kibps == 8192 && f.u.limits.max_channel_ids == 16 && f.u.limits.max_joined == 4);

    MCQUIC_TEST_CHECK(mcquic_kat_frame_roundtrip(mcquic_kat_frame_state, sizeof(mcquic_kat_frame_state), 0, &f) == 0);
    MCQUIC_TEST_CHECK(f.u.state.sequence == 1 && f.u.state.state == PICOQUIC_MCQUIC_STATE_JOINED &&
        f.u.state.reason == PICOQUIC_MCQUIC_REASON_REQUESTED_BY_SERVER && f.u.state.phrase_length == 0);

    MCQUIC_TEST_CHECK(mcquic_kat_frame_roundtrip(mcquic_kat_frame_ack, sizeof(mcquic_kat_frame_ack), 0, &f) == 0);
    MCQUIC_TEST_CHECK(f.u.ack.largest == 1116 && f.u.ack.ack_delay == 0 && f.u.ack.range_count == 0 && f.u.ack.first_range == 1);

    /* The frames this client sends can be skipped by the loss recovery code; MC_ACK is not ack-eliciting */
    MCQUIC_TEST_CHECK(picoquic_mcquic_frame_skip(mcquic_kat_frame_ack + 4, mcquic_kat_frame_ack + sizeof(mcquic_kat_frame_ack),
        PICOQUIC_MCQUIC_FRAME_ACK, &pure_ack) == mcquic_kat_frame_ack + sizeof(mcquic_kat_frame_ack) && pure_ack == 1);
    MCQUIC_TEST_CHECK(picoquic_mcquic_frame_skip(mcquic_kat_frame_state + 4, mcquic_kat_frame_state + sizeof(mcquic_kat_frame_state),
        PICOQUIC_MCQUIC_FRAME_STATE, &pure_ack) == mcquic_kat_frame_state + sizeof(mcquic_kat_frame_state) && pure_ack == 0);

    /* Truncated frames are rejected */
    {
        uint64_t frame_type = 0;
        const uint8_t* bytes = picoquic_frames_varint_decode(mcquic_kat_frame_announce,
            mcquic_kat_frame_announce + sizeof(mcquic_kat_frame_announce), &frame_type);
        for (size_t l = 4; l < sizeof(mcquic_kat_frame_announce); l++) {
            MCQUIC_TEST_CHECK(picoquic_mcquic_frame_decode(bytes, mcquic_kat_frame_announce + l, frame_type, 0, &f) == NULL);
        }
    }
    return 0;
}

/* Integrity hash algorithms by registry ID, as quiche maps them: 1 is SHA-256,
 * 5 is SHA-256 truncated to 8 bytes, 6 to 4 bytes. The client advertises the
 * chosen one, and an MC_INTEGRITY batch of such hashes decodes by count. */
int mcquic_kat_hash_ids_test(void)
{
    static const uint16_t ids[3] = { PICOQUIC_MCQUIC_HASH_SHA256, PICOQUIC_MCQUIC_HASH_SHA256_64, PICOQUIC_MCQUIC_HASH_SHA256_32 };
    static const size_t lengths[3] = { 32, 8, 4 };
    uint8_t hash[PICOQUIC_MCQUIC_HASH_MAX];
    uint8_t buffer[512];
    uint8_t* bytes;
    picoquic_mcquic_client_params_t params;
    picoquic_mcquic_client_params_t decoded;
    picoquic_mcquic_frame_t f;

    MCQUIC_TEST_CHECK(picoquic_mcquic_hash_length(PICOQUIC_MCQUIC_HASH_SHA512) == 64 && picoquic_mcquic_hash_length(9) == 0 &&
        picoquic_mcquic_hash_length(0) == 0);
    for (size_t i = 0; i < 3; i++) {
        uint64_t frame_type = 0;
        const uint8_t* next;

        MCQUIC_TEST_CHECK(picoquic_mcquic_hash_length(ids[i]) == lengths[i]);
        /* The truncated variants are the leading bytes of the SHA-256 digest */
        MCQUIC_TEST_CHECK(picoquic_mcquic_integrity_hash(ids[i], mcquic_kat_packet0, sizeof(mcquic_kat_packet0), hash, sizeof(hash)) == 0);
        MCQUIC_TEST_CHECK(memcmp(hash, mcquic_kat_hash0, lengths[i]) == 0);
        MCQUIC_TEST_CHECK(picoquic_mcquic_integrity_hash(ids[i], mcquic_kat_packet0, sizeof(mcquic_kat_packet0), hash, lengths[i] - 1) != 0);
        /* Advertised in multicast_client_params */
        picoquic_mcquic_set_default_client_params(&params);
        params.hash_algs[0] = ids[i];
        bytes = picoquic_mcquic_client_params_encode(buffer, buffer + sizeof(buffer), &params);
        MCQUIC_TEST_CHECK(bytes != NULL && picoquic_mcquic_client_params_decode(buffer, bytes, &decoded) == bytes);
        MCQUIC_TEST_CHECK(decoded.nb_hash_algs == 1 && decoded.hash_algs[0] == ids[i]);
        /* A batch of 3 hashes in one MC_INTEGRITY */
        memset(&f, 0, sizeof(f));
        f.frame_type = PICOQUIC_MCQUIC_FRAME_INTEGRITY_LEN;
        f.channel_id.id_len = sizeof(mcquic_kat_channel_id);
        memcpy(f.channel_id.id, mcquic_kat_channel_id, sizeof(mcquic_kat_channel_id));
        f.u.integrity.packet_number_start = 1000;
        f.u.integrity.has_count = 1;
        f.u.integrity.hash_count = 3;
        f.u.integrity.hashes = mcquic_kat_hash0;
        f.u.integrity.hashes_length = 3 * lengths[i];
        MCQUIC_TEST_CHECK(3 * lengths[i] <= 3 * 32);
        {
            uint8_t hashes[3 * 32];
            memcpy(hashes, mcquic_kat_hash0, 32);
            memcpy(hashes + 32, mcquic_kat_hash1115, 32);
            memcpy(hashes + 64, mcquic_kat_hash0, 32);
            f.u.integrity.hashes = hashes;
            bytes = picoquic_mcquic_frame_encode(buffer, buffer + sizeof(buffer), &f);
        }
        MCQUIC_TEST_CHECK(bytes != NULL);
        next = picoquic_frames_varint_decode(buffer, bytes, &frame_type);
        memset(&f, 0, sizeof(f));
        MCQUIC_TEST_CHECK(next != NULL && picoquic_mcquic_frame_decode(next, bytes, frame_type, lengths[i], &f) == bytes);
        MCQUIC_TEST_CHECK(f.u.integrity.hash_count == 3 && f.u.integrity.hashes_length == 3 * lengths[i] &&
            f.u.integrity.packet_number_start == 1000);
        /* With the wrong hash length the count does not match the frame */
        MCQUIC_TEST_CHECK(picoquic_mcquic_frame_decode(next, bytes, frame_type, lengths[i] + 1, &f) != bytes);
    }
    return 0;
}

/* Send path: with the example's fixed secrets, the sender's channel packets and
 * control frames must be byte-identical to those the QUICast example server sent
 * (AES-GCM is deterministic for a given key, nonce and plaintext). */
static int mcquic_kat_encode_frame(const picoquic_mcquic_frame_t* f, const uint8_t* expected, size_t expected_length)
{
    uint8_t buffer[256];
    uint8_t* bytes = picoquic_mcquic_frame_encode(buffer, buffer + sizeof(buffer), f);

    return (bytes != NULL && mcquic_kat_bytes_equal(buffer, bytes - buffer, expected, expected_length)) ? 0 : -1;
}

int mcquic_kat_encode_test(void)
{
    picoquic_mcquic_sender_config_t config;
    picoquic_mcquic_frame_t f;
    uint8_t plaintext[2048];
    uint8_t packet[2048];
    uint8_t hash[PICOQUIC_MCQUIC_HASH_MAX];
    size_t length;
    void* hp = NULL;
    void* aead_enc = NULL;
    void* aead_dec = NULL;
    int ret = 0;

    picoquic_mcquic_set_default_sender_config(&config);
    config.source[0] = 192;
    config.source[1] = 0;
    config.source[2] = 2;
    config.source[3] = 1;
    /* Control frames */
    picoquic_mcquic_sender_frame(&config, PICOQUIC_MCQUIC_FRAME_ANNOUNCE_V4, &f);
    MCQUIC_TEST_CHECK(mcquic_kat_encode_frame(&f, mcquic_kat_frame_announce, sizeof(mcquic_kat_frame_announce)) == 0);
    picoquic_mcquic_sender_frame(&config, PICOQUIC_MCQUIC_FRAME_KEY, &f);
    MCQUIC_TEST_CHECK(mcquic_kat_encode_frame(&f, mcquic_kat_frame_key, sizeof(mcquic_kat_frame_key)) == 0);
    picoquic_mcquic_sender_frame(&config, PICOQUIC_MCQUIC_FRAME_JOIN, &f);
    f.u.join.limits_sequence = 1;
    MCQUIC_TEST_CHECK(mcquic_kat_encode_frame(&f, mcquic_kat_frame_join, sizeof(mcquic_kat_frame_join)) == 0);
    memset(&f, 0, sizeof(f));
    f.frame_type = PICOQUIC_MCQUIC_FRAME_INTEGRITY_LEN;
    f.channel_id = config.channel_id;
    f.u.integrity.packet_number_start = 1115;
    f.u.integrity.has_count = 1;
    f.u.integrity.hash_count = 1;
    f.u.integrity.hashes = mcquic_kat_hash1115;
    f.u.integrity.hashes_length = sizeof(mcquic_kat_hash1115);
    MCQUIC_TEST_CHECK(mcquic_kat_encode_frame(&f, mcquic_kat_frame_integrity, sizeof(mcquic_kat_frame_integrity)) == 0);

    /* Channel packets */
    hp = picoquic_mcquic_hp_create(config.cipher_suite, config.header_secret, config.header_secret_len);
    aead_enc = picoquic_mcquic_aead_create_encrypt(config.cipher_suite, config.key_secret, config.key_secret_len);
    aead_dec = picoquic_mcquic_aead_create(config.cipher_suite, config.key_secret, config.key_secret_len);
    if (hp == NULL || aead_enc == NULL || aead_dec == NULL) {
        ret = -1;
    }
    if (ret == 0) {
        length = picoquic_mcquic_protect(hp, aead_enc, 1, &config.channel_id, 0, mcquic_kat_plaintext0,
            sizeof(mcquic_kat_plaintext0), packet, sizeof(packet));
        if (!mcquic_kat_bytes_equal(packet, length, mcquic_kat_packet0, sizeof(mcquic_kat_packet0)) ||
            picoquic_mcquic_integrity_hash(config.hash_alg, packet, length, hash, sizeof(hash)) != 0 ||
            memcmp(hash, mcquic_kat_hash0, sizeof(mcquic_kat_hash0)) != 0) {
            ret = -1;
        }
    }
    if (ret == 0) {
        /* The captured plaintext of packet 1115, re-encrypted */
        size_t pt_length = picoquic_mcquic_decrypt(aead_dec, mcquic_kat_packet1115, sizeof(mcquic_kat_packet1115),
            mcquic_kat_header1115, sizeof(mcquic_kat_header1115), 1115, plaintext);
        length = (pt_length == SIZE_MAX) ? 0 : picoquic_mcquic_protect(hp, aead_enc, 1, &config.channel_id, 1115,
            plaintext, pt_length, packet, sizeof(packet));
        if (!mcquic_kat_bytes_equal(packet, length, mcquic_kat_packet1115, sizeof(mcquic_kat_packet1115)) ||
            picoquic_mcquic_integrity_hash(config.hash_alg, packet, length, hash, sizeof(hash)) != 0 ||
            memcmp(hash, mcquic_kat_hash1115, sizeof(mcquic_kat_hash1115)) != 0) {
            ret = -1;
        }
    }
    if (ret == 0) {
        /* Too small an output buffer is refused */
        if (picoquic_mcquic_protect(hp, aead_enc, 1, &config.channel_id, 0, mcquic_kat_plaintext0,
            sizeof(mcquic_kat_plaintext0), packet, sizeof(mcquic_kat_packet0) - 1) != 0) {
            ret = -1;
        }
    }
    if (hp != NULL) {
        picoquic_cipher_free(hp);
    }
    if (aead_enc != NULL) {
        picoquic_aead_free(aead_enc);
    }
    if (aead_dec != NULL) {
        picoquic_aead_free(aead_dec);
    }
    return ret;
}

/* Receive path, end to end on an unstarted client connection: the control frames
 * of the capture are fed to the frame hook, the channel packets to
 * picoquic_incoming_multicast_packet(); the frames the client queues in response
 * must match what the QUICast client sent. */
typedef struct st_mcquic_receive_test_ctx_t {
    int nb_join;
    int nb_datagram;
    uint64_t last_pn;
    size_t last_length;
    uint8_t last_head[16];
} mcquic_receive_test_ctx_t;

static int mcquic_receive_test_callback(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    mcquic_receive_test_ctx_t* ctx = (mcquic_receive_test_ctx_t*)callback_ctx;
    (void)cnx;
    (void)v_stream_ctx;
    if (fin_or_event == picoquic_callback_mc_join) {
        ctx->nb_join++;
    }
    else if (fin_or_event == picoquic_callback_mc_datagram) {
        ctx->nb_datagram++;
        ctx->last_pn = stream_id;
        ctx->last_length = length;
        memcpy(ctx->last_head, bytes, (length < 16) ? length : 16);
    }
    return 0;
}

/* Pops the oldest queued misc frame and compares it with the expected bytes */
static int mcquic_receive_test_pop(picoquic_cnx_t* cnx, const uint8_t* expected, size_t expected_length)
{
    picoquic_misc_frame_header_t* misc = cnx->first_misc_frame;
    int ret = -1;

    if (misc != NULL) {
        if (misc->length == expected_length && memcmp((uint8_t*)misc + sizeof(picoquic_misc_frame_header_t), expected, expected_length) == 0) {
            ret = 0;
        }
        picoquic_delete_misc_or_dg(&cnx->first_misc_frame, &cnx->last_misc_frame, misc);
    }
    return ret;
}

static int mcquic_receive_test_frame(picoquic_cnx_t* cnx, const uint8_t* wire, size_t wire_length, uint64_t now)
{
    uint64_t frame_type = 0;
    const uint8_t* bytes = picoquic_frames_varint_decode(wire, wire + wire_length, &frame_type);
    return (bytes != NULL && picoquic_mcquic_decode_control_frame(cnx, bytes, wire + wire_length, frame_type, now) == wire + wire_length) ? 0 : -1;
}

int mcquic_receive_test(void)
{
    uint64_t now = 0;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, "h3", NULL, NULL, NULL, NULL, NULL, now, &now, NULL, NULL, 0);
    picoquic_cnx_t* cnx = NULL;
    struct sockaddr_in server;
    struct sockaddr_in source;
    mcquic_receive_test_ctx_t test_ctx;
    picoquic_mcquic_stats_t stats;
    picoquic_mcquic_frame_t f;
    picoquic_mcquic_channel_id_t id;
    uint8_t buffer[128];
    uint8_t* end;
    uint8_t bad[sizeof(mcquic_kat_packet0)];
    static const uint8_t ack_1115[] = { 0x8f, 0xf3, 0xe8, 0x06, 0x08, 'q', 'm', 'c', 'f', 'i', 'l', 'e', '1', 0x44, 0x5b, 0x00, 0x00, 0x00 };
    /* Largest 1115, delay 0, one range: gap 1113 (1115 - 0 - 2), length 0 */
    static const uint8_t ack_1115_0[] = { 0x8f, 0xf3, 0xe8, 0x06, 0x08, 'q', 'm', 'c', 'f', 'i', 'l', 'e', '1', 0x44, 0x5b, 0x00, 0x01, 0x00, 0x44, 0x59, 0x00 };
    int ret = 0;

    memset(&test_ctx, 0, sizeof(test_ctx));
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(5757);
    memset(&source, 0, sizeof(source));
    source.sin_family = AF_INET;
    source.sin_addr.s_addr = htonl(0xc0000201); /* 192.0.2.1, the announced source */
    id.id_len = sizeof(mcquic_kat_channel_id);
    memcpy(id.id, mcquic_kat_channel_id, sizeof(mcquic_kat_channel_id));

    if (quic == NULL ||
        (cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&server, now, 0, "test.com", "h3", 1)) == NULL ||
        picoquic_mcquic_enable_client(cnx, NULL) != 0) {
        ret = -1;
    }
    if (ret == 0) {
        picoquic_set_callback(cnx, mcquic_receive_test_callback, &test_ctx);
        /* Server support TP: MC_LIMITS 1, as the QUICast client sends it */
        if (picoquic_mcquic_receive_server_support(cnx, 0) != 0 ||
            mcquic_receive_test_pop(cnx, mcquic_kat_frame_limits, sizeof(mcquic_kat_frame_limits)) != 0) {
            ret = -1;
        }
    }
    /* ANNOUNCE, KEY, JOIN: the client joins and reports MC_STATE Joined */
    if (ret == 0 && (mcquic_receive_test_frame(cnx, mcquic_kat_frame_announce, sizeof(mcquic_kat_frame_announce), now) != 0 ||
        mcquic_receive_test_frame(cnx, mcquic_kat_frame_key, sizeof(mcquic_kat_frame_key), now) != 0 ||
        mcquic_receive_test_frame(cnx, mcquic_kat_frame_join, sizeof(mcquic_kat_frame_join), now) != 0 ||
        test_ctx.nb_join != 1 ||
        mcquic_receive_test_pop(cnx, mcquic_kat_frame_state, sizeof(mcquic_kat_frame_state)) != 0)) {
        ret = -1;
    }
    /* Packet 1115 first: held until its hash arrives */
    if (ret == 0 && (picoquic_incoming_multicast_packet(quic, mcquic_kat_packet1115, sizeof(mcquic_kat_packet1115),
        (struct sockaddr*)&source, now) != 1 || test_ctx.nb_datagram != 0 || cnx->first_misc_frame != NULL)) {
        ret = -1;
    }
    /* Then its MC_INTEGRITY: released, one DATAGRAM of 1046 bytes, first MC_ACK as the QUICast client's */
    if (ret == 0 && (mcquic_receive_test_frame(cnx, mcquic_kat_frame_integrity, sizeof(mcquic_kat_frame_integrity), now) != 0 ||
        test_ctx.nb_datagram != 1 || test_ctx.last_pn != 1115 || test_ctx.last_length != 1046 ||
        memcmp(test_ctx.last_head, mcquic_kat_plaintext1115_head + 3, 16) != 0 ||
        mcquic_receive_test_pop(cnx, ack_1115, sizeof(ack_1115)) != 0)) {
        ret = -1;
    }
    /* A duplicate of packet 1115 is dropped */
    if (ret == 0 && (picoquic_incoming_multicast_packet(quic, mcquic_kat_packet1115, sizeof(mcquic_kat_packet1115),
        (struct sockaddr*)&source, now) != 1 || test_ctx.nb_datagram != 1)) {
        ret = -1;
    }
    /* The hash of packet 0 first, then a modified packet 0: integrity failure, nothing released */
    if (ret == 0) {
        memset(&f, 0, sizeof(f));
        f.frame_type = PICOQUIC_MCQUIC_FRAME_INTEGRITY_LEN;
        f.channel_id = id;
        f.u.integrity.packet_number_start = 0;
        f.u.integrity.has_count = 1;
        f.u.integrity.hash_count = 1;
        f.u.integrity.hashes = mcquic_kat_hash0;
        f.u.integrity.hashes_length = sizeof(mcquic_kat_hash0);
        end = picoquic_mcquic_frame_encode(buffer, buffer + sizeof(buffer), &f);
        memcpy(bad, mcquic_kat_packet0, sizeof(bad));
        bad[40] ^= 0x80;
        if (end == NULL || mcquic_receive_test_frame(cnx, buffer, end - buffer, now) != 0 ||
            picoquic_incoming_multicast_packet(quic, bad, sizeof(bad), (struct sockaddr*)&source, now) != 1 ||
            test_ctx.nb_datagram != 1 || picoquic_mcquic_get_stats(cnx, &id, &stats) != 0 || stats.integrity_failures != 1) {
            ret = -1;
        }
        /* The genuine packet 0 with its hash again: released; MC_ACK now carries a range with a gap */
        if (ret == 0 && (mcquic_receive_test_frame(cnx, buffer, end - buffer, now) != 0 ||
            picoquic_incoming_multicast_packet(quic, mcquic_kat_packet0, sizeof(mcquic_kat_packet0),
                (struct sockaddr*)&source, now) != 1 || test_ctx.nb_datagram != 2 || test_ctx.last_pn != 0)) {
            ret = -1;
        }
        if (ret == 0) {
            picoquic_mcquic_send_acks(cnx, now, 1);
            if (mcquic_receive_test_pop(cnx, ack_1115_0, sizeof(ack_1115_0)) != 0) {
                ret = -1;
            }
        }
    }
    /* A packet from another source is not taken */
    if (ret == 0) {
        source.sin_addr.s_addr = htonl(0xc6336401); /* 198.51.100.1 */
        if (picoquic_incoming_multicast_packet(quic, mcquic_kat_packet0, sizeof(mcquic_kat_packet0),
            (struct sockaddr*)&source, now) != 0) {
            ret = -1;
        }
    }
    if (ret == 0 && (picoquic_mcquic_get_stats(cnx, &id, &stats) != 0 || stats.packets_released != 2 ||
        stats.decrypt_failures != 0 || stats.packets_duplicate != 1)) {
        ret = -1;
    }
    if (quic != NULL) {
        picoquic_free(quic);
    }
    return ret;
}
