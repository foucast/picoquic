# Multicast QUIC (QUICast, draft-08 DATAGRAM channels)

This branch adds a multicast QUIC receiver and sender to picoquic, following
[draft-jholland-quic-multicast-08](https://datatracker.ietf.org/doc/draft-jholland-quic-multicast/08/)
as implemented by QUICast quiche. A server announces a multicast channel over an
ordinary unicast QUIC connection (MC_ANNOUNCE, MC_KEY, MC_JOIN). It then sends
channel packets to a source-specific group (S,G), and sends their integrity
hashes over the unicast connection (MC_INTEGRITY). A client joins the channel and
releases a channel packet only once its hash matches. Its DATAGRAM frames are
then delivered to the application, and the client acknowledges them with MC_ACK.

The wire format is draft-08's, exactly as QUICast quiche implements it, because
interoperability is the goal. The experimental code points (0xff3e800 and up)
are shared with draft-09. Where draft-09 changes the wire format, the change is
noted in the code (`picoquic/mcquic.c`, `picoquic/mcquic.h`).

**Interop:** tested against QUICast quiche `main`, with its tokio-quiche examples
`async_multicast_file_server` and `async_multicast_file_client`, in both
directions:
- the picoquic client receives from the quiche server;
- the quiche client receives from the picoquic server.

## What is here

| File | What |
|---|---|
| `picoquic/mcquic.c`, `mcquic.h` | Transport parameters, MC_* frame codecs, channel key derivation, header protection and AEAD, the integrity check and batching, MC_ACK ranges, receiver and sender state |
| `picoquic/mcquic_loop.c`, `mcquic_loop.h` | Optional: picoquic's packet loop opens, joins and polls the channel sockets and sends channel packets (POSIX poll/select loops) |
| `mcquic_client/` | Example client: receives a file over a channel and prints its SHA-256 |
| `mcquic_server/` | Example server: sends a file over a channel, looping, with the quiche example's constants |
| `picoquictest/mcquic_test.c` | Known-answer tests for keys, header protection, decryption, integrity hashes, transport parameters, frames and encoding, plus a receive test |

Small hooks connect it to existing code: transport parameters (`transport.c`),
the control frames (`frames.c`), the context (`quicctx.c`,
`picoquic_internal.h`) and the packet loop (`sockloop.c`).

## Build

As usual for picoquic (see `building_picoquic.md`). The examples build with
the demo programs on non-Windows systems:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
build/picoquic_ct mcquic_kat_keys mcquic_kat_header mcquic_kat_decrypt mcquic_kat_integrity \
    mcquic_kat_tp mcquic_kat_frames mcquic_kat_encode mcquic_kat_hash_ids mcquic_receive
```

## Run the examples

The server listens for unicast QUIC on `-a`, and by default uses that address
as the channel source and the sending interface. The channel is
232.1.2.3:4444. The client joins the channel on the interface whose address
you give it with `-i`. The test certificate in `certs/` is enough, because the
client doesn't verify certificates.

**One host** (multicast loopback is on, so the host receives its own channel).
Use the address of an interface that has multicast enabled; `ADDR` below. To
keep the channel off the network, use `lo` in a network namespace:
`unshare -n`, then `ip link set lo up multicast on`,
`ip route add 224.0.0.0/4 dev lo`, and `ADDR=127.0.0.1`.

```sh
build/mcquic_server -a ADDR -c certs/cert.pem -k certs/key.pem -f somefile 4433 &
build/mcquic_client -i ADDR -o received ADDR 4433
sha256sum somefile received
```

**Two hosts on one LAN** (the channel TTL is 1). `SERVER` and `CLIENT` are each
host's address on the shared LAN:

```sh
# on the server host
build/mcquic_server -a SERVER -c certs/cert.pem -k certs/key.pem -f somefile 4433
# on the client host
build/mcquic_client -i CLIENT -o received SERVER 4433
```

Both programs print statistics every 5 s:
- the server: packets published, MC_INTEGRITY frames, MC_ACKs;
- the client: packets received and released, integrity and decryption failures,
  and the release delay.

Other options:
- `mcquic_server -H n -T ms` batches up to `n` hashes per MC_INTEGRITY frame,
  holding a hash at most `ms`.
- `-A id` selects the integrity hash algorithm (draft-08 ids 1–8).
- Run either program without arguments for its full usage.

## Using it from an application

See the comments in `picoquic/mcquic.h`.

**Client:**
1. Call `picoquic_mcquic_enable_client()` on the connection before it starts.
2. Either call `picoquic_mcquic_loop_config()` so that the packet loop handles
   the channel sockets, or open them yourself on `picoquic_callback_mc_join`
   and pass packets to `picoquic_incoming_multicast_packet()`.
3. Channel datagrams arrive as `picoquic_callback_mc_datagram`.

**Server:**
1. Call `picoquic_mcquic_sender_create()` on the context.
2. Call `picoquic_mcquic_server_start()` on each connection that is ready.
3. Call `picoquic_mcquic_sender_publish()` for each datagram.

## Known limits

- DATAGRAM channels only: no STREAM channels.
- One channel per server and one static key: no key rotation.
- IPv4 only.
- MC_ACKs are counted and logged. There is no retransmission or recovery over
  the channel.
- Loop-owned sockets work with the POSIX poll and select loops, not with
  io_uring or on Windows.
- The draft-08 wire format only. draft-09 is not implemented.

## License and credit

MIT, the same as picoquic (see `LICENSE`).

Written with Claude (Anthropic), under my direction.
