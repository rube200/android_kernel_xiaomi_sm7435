/* SPDX-License-Identifier: GPL-2.0 */
/*
 * WireGuard traffic obfuscation: random junk in reserved header bytes,
 * XOR-transformed message type, and optional trailing junk on handshakes.
 *
 * WGPEER_A_OBFUSCATION: if set, 0 or 1 forces outbound wire format; if omitted,
 * the peer stays in reactive mode (match remote from RX). New peers default to
 * reactive.
 */

#ifndef _WG_OBFUSCATION_H
#define _WG_OBFUSCATION_H

#include "messages.h"

#include <linux/skbuff.h>
#include <linux/types.h>

struct wg_peer;

/* Fixed trailing junk range on handshakes: 0..WG_OBF_SUFFIX_MAX bytes. */
#define WG_OBF_SUFFIX_MAX 32

void wg_obf_encode_header(struct message_header *hdr, u8 msg_type,
			  const u8 junk[3]);
bool wg_obf_decode_header(const struct message_header *hdr, u8 *msg_type,
			  u8 junk[3]);

u8 wg_obf_suffix_len(const u8 junk[3]);

bool wg_obf_header_looks_obfuscated(const struct message_header *hdr);
bool wg_obf_active_for_send(const struct wg_peer *peer);

void wg_obf_peer_note_rx_format(struct wg_peer *peer, bool obfuscated);
void wg_obf_peer_reset_format(struct wg_peer *peer);

u8 wg_obf_peer_uapi_format(const struct wg_peer *peer);

u8 wg_obf_parse_message(struct sk_buff *skb);

size_t wg_obf_wrap_handshake(void *dst, size_t dst_cap, const void *src,
			     size_t src_len, u8 msg_type);

void wg_obf_obfuscate_header_inplace(void *message, u8 msg_type,
				     u8 junk_out[3]);

#ifdef DEBUG
bool wg_obfuscation_selftest(void);
#endif

#endif /* _WG_OBFUSCATION_H */
