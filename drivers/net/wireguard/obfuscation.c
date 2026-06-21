// SPDX-License-Identifier: GPL-2.0
/*
 * WireGuard traffic obfuscation.
 */

#include "obfuscation.h"
#include "peer.h"
#include "queueing.h"

#include <linux/random.h>
#include <linux/skbuff.h>
#include <uapi/linux/wireguard.h>

static u8 obf_xor_mask(const u8 junk[3])
{
	return junk[0] ^ junk[1] ^ junk[2];
}

static size_t obf_handshake_base_len(u8 msg_type)
{
	switch (msg_type) {
	case MESSAGE_HANDSHAKE_INITIATION:
		return sizeof(struct message_handshake_initiation);
	case MESSAGE_HANDSHAKE_RESPONSE:
		return sizeof(struct message_handshake_response);
	case MESSAGE_HANDSHAKE_COOKIE:
		return sizeof(struct message_handshake_cookie);
	default:
		return 0;
	}
}

void wg_obf_encode_header(struct message_header *hdr, u8 msg_type,
			  const u8 junk[3])
{
	u32 wire = msg_type ^ obf_xor_mask(junk);

	wire |= (u32)junk[0] << 8;
	wire |= (u32)junk[1] << 16;
	wire |= (u32)junk[2] << 24;
	hdr->type = cpu_to_le32(wire);
}

bool wg_obf_decode_header(const struct message_header *hdr, u8 *msg_type,
			  u8 junk[3])
{
	u32 wire = le32_to_cpu(hdr->type);

	junk[0] = (wire >> 8) & 0xff;
	junk[1] = (wire >> 16) & 0xff;
	junk[2] = (wire >> 24) & 0xff;
	*msg_type = (wire & 0xff) ^ obf_xor_mask(junk);
	return *msg_type >= MESSAGE_HANDSHAKE_INITIATION &&
	       *msg_type <= MESSAGE_DATA;
}

u8 wg_obf_suffix_len(const u8 junk[3])
{
	return obf_xor_mask(junk) % (WG_OBF_SUFFIX_MAX + 1);
}

bool wg_obf_header_looks_obfuscated(const struct message_header *hdr)
{
	return !!(le32_to_cpu(hdr->type) & ~0xffU);
}

bool wg_obf_active_for_send(const struct wg_peer *peer)
{
	if (!peer)
		return false;
	if (READ_ONCE(peer->obfuscation_configured))
		return READ_ONCE(peer->obfuscation_outbound);
	return READ_ONCE(peer->obfuscation_learned);
}

void wg_obf_peer_note_rx_format(struct wg_peer *peer, bool obfuscated)
{
	if (READ_ONCE(peer->obfuscation_configured))
		return;
	WRITE_ONCE(peer->obfuscation_learned, obfuscated);
}

void wg_obf_peer_reset_format(struct wg_peer *peer)
{
	if (!READ_ONCE(peer->obfuscation_configured))
		return;
	WRITE_ONCE(peer->obfuscation_learned, false);
}

u8 wg_obf_peer_uapi_format(const struct wg_peer *peer)
{
	if (READ_ONCE(peer->obfuscation_configured))
		return READ_ONCE(peer->obfuscation_outbound) ?
			WGPEER_OBFUSCATION_FORMAT_OBFUSCATED :
			WGPEER_OBFUSCATION_FORMAT_STANDARD;
	if (READ_ONCE(peer->obfuscation_learned))
		return WGPEER_OBFUSCATION_FORMAT_OBFUSCATED;
	return WGPEER_OBFUSCATION_FORMAT_STANDARD;
}

void wg_obf_obfuscate_header_inplace(void *message, u8 msg_type,
				     u8 junk_out[3])
{
	struct message_header *hdr = message;

	wait_for_random_bytes();
	get_random_bytes(junk_out, 3);
	wg_obf_encode_header(hdr, msg_type, junk_out);
}

size_t wg_obf_wrap_handshake(void *dst, size_t dst_cap, const void *src,
			     size_t src_len, u8 msg_type)
{
	u8 junk[3];
	size_t suffix_len, total;

	if (unlikely(src_len > dst_cap))
		return 0;

	memcpy(dst, src, src_len);
	wg_obf_obfuscate_header_inplace(dst, msg_type, junk);
	suffix_len = wg_obf_suffix_len(junk);
	total = src_len + suffix_len;
	if (unlikely(total > dst_cap))
		return 0;
	if (suffix_len) {
		wait_for_random_bytes();
		get_random_bytes((u8 *)dst + src_len, suffix_len);
	}
	return total;
}

static bool obf_handshake_len_valid(u8 msg_type, size_t len, const u8 junk[3],
				    size_t *base_len)
{
	size_t base = obf_handshake_base_len(msg_type);
	size_t suffix_len;

	if (!base)
		return false;
	suffix_len = wg_obf_suffix_len(junk);
	if (len != base + suffix_len)
		return false;
	*base_len = base;
	return true;
}

static bool obf_standard_message_valid(struct sk_buff *skb, u8 msg_type)
{
	/* Same checks as upstream validate_header_len() for standard wire. */
	switch (msg_type) {
	case MESSAGE_DATA:
		return skb->len >= MESSAGE_MINIMUM_LENGTH;
	case MESSAGE_HANDSHAKE_INITIATION:
		return skb->len == sizeof(struct message_handshake_initiation);
	case MESSAGE_HANDSHAKE_RESPONSE:
		return skb->len == sizeof(struct message_handshake_response);
	case MESSAGE_HANDSHAKE_COOKIE:
		return skb->len == sizeof(struct message_handshake_cookie);
	default:
		return false;
	}
}

u8 wg_obf_parse_message(struct sk_buff *skb)
{
	struct message_header *hdr = (struct message_header *)skb->data;
	u8 msg_type, junk[3];
	size_t base_len;

	/* Replaces upstream validate_header_len(); supports obfuscated wire too. */
	if (unlikely(skb->len < sizeof(*hdr)))
		return 0;

	PACKET_CB(skb)->obf_learned = false;
	PACKET_CB(skb)->obf_wire_len = 0;

	if (!wg_obf_decode_header(hdr, &msg_type, junk))
		return 0;

	if (!wg_obf_header_looks_obfuscated(hdr)) {
		if (!obf_standard_message_valid(skb, msg_type))
			return 0;
		return msg_type;
	}

	PACKET_CB(skb)->obf_wire_len = skb->len;

	if (msg_type == MESSAGE_DATA) {
		if (skb->len < MESSAGE_MINIMUM_LENGTH)
			return 0;
		PACKET_CB(skb)->obf_learned = true;
		hdr->type = cpu_to_le32(msg_type);
		return msg_type;
	}

	if (!obf_handshake_len_valid(msg_type, skb->len, junk, &base_len))
		return 0;

	PACKET_CB(skb)->obf_learned = true;

	if (pskb_trim(skb, base_len))
		return 0;

	hdr->type = cpu_to_le32(msg_type);
	return msg_type;
}

#include "selftest/obfuscation.c"
