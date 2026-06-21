// SPDX-License-Identifier: GPL-2.0

#ifdef DEBUG
static struct sk_buff *obf_test_skb(const void *data, size_t len)
{
	struct sk_buff *skb;

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return NULL;
	skb_put_data(skb, data, len);
	return skb;
}

bool __init wg_obfuscation_selftest(void)
{
	struct message_header hdr;
	struct wg_peer peer = {
		.obfuscation_outbound = false,
		.obfuscation_configured = false,
		.obfuscation_learned = false,
	};
	u8 msg_type, junk[3], parsed;
	u8 wire[sizeof(struct message_handshake_initiation) + WG_OBF_SUFFIX_MAX];
	u8 data_wire[MESSAGE_MINIMUM_LENGTH];
	struct message_handshake_initiation packet;
	struct message_handshake_cookie cookie;
	struct message_data data_pkt;
	struct sk_buff *skb;
	size_t len;
	unsigned int i;
	bool success = true;

	for (i = MESSAGE_HANDSHAKE_INITIATION; i <= MESSAGE_DATA; ++i) {
		junk[0] = 0x11;
		junk[1] = 0x22;
		junk[2] = 0x33;
		wg_obf_encode_header(&hdr, i, junk);
		if (!wg_obf_decode_header(&hdr, &msg_type, junk) ||
		    msg_type != i) {
			pr_err("obfuscation self-test decode header %u: FAIL\n", i);
			success = false;
		}
	}

	junk[0] = junk[1] = junk[2] = 0;
	if (wg_obf_suffix_len(junk) != 0) {
		pr_err("obfuscation self-test suffix min: FAIL\n");
		success = false;
	}
	junk[0] = 0x20;
	junk[1] = junk[2] = 0;
	if (wg_obf_suffix_len(junk) != WG_OBF_SUFFIX_MAX) {
		pr_err("obfuscation self-test suffix max: FAIL\n");
		success = false;
	}

	if (wg_obf_active_for_send(NULL)) {
		pr_err("obfuscation self-test active with null peer: FAIL\n");
		success = false;
	}
	if (wg_obf_active_for_send(&peer)) {
		pr_err("obfuscation self-test active when unset: FAIL\n");
		success = false;
	}
	peer.obfuscation_configured = true;
	peer.obfuscation_outbound = true;
	if (!wg_obf_active_for_send(&peer)) {
		pr_err("obfuscation self-test outbound enabled: FAIL\n");
		success = false;
	}
	peer.obfuscation_learned = true;
	if (!wg_obf_active_for_send(&peer)) {
		pr_err("obfuscation self-test configured ignores learned: FAIL\n");
		success = false;
	}
	peer.obfuscation_outbound = false;
	if (wg_obf_active_for_send(&peer)) {
		pr_err("obfuscation self-test configured disable: FAIL\n");
		success = false;
	}
	peer.obfuscation_configured = false;
	peer.obfuscation_outbound = false;
	peer.obfuscation_learned = true;
	if (!wg_obf_active_for_send(&peer)) {
		pr_err("obfuscation self-test reactive obfuscated: FAIL\n");
		success = false;
	}
	peer.obfuscation_learned = false;
	if (wg_obf_active_for_send(&peer)) {
		pr_err("obfuscation self-test reactive standard: FAIL\n");
		success = false;
	}
	wg_obf_peer_note_rx_format(&peer, true);
	if (!peer.obfuscation_learned) {
		pr_err("obfuscation self-test note rx format: FAIL\n");
		success = false;
	}
	peer.obfuscation_configured = true;
	wg_obf_peer_note_rx_format(&peer, false);
	if (!peer.obfuscation_learned) {
		pr_err("obfuscation self-test configured ignores rx note: FAIL\n");
		success = false;
	}
	peer.obfuscation_configured = false;
	if (!wg_obf_active_for_send(&peer)) {
		pr_err("obfuscation self-test noted obfuscated send: FAIL\n");
		success = false;
	}
	wg_obf_peer_note_rx_format(&peer, false);
	if (peer.obfuscation_learned) {
		pr_err("obfuscation self-test note rx standard: FAIL\n");
		success = false;
	}
	if (wg_obf_active_for_send(&peer)) {
		pr_err("obfuscation self-test noted standard send: FAIL\n");
		success = false;
	}
	peer.obfuscation_learned = true;
	wg_obf_peer_reset_format(&peer);
	if (!peer.obfuscation_learned) {
		pr_err("obfuscation self-test reset preserves reactive learned: FAIL\n");
		success = false;
	}
	peer.obfuscation_configured = true;
	peer.obfuscation_learned = true;
	wg_obf_peer_reset_format(&peer);
	if (peer.obfuscation_learned) {
		pr_err("obfuscation self-test reset clears configured learned: FAIL\n");
		success = false;
	}
	peer.obfuscation_outbound = true;
	if (!wg_obf_active_for_send(&peer)) {
		pr_err("obfuscation self-test outbound after reset: FAIL\n");
		success = false;
	}
	peer.obfuscation_configured = false;
	peer.obfuscation_outbound = false;

	if (wg_obf_peer_uapi_format(&peer) != WGPEER_OBFUSCATION_FORMAT_STANDARD) {
		pr_err("obfuscation self-test uapi initial standard: FAIL\n");
		success = false;
	}
	peer.obfuscation_configured = true;
	peer.obfuscation_outbound = true;
	if (wg_obf_peer_uapi_format(&peer) != WGPEER_OBFUSCATION_FORMAT_OBFUSCATED) {
		pr_err("obfuscation self-test uapi configured outbound: FAIL\n");
		success = false;
	}
	peer.obfuscation_configured = false;
	wg_obf_peer_note_rx_format(&peer, true);
	if (wg_obf_peer_uapi_format(&peer) != WGPEER_OBFUSCATION_FORMAT_OBFUSCATED) {
		pr_err("obfuscation self-test uapi obfuscated: FAIL\n");
		success = false;
	}
	wg_obf_peer_note_rx_format(&peer, false);
	if (wg_obf_peer_uapi_format(&peer) != WGPEER_OBFUSCATION_FORMAT_STANDARD) {
		pr_err("obfuscation self-test uapi standard: FAIL\n");
		success = false;
	}
	wg_obf_peer_reset_format(&peer);
	if (wg_obf_peer_uapi_format(&peer) != WGPEER_OBFUSCATION_FORMAT_STANDARD) {
		pr_err("obfuscation self-test uapi after reactive reset: FAIL\n");
		success = false;
	}

	memset(&packet, 0, sizeof(packet));
	packet.header.type = cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION);
	len = wg_obf_wrap_handshake(wire, sizeof(wire), &packet, sizeof(packet),
				    MESSAGE_HANDSHAKE_INITIATION);
	if (!len || len < sizeof(packet)) {
		pr_err("obfuscation self-test wrap initiation: FAIL\n");
		success = false;
	} else {
		skb = obf_test_skb(wire, len);
		if (!skb) {
			pr_err("obfuscation self-test skb alloc initiation: FAIL\n");
			return false;
		}
		parsed = wg_obf_parse_message(skb);
		if (parsed != MESSAGE_HANDSHAKE_INITIATION ||
		    skb->len != sizeof(packet) ||
		    !PACKET_CB(skb)->obf_learned) {
			pr_err("obfuscation self-test parse initiation: FAIL\n");
			success = false;
		}
		consume_skb(skb);
	}

	skb = obf_test_skb(&packet, sizeof(packet));
	if (!skb) {
		pr_err("obfuscation self-test skb alloc standard: FAIL\n");
		return false;
	}
	parsed = wg_obf_parse_message(skb);
	if (parsed != MESSAGE_HANDSHAKE_INITIATION ||
	    PACKET_CB(skb)->obf_learned) {
		pr_err("obfuscation self-test parse standard initiation: FAIL\n");
		success = false;
	}
	consume_skb(skb);

	memset(&cookie, 0, sizeof(cookie));
	cookie.header.type = cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE);
	len = wg_obf_wrap_handshake(wire, sizeof(wire), &cookie, sizeof(cookie),
				    MESSAGE_HANDSHAKE_COOKIE);
	if (!len || len < sizeof(cookie)) {
		pr_err("obfuscation self-test wrap cookie: FAIL\n");
		success = false;
	} else {
		skb = obf_test_skb(wire, len);
		if (!skb) {
			pr_err("obfuscation self-test skb alloc cookie: FAIL\n");
			return false;
		}
		parsed = wg_obf_parse_message(skb);
		if (parsed != MESSAGE_HANDSHAKE_COOKIE ||
		    skb->len != sizeof(cookie) ||
		    !PACKET_CB(skb)->obf_learned) {
			pr_err("obfuscation self-test parse cookie: FAIL\n");
			success = false;
		}
		consume_skb(skb);
	}

	memset(&data_pkt, 0, sizeof(data_pkt));
	data_pkt.header.type = cpu_to_le32(MESSAGE_DATA);
	wg_obf_obfuscate_header_inplace(&data_pkt, MESSAGE_DATA, junk);
	memset(data_wire, 0, sizeof(data_wire));
	memcpy(data_wire, &data_pkt, sizeof(data_pkt));
	skb = obf_test_skb(data_wire, sizeof(data_wire));
	if (!skb) {
		pr_err("obfuscation self-test skb alloc data: FAIL\n");
		return false;
	}
	parsed = wg_obf_parse_message(skb);
	if (parsed != MESSAGE_DATA || skb->len != sizeof(data_wire) ||
	    !PACKET_CB(skb)->obf_learned ||
	    le32_to_cpu(((struct message_data *)skb->data)->header.type) !=
		    MESSAGE_DATA) {
		pr_err("obfuscation self-test parse data: FAIL\n");
		success = false;
	}
	consume_skb(skb);

	if (success)
		pr_info("obfuscation self-tests: pass\n");
	return success;
}
#endif
