# Xiaomi sm7435 kernel

Kernel source to build **LineageOS on Qualcomm sm7435** (parrot). Developed on
**garnet** (Redmi Note 13 Pro 5G).

**Why this repo exists:** ship a working Lineage kernel for sm7435 phones. The
custom work here is **WireGuard traffic obfuscation** — VPN UDP packets are harder
to detect and block than stock WireGuard, while crypto and the Noise protocol stay
the same. All other code is normal platform support (display, audio, Wi‑Fi, …).

## WireGuard obfuscation

The in-kernel WireGuard driver (`drivers/net/wireguard/`) adds optional **UDP packet obfuscation** so traffic is harder to fingerprint as WireGuard. Everything upstream stays the same — Noise handshakes, session keys, and **ChaCha20-Poly1305** payload encryption (ChaCha20 encrypts the tunneled IP data; Poly1305 verifies it was not tampered with). Only the UDP bytes actually sent on the network are changed; in-kernel structs and crypto are not.

| | Upstream | This repo |
|---|----------|-----------|
| Handshakes, keys, ChaCha20-Poly1305 payloads | unchanged | unchanged |
| UDP packet layout (header + optional handshake padding) | standard | obfuscated when enabled |
| Netlink | standard | + `WGPEER_A_OBFUSCATION`, `WGPEER_A_OBFUSCATION_FORMAT` |

Encode before send, decode after receive — then normal WireGuard processing. Stock WireGuard peers cannot interoperate unless both sides run this driver (client needs userspace that sets the new netlink attr).

### Tests

In-kernel selftests live in `drivers/net/wireguard/selftest/obfuscation.c`
(same pattern as upstream WireGuard selftests). They run once at driver init when
`CONFIG_WIREGUARD_DEBUG=y` is enabled; failure prevents WireGuard from loading.

Coverage:

- Header encode/decode for all message types
- Handshake suffix length (0 and max 32 bytes)
- Send decision (`wg_obf_active_for_send`) — configured vs reactive
- RX format learning, configured override, reset on `wg down`
- UAPI format helper
- Round-trip wrap + parse (initiation, cookie, data packets)

Not covered: live UDP on the network, netlink from userspace, or two-phone
end-to-end — those need a debug kernel build plus manual / VPN testing on device.

---

## Packet format (network)

What leaves the phone on UDP vs standard WireGuard. Inside the kernel, message
structs are unchanged; this is only the encoding of those bytes for transmit.

### Message header (all packet types)

The 32-bit header field is normally `type = MESSAGE_*` (1–4). With obfuscation
enabled, bytes 1–3 carry random junk and byte 0 is XOR-mixed:

```
byte0 = msg_type XOR junk[0] XOR junk[1] XOR junk[2]
byte1 = junk[0]
byte2 = junk[1]
byte3 = junk[2]
```

If any of bytes 1–3 are non-zero, the packet is treated as obfuscated on RX.

### Handshake packets (initiation, response, cookie)

After the normal handshake struct, the sender may append **0–32 bytes** of random
trailing junk (`WG_OBF_SUFFIX_MAX = 32`). Suffix length is derived from the
header junk:

```
suffix_len = (junk[0] ^ junk[1] ^ junk[2]) % 33
```

On RX, suffix is stripped after length validation; the Noise/cookie layers see the
standard struct size.

### Data packets

Only the **4-byte header** is obfuscated. `key_idx` and `counter` stay visible
in the UDP packet (same as standard data packets after the header). Payload
encryption is unchanged.

---

## Configuration (UAPI)

Vendor netlink attributes (see `include/uapi/linux/wireguard.h`):

| Attribute | ID | SET | GET |
|-----------|----|-----|-----|
| `WGPEER_A_OBFUSCATION` | 9 | u8 `0` or `1` | u8 `0` or `1` (only if configured) |
| `WGPEER_A_OBFUSCATION_FORMAT` | 10 | — (read-only) | u8 format enum |

Format values (`wgpeer_obfuscation_format`):

- `WGPEER_OBFUSCATION_FORMAT_STANDARD` (1)
- `WGPEER_OBFUSCATION_FORMAT_OBFUSCATED` (2)

### Client (outbound obfuscation)

Set obfuscation on the server peer:

```
wg set <iface> peer <server_pubkey> obfuscation 1
```

Netlink: include `WGPEER_A_OBFUSCATION = 1`. Use `0` to force standard packets.

Once set, the configured value controls TX regardless of what was learned from
RX.

### Server (reactive mode)

**Omit** `WGPEER_A_OBFUSCATION` on SET for each client peer. The driver learns
the packet format per peer from the first **authenticated** RX packet (handshake
after Noise validation, data after decrypt + replay check).

Each client is independent: one peer may use obfuscation, another standard.

There is no network negotiation; format is inferred from headers or prior
learning.

### Peer state fields (`drivers/net/wireguard/peer.h`)

| Field | Meaning |
|-------|---------|
| `obfuscation_configured` | User set `WGPEER_A_OBFUSCATION` (0/1) |
| `obfuscation_outbound` | Configured TX mode when `obfuscation_configured` |
| `obfuscation_learned` | Reactive RX-learned format when not configured |

TX decision (`wg_obf_active_for_send`):

```
if (obfuscation_configured) → obfuscation_outbound
else                         → obfuscation_learned
```

On `wg down` (`wg_obf_peer_reset_format`):

- **Reactive peers:** `obfuscation_learned` is **kept** across down/up.
- **Configured peers:** `obfuscation_learned` is cleared (outbound/configured
  unchanged).

---

## Source files

| File | Role |
|------|------|
| `drivers/net/wireguard/obfuscation.c`, `obfuscation.h` | Encode/decode, parse, wrap, send decision |
| `drivers/net/wireguard/send.c` | Obfuscate handshake and data headers on TX |
| `drivers/net/wireguard/receive.c` | Parse before dispatch; learn format on RX |
| `drivers/net/wireguard/netlink.c` | Peer GET/SET for obfuscation attributes |
| `drivers/net/wireguard/peer.h` | Peer obfuscation fields |
| `drivers/net/wireguard/device.c` | `wg_obf_peer_reset_format()` on interface stop |
| `include/uapi/linux/wireguard.h` | UAPI attribute definitions |
| `drivers/net/wireguard/selftest/obfuscation.c` | DEBUG selftests |
| `drivers/net/wireguard/Makefile` | Adds `obfuscation.o` |

---

## Limitations and notes

- **Not hidden crypto:** header XOR and trailing junk are reversible; this is
  obfuscation for classification evasion, not secrecy.
- **No stock interop:** upstream WireGuard cannot parse obfuscated packets.
- **Userspace:** driver change is kernel-side only; VPN apps / `wg` must send
  netlink attr 9 for client configuration.
- **Queued packets:** toggling obfuscation may not apply to packets already in
  the encrypt queue until the next batch.
- **Reactive unconfigure:** omitting attr 9 on SET does not revert a peer to
  reactive mode after it was configured; remove and re-add the peer instead.
- **`obf_wire_len`:** stored in `skb` control block for RX byte stats on
  obfuscated handshakes; not required for protocol logic.

---

## Security

Format learning happens only after authentication (Noise handshake or data
decrypt + replay window check). Configured clients are not overwritten by RX
learning. No extra heap allocations in the obfuscation path; skb and peer
lifecycle match upstream WireGuard.

---

# How do I submit patches to Android Common Kernels

1. BEST: Make all of your changes to upstream Linux. If appropriate, backport to the stable releases.
   These patches will be merged automatically in the corresponding common kernels. If the patch is already
   in upstream Linux, post a backport of the patch that conforms to the patch requirements below.
   - Do not send patches upstream that contain only symbol exports. To be considered for upstream Linux,
additions of `EXPORT_SYMBOL_GPL()` require an in-tree modular driver that uses the symbol -- so include
the new driver or changes to an existing driver in the same patchset as the export.
   - When sending patches upstream, the commit message must contain a clear case for why the patch
is needed and beneficial to the community. Enabling out-of-tree drivers or functionality is not
not a persuasive case.

2. LESS GOOD: Develop your patches out-of-tree (from an upstream Linux point-of-view). Unless these are
   fixing an Android-specific bug, these are very unlikely to be accepted unless they have been
   coordinated with kernel-team@android.com. If you want to proceed, post a patch that conforms to the
   patch requirements below.

# Common Kernel patch requirements

- All patches must conform to the Linux kernel coding standards and pass `script/checkpatch.pl`
- Patches shall not break gki_defconfig or allmodconfig builds for arm, arm64, x86, x86_64 architectures
(see  https://source.android.com/setup/build/building-kernels)
- If the patch is not merged from an upstream branch, the subject must be tagged with the type of patch:
`UPSTREAM:`, `BACKPORT:`, `FROMGIT:`, `FROMLIST:`, or `ANDROID:`.
- All patches must have a `Change-Id:` tag (see https://gerrit-review.googlesource.com/Documentation/user-changeid.html)
- If an Android bug has been assigned, there must be a `Bug:` tag.
- All patches must have a `Signed-off-by:` tag by the author and the submitter

Additional requirements are listed below based on patch type

## Requirements for backports from mainline Linux: `UPSTREAM:`, `BACKPORT:`

- If the patch is a cherry-pick from Linux mainline with no changes at all
    - tag the patch subject with `UPSTREAM:`.
    - add upstream commit information with a `(cherry picked from commit ...)` line
    - Example:
        - if the upstream commit message is
```
        important patch from upstream

        This is the detailed description of the important patch

        Signed-off-by: Fred Jones <fred.jones@foo.org>
```
>- then Joe Smith would upload the patch for the common kernel as
```
        UPSTREAM: important patch from upstream

        This is the detailed description of the important patch

        Signed-off-by: Fred Jones <fred.jones@foo.org>

        Bug: 135791357
        Change-Id: I4caaaa566ea080fa148c5e768bb1a0b6f7201c01
        (cherry picked from commit c31e73121f4c1ec41143423ac6ce3ce6dafdcec1)
        Signed-off-by: Joe Smith <joe.smith@foo.org>
```

- If the patch requires any changes from the upstream version, tag the patch with `BACKPORT:`
instead of `UPSTREAM:`.
    - use the same tags as `UPSTREAM:`
    - add comments about the changes under the `(cherry picked from commit ...)` line
    - Example:
```
        BACKPORT: important patch from upstream

        This is the detailed description of the important patch

        Signed-off-by: Fred Jones <fred.jones@foo.org>

        Bug: 135791357
        Change-Id: I4caaaa566ea080fa148c5e768bb1a0b6f7201c01
        (cherry picked from commit c31e73121f4c1ec41143423ac6ce3ce6dafdcec1)
        [joe: Resolved minor conflict in drivers/foo/bar.c ]
        Signed-off-by: Joe Smith <joe.smith@foo.org>
```

## Requirements for other backports: `FROMGIT:`, `FROMLIST:`,

- If the patch has been merged into an upstream maintainer tree, but has not yet
been merged into Linux mainline
    - tag the patch subject with `FROMGIT:`
    - add info on where the patch came from as `(cherry picked from commit <sha1> <repo> <branch>)`. This
must be a stable maintainer branch (not rebased, so don't use `linux-next` for example).
    - if changes were required, use `BACKPORT: FROMGIT:`
    - Example:
        - if the commit message in the maintainer tree is
```
        important patch from upstream

        This is the detailed description of the important patch

        Signed-off-by: Fred Jones <fred.jones@foo.org>
```
>- then Joe Smith would upload the patch for the common kernel as
```
        FROMGIT: important patch from upstream

        This is the detailed description of the important patch

        Signed-off-by: Fred Jones <fred.jones@foo.org>

        Bug: 135791357
        (cherry picked from commit 878a2fd9de10b03d11d2f622250285c7e63deace
         https://git.kernel.org/pub/scm/linux/kernel/git/foo/bar.git test-branch)
        Change-Id: I4caaaa566ea080fa148c5e768bb1a0b6f7201c01
        Signed-off-by: Joe Smith <joe.smith@foo.org>
```


- If the patch has been submitted to LKML, but not accepted into any maintainer tree
    - tag the patch subject with `FROMLIST:`
    - add a `Link:` tag with a link to the submittal on lore.kernel.org
    - add a `Bug:` tag with the Android bug (required for patches not accepted into
a maintainer tree)
    - if changes were required, use `BACKPORT: FROMLIST:`
    - Example:
```
        FROMLIST: important patch from upstream

        This is the detailed description of the important patch

        Signed-off-by: Fred Jones <fred.jones@foo.org>

        Bug: 135791357
        Link: https://lore.kernel.org/lkml/20190619171517.GA17557@someone.com/
        Change-Id: I4caaaa566ea080fa148c5e768bb1a0b6f7201c01
        Signed-off-by: Joe Smith <joe.smith@foo.org>
```

## Requirements for Android-specific patches: `ANDROID:`

- If the patch is fixing a bug to Android-specific code
    - tag the patch subject with `ANDROID:`
    - add a `Fixes:` tag that cites the patch with the bug
    - Example:
```
        ANDROID: fix android-specific bug in foobar.c

        This is the detailed description of the important fix

        Fixes: 1234abcd2468 ("foobar: add cool feature")
        Change-Id: I4caaaa566ea080fa148c5e768bb1a0b6f7201c01
        Signed-off-by: Joe Smith <joe.smith@foo.org>
```

- If the patch is a new feature
    - tag the patch subject with `ANDROID:`
    - add a `Bug:` tag with the Android bug (required for android-specific features)
