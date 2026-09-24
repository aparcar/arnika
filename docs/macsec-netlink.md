# macsec-netlink

**Key writer module - installs the key into a local [MACsec](https://en.wikipedia.org/wiki/IEEE_802.1AE) (IEEE 802.1AE) interface through the kernel's generic netlink and rtnetlink APIs.**

This is the single document for the `macsec-netlink` module. For the generic architecture all key reader and key writer modules follow, see [`KEYCONTROL.md`](../KEYCONTROL.md).

---

## At a Glance

| | |
|---|---|
| **Module name** | `macsec-netlink` |
| **Kind** | Key writer (sink) |
| **Build tag** | `macsec_netlink` |
| **Adapter** | [`repositories/macsec-netlink.go`](../repositories/macsec-netlink.go) |
| **Tests** | [`repositories/macsec-netlink_test.go`](../repositories/macsec-netlink_test.go) (encoding, AN choice, XPN parameters), integration test in [`ci/macsec/`](../ci/macsec/) for both cipher suites, live demo [`ci/macsec/demo.sh`](../ci/macsec/demo.sh) |
| **Wiring** | [`macsecnetlink.go`](../macsecnetlink.go) |
| **Target** | A **local** MACsec interface |
| **Transport** | Generic netlink family `macsec` (SAs), rtnetlink `RTM_GETLINK` (SCI, cipher suite, encoding SA) and `RTM_NEWLINK` (switch the encoding SA) |
| **Dependencies** | `github.com/mdlayher/genetlink`, `github.com/mdlayher/netlink` |
| **Privileges** | `CAP_NET_ADMIN` |
| **Platform** | Linux only (kernel 4.6+; 5.7+ for GCM-AES-XPN-256) |

---

## How the Module Works

MACsec provides hop-by-hop Layer 2 encryption. The 32-byte PSK becomes the key of a Secure Association (SA); the SA key ID is the first 16 bytes of its SHA-256, so both peers derive the same ID without exchanging it.

**Cipher suite:** the adapter uses whatever suite the interface was created with, read from the kernel on every call:

| Suite | Packet number | Use |
|---|---|---|
| `gcm-aes-256` | 32 bit | Links up to roughly 10 Gbit/s |
| `gcm-aes-xpn-256` | 64 bit (XPN) | High-speed links: a 32-bit packet number runs out within seconds to minutes at 100–400 Gbit/s |

The 128-bit suites are rejected, since Arnika installs 256-bit keys. XPN SAs also need a salt and a short SCI (SSCI), which both peers must agree on. The salt is derived from the key (SHA-256 with a fixed label, first 12 bytes); it is not secret, and MKA also derives it from public values. SSCIs follow MKA's rule: numbered from 1 in ascending SCI order, so the peer with the lower SCI transmits as SSCI 1.

**Association number:** the AN of a new key is derived from the key, and skips the AN the interface currently encrypts with (read from the kernel). Both peers therefore put the same key under the same AN without keeping a counter, and fall back into step by themselves after a failed install or a restart. Each install keeps the current SA for frames still in flight, removes every other SA, and adds the new key as TX and RX SA. Between rotations two SAs exist per direction: the current one and the previous one.

**Deferred TX switch:** each new SA is installed for TX and RX at once, but the interface only starts encrypting with it one second later. Both peers install a key within milliseconds of each other, so by then the receiver already has the SA; switching immediately would drop the frames sent in that gap (`InPktsNotUsingSA`). If the next key arrives while a switch is still pending, that switch is applied first. The one-second margin does not cover a peer whose KMS lookup takes longer or fails; that needs a confirmation from the peer before switching, which the peer protocol does not provide yet.

**Invalidation:** `InvalidateTunnel` removes every TX and RX SA instead of installing a random key. Without a TX SA the interface drops outgoing frames, and without RX SAs it drops everything the peer sends, so both directions are cut at once. A random key would only cut the sending direction, because the RX SAs of the current key would keep accepting the peer's frames.

The RX Secure Channel (SC) for the peer is created on the first key injection if it does not exist yet. The interface, its settings and the netlink family are resolved on every call, and no rotation state is kept in memory.

---

## Part 1 — Prepare the Host

The MACsec interface must exist before Arnika starts, and must use `cipher gcm-aes-256` or `cipher gcm-aes-xpn-256`: the kernel rejects a 32-byte key on the default GCM-AES-128 SecY. Both peers must use the same suite.

```bash
ip link add link eth0 macsec0 type macsec sci 001122334455ffff cipher gcm-aes-256 encrypt on
# or, for high-speed links:
# ip link add link eth0 macsec0 type macsec sci 001122334455ffff cipher gcm-aes-xpn-256 encrypt on
ip link set macsec0 up
ip addr add 10.0.0.1/24 dev macsec0
```

---

## Part 2 — Configuration Reference

MACsec has no WireGuard peer, so `WIREGUARD_INTERFACE` and `WIREGUARD_PEER_PUBLIC_KEY` are not used.

| Env var | Required | Description |
|---|:---:|---|
| `MACSEC_INTERFACE` | yes | Name of the MACsec interface, e.g. `macsec0` |
| `MACSEC_RX_SCI` | yes | Secure Channel Identifier of the **remote** peer's transmit SC — 16 hex characters (8 bytes), typically its MAC address followed by the port number |

---

## Part 3 — Compile

```bash
GOEXPERIMENT=runtimesecret go build -tags macsec_netlink .
```

Via the Makefile:
```bash
make build BUILD_TAGS=macsec_netlink
```

---

## Part 4 — Run

```bash
MACSEC_INTERFACE=macsec0 \
MACSEC_RX_SCI=aabbccddeeff0001 \
arnika
```

---

## References

- Module architecture: [`KEYCONTROL.md`](../KEYCONTROL.md)
- Kernel UAPI: `include/uapi/linux/if_macsec.h`, `include/uapi/linux/if_link.h`
- `ip-macsec(8)`
