//go:build linux

// Platform constraint only: matches the adapter in macsec-netlink.go.

package repositories

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestNewMacsecNetlinkRepositoryValidatesArgs(t *testing.T) {
	if _, err := NewMacsecNetlinkRepository("", "001122334455ffff"); err == nil {
		t.Error("expected an error for an empty interface name")
	}
	for _, sci := range []string{"", "0011", "001122334455fffg", "001122334455ffff00"} {
		if _, err := NewMacsecNetlinkRepository("macsec0", sci); err == nil {
			t.Errorf("expected an error for RX SCI %q", sci)
		}
	}
	repo, err := NewMacsecNetlinkRepository("macsec0", "001122334455ffff")
	if err != nil {
		t.Fatal(err)
	}
	if repo.rxSCI != 0x001122334455ffff {
		t.Errorf("rxSCI = %#x, want 0x001122334455ffff", repo.rxSCI)
	}
}

func TestMacsecNetlinkRejectsBadPSK(t *testing.T) {
	repo, err := NewMacsecNetlinkRepository("macsec0", "001122334455ffff")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SetPSK("not base64!"); err == nil {
		t.Error("expected an error for a PSK that is not base64")
	}
	if err := repo.SetPSK("AAAA"); err == nil {
		t.Error("expected an error for a PSK that is not 32 bytes")
	}
}

// TestMacsecChooseAN checks that the AN for a key never collides with the AN
// in use, is the same on both peers, and spreads over all four ANs.
func TestMacsecChooseAN(t *testing.T) {
	seen := map[uint8]bool{}
	for i := 0; i < 64; i++ {
		key := bytes.Repeat([]byte{byte(i)}, 32)
		for current := uint8(0); current < macsecNumAN; current++ {
			an := macsecChooseAN(key, current)
			if an == current || an >= macsecNumAN {
				t.Fatalf("key %d, current %d: chose AN %d", i, current, an)
			}
			if again := macsecChooseAN(append([]byte(nil), key...), current); again != an {
				t.Fatalf("key %d, current %d: not deterministic (%d, then %d)", i, current, an, again)
			}
			seen[an] = true
		}
	}
	if len(seen) != macsecNumAN {
		t.Errorf("only ANs %v were ever chosen", seen)
	}
}

// TestMacsecSAParams checks cipher handling and that both peers derive
// matching XPN parameters: the same salt, and mirrored SSCIs.
func TestMacsecSAParams(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	const sciA, sciB = 0x001122334455_0001, 0x66778899aabb_0001

	for _, cipher := range []uint64{macsecCipherGCMAES128, macsecCipherGCMAESXPN128, 0x1234} {
		if _, err := newMacsecSAParams(key, macsecLink{sci: sciA, cipher: cipher}, sciB); err == nil {
			t.Errorf("cipher %#x: expected an error", cipher)
		}
	}

	p, err := newMacsecSAParams(key, macsecLink{sci: sciA, cipher: macsecCipherGCMAES256}, sciB)
	if err != nil {
		t.Fatal(err)
	}
	if p.xpn || p.salt != nil {
		t.Error("GCM-AES-256 must not use XPN parameters")
	}

	a, err := newMacsecSAParams(key, macsecLink{sci: sciA, cipher: macsecCipherGCMAESXPN256}, sciB)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newMacsecSAParams(key, macsecLink{sci: sciB, cipher: macsecCipherGCMAESXPN256}, sciA)
	if err != nil {
		t.Fatal(err)
	}
	if !a.xpn || len(a.salt) != macsecSaltLen || !bytes.Equal(a.salt, b.salt) {
		t.Errorf("salts differ or have the wrong length: %x / %x", a.salt, b.salt)
	}
	if a.txSSCI != 1 || a.rxSSCI != 2 || b.txSSCI != 2 || b.rxSSCI != 1 {
		t.Errorf("SSCIs not mirrored: A tx=%d rx=%d, B tx=%d rx=%d", a.txSSCI, a.rxSSCI, b.txSSCI, b.rxSSCI)
	}
	if !bytes.Equal(a.keyID, b.keyID) {
		t.Error("key IDs differ between peers")
	}
	if _, err := newMacsecSAParams(key, macsecLink{sci: sciA, cipher: macsecCipherGCMAESXPN256}, sciA); err == nil {
		t.Error("expected an error when own SCI equals the RX SCI")
	}
}

// TestMacsecSAConfigEncoding checks what the kernel validates: a 4-byte PN
// without XPN, and an 8-byte PN plus SSCI and 12-byte salt with XPN.
func TestMacsecSAConfigEncoding(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	decode := func(p *macsecSAParams, ssci uint32) map[uint16][]byte {
		t.Helper()
		ae := netlink.NewAttributeEncoder()
		ae.Nested(macsecAttrSaConfig, encodeMacsecSAConfig(2, p, ssci))
		b, err := ae.Encode()
		if err != nil {
			t.Fatal(err)
		}
		got := map[uint16][]byte{}
		ad, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			t.Fatal(err)
		}
		for ad.Next() {
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					got[nad.Type()] = append([]byte(nil), nad.Bytes()...)
				}
				return nil
			})
		}
		if err := ad.Err(); err != nil {
			t.Fatal(err)
		}
		return got
	}

	plain, err := newMacsecSAParams(key, macsecLink{sci: 1, cipher: macsecCipherGCMAES256}, 2)
	if err != nil {
		t.Fatal(err)
	}
	got := decode(plain, 0)
	if len(got[macsecSaAttrPn]) != 4 {
		t.Errorf("GCM-AES-256 PN length = %d, want 4", len(got[macsecSaAttrPn]))
	}
	if _, ok := got[macsecSaAttrSsci]; ok {
		t.Error("GCM-AES-256 SA must not carry an SSCI")
	}
	if !bytes.Equal(got[macsecSaAttrKey], key) || got[macsecSaAttrAn][0] != 2 {
		t.Error("key or AN not encoded")
	}

	xpn, err := newMacsecSAParams(key, macsecLink{sci: 1, cipher: macsecCipherGCMAESXPN256}, 2)
	if err != nil {
		t.Fatal(err)
	}
	got = decode(xpn, 2)
	if len(got[macsecSaAttrPn]) != 8 {
		t.Errorf("XPN PN length = %d, want 8", len(got[macsecSaAttrPn]))
	}
	if hex.EncodeToString(got[macsecSaAttrSsci]) != "00000002" {
		t.Errorf("SSCI on the wire = %x, want 00000002 (network byte order)", got[macsecSaAttrSsci])
	}
	if !bytes.Equal(got[macsecSaAttrSalt], xpn.salt) {
		t.Errorf("salt on the wire = %x, want %x", got[macsecSaAttrSalt], xpn.salt)
	}
}

// TestParseMacsecLink parses an RTM_NEWLINK attribute payload as the kernel
// sends it for a MACsec interface.
func TestParseMacsecLink(t *testing.T) {
	build := func(kind string) []byte {
		ae := netlink.NewAttributeEncoder()
		ae.String(unix.IFLA_IFNAME, "macsec0")
		ae.Nested(unix.IFLA_LINKINFO, func(nae *netlink.AttributeEncoder) error {
			nae.String(unix.IFLA_INFO_KIND, kind)
			nae.Nested(unix.IFLA_INFO_DATA, func(dae *netlink.AttributeEncoder) error {
				dae.Bytes(unix.IFLA_MACSEC_SCI, binary.BigEndian.AppendUint64(nil, 0x001122334455_0001))
				dae.Uint64(unix.IFLA_MACSEC_CIPHER_SUITE, macsecCipherGCMAESXPN256)
				dae.Uint8(unix.IFLA_MACSEC_ENCODING_SA, 3)
				return nil
			})
			return nil
		})
		b, err := ae.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	l, err := parseMacsecLink(build("macsec"))
	if err != nil {
		t.Fatal(err)
	}
	want := macsecLink{sci: 0x001122334455_0001, cipher: macsecCipherGCMAESXPN256, encodingSA: 3}
	if l != want {
		t.Errorf("parsed %+v, want %+v", l, want)
	}
	if _, err := parseMacsecLink(build("veth")); err == nil {
		t.Error("expected an error for a non-MACsec interface")
	}
}

// TestMacsecRxSCIWireFormat pins the RX SC attribute layout the kernel
// expects: the SCI in network byte order (MAC address, then port), and
// MACSEC_ATTR_RXSC_CONFIG = 2 in linux/if_macsec.h.
func TestMacsecRxSCIWireFormat(t *testing.T) {
	repo, err := NewMacsecNetlinkRepository("macsec0", "001122334455ffff")
	if err != nil {
		t.Fatal(err)
	}
	s := macsecSession{rxSCI: repo.rxSCI}
	ae := netlink.NewAttributeEncoder()
	ae.Nested(macsecAttrRxscConfig, s.encodeRxSCI(true))
	b, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		t.Fatal(err)
	}
	var gotType uint16
	var gotSCI []byte
	for ad.Next() {
		gotType = ad.Type()
		ad.Nested(func(nad *netlink.AttributeDecoder) error {
			for nad.Next() {
				if nad.Type() == macsecRxscAttrSci {
					gotSCI = nad.Bytes()
				}
			}
			return nil
		})
	}
	if err := ad.Err(); err != nil {
		t.Fatal(err)
	}
	if gotType != 2 {
		t.Errorf("RX SC config attribute type = %d, want 2 (MACSEC_ATTR_RXSC_CONFIG)", gotType)
	}
	if got := hex.EncodeToString(gotSCI); got != "001122334455ffff" {
		t.Errorf("SCI on the wire = %s, want 001122334455ffff (network byte order)", got)
	}
	if macsecAttrSaConfig != 3 {
		t.Errorf("macsecAttrSaConfig = %d, want 3 (MACSEC_ATTR_SA_CONFIG)", macsecAttrSaConfig)
	}
}

// TestMacsecEncodingSAMessage guards against RTM_SETLINK, which the kernel
// accepts but never forwards to the macsec driver, so the TX SA never changes.
func TestMacsecEncodingSAMessage(t *testing.T) {
	msg, err := macsecEncodingSAMessage(7, 2)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Type != unix.RTM_NEWLINK {
		t.Fatalf("message type = %d, want RTM_NEWLINK (%d)", msg.Header.Type, unix.RTM_NEWLINK)
	}
	if msg.Header.Flags&(netlink.Create|netlink.Excl) != 0 {
		t.Error("request must modify the existing link, not create one")
	}
	if got := binary.NativeEndian.Uint32(msg.Data[4:8]); got != 7 {
		t.Errorf("ifindex = %d, want 7", got)
	}
	ad, err := netlink.NewAttributeDecoder(msg.Data[unix.SizeofIfInfomsg:])
	if err != nil {
		t.Fatal(err)
	}
	var kind string
	encodingSA := -1
	for ad.Next() {
		if ad.Type() != unix.IFLA_LINKINFO {
			continue
		}
		ad.Nested(func(nad *netlink.AttributeDecoder) error {
			for nad.Next() {
				switch nad.Type() {
				case unix.IFLA_INFO_KIND:
					kind = nad.String()
				case unix.IFLA_INFO_DATA:
					nad.Nested(func(dad *netlink.AttributeDecoder) error {
						for dad.Next() {
							if dad.Type() == unix.IFLA_MACSEC_ENCODING_SA {
								encodingSA = int(dad.Uint8())
							}
						}
						return nil
					})
				}
			}
			return nil
		})
	}
	if err := ad.Err(); err != nil {
		t.Fatal(err)
	}
	if kind != "macsec" || encodingSA != 2 {
		t.Errorf("linkinfo = (kind %q, encoding SA %d), want (macsec, 2)", kind, encodingSA)
	}
}

// TestMacsecDeferredSwitch checks the hitless handover: TX switches to a new
// SA only after switchDelay, and a pending switch is applied before the next
// install without firing again later.
func TestMacsecDeferredSwitch(t *testing.T) {
	repo, err := NewMacsecNetlinkRepository("macsec0", "001122334455ffff")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var switched []uint8
	repo.switchSA = func(an uint8) error {
		mu.Lock()
		defer mu.Unlock()
		switched = append(switched, an)
		return nil
	}
	got := func() []uint8 {
		mu.Lock()
		defer mu.Unlock()
		return append([]uint8(nil), switched...)
	}
	repo.switchDelay = 50 * time.Millisecond

	repo.mu.Lock()
	if err := repo.scheduleSwitchLocked(1); err != nil {
		t.Fatal(err)
	}
	repo.mu.Unlock()
	if s := got(); len(s) != 0 {
		t.Fatalf("switched before the delay: %v", s)
	}
	time.Sleep(150 * time.Millisecond)
	if s := got(); !reflect.DeepEqual(s, []uint8{1}) {
		t.Fatalf("after the delay switched = %v, want [1]", s)
	}

	// A new install flushes the pending switch before scheduling its own.
	repo.mu.Lock()
	if err := repo.scheduleSwitchLocked(2); err != nil {
		t.Fatal(err)
	}
	if err := repo.flushPendingLocked(); err != nil {
		t.Fatal(err)
	}
	repo.mu.Unlock()
	time.Sleep(150 * time.Millisecond)
	if s := got(); !reflect.DeepEqual(s, []uint8{1, 2}) {
		t.Fatalf("switched = %v, want [1 2] with no late duplicate", s)
	}
}
