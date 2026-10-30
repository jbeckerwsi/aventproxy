package imm

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/stun/v4"
)

var testKey = []byte("0123456789abcdef")

func TestRecordRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 15, 16, 17, 1168, 1300} {
		plain := bytes.Repeat([]byte{0xab}, n)
		rec, err := encryptRecord(testKey, plain)
		if err != nil {
			t.Fatal(err)
		}
		if len(rec)%16 != 0 || len(rec) < 32 {
			t.Fatalf("record length %d for %d bytes", len(rec), n)
		}
		got, fullPad, err := decryptRecord(testKey, rec)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("n=%d: got %x err %v", n, got, err)
		}
		if fullPad != (n%16 == 0) {
			t.Fatalf("n=%d: fullPad=%v", n, fullPad)
		}
	}
}

func TestDecryptRecordRejectsMalformed(t *testing.T) {
	if _, _, err := decryptRecord(testKey, make([]byte, 20)); err == nil {
		t.Fatal("accepted a record that is not whole blocks")
	}
	rec, _ := encryptRecord(testKey, bytes.Repeat([]byte{1}, 32))
	other := []byte("fedcba9876543210")
	if plain, fullPad, err := decryptRecord(other, rec); err == nil && fullPad {
		t.Fatalf("wrong key produced a full-block pad: %x", plain)
	}
}

func TestTag(t *testing.T) {
	body := []byte("kcp segment bytes")
	datagram := append(append([]byte{}, body...), tag(testKey, body)...)
	if !tagValid(testKey, datagram) {
		t.Fatal("valid tag rejected")
	}
	datagram[0] ^= 1
	if tagValid(testKey, datagram) {
		t.Fatal("tampered datagram accepted")
	}
}

func TestBuildOffer(t *testing.T) {
	sdp := buildOffer("uid1", "sess1", "uf", "pw", "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", 1700000000)
	for _, want := range []string{
		"a=group:BUNDLE imm0\r\n", "m=application 9 imm 6001\r\n", "a=ice-ufrag:uf\r\n",
		"a=ice-pwd:pw\r\n", "a=aes-key:0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f\r\n",
		"a=rtpmap:6001 AES/KCP 330\r\n", "a=ssrc:0 cname:uid1\r\n",
	} {
		if !strings.Contains(sdp, want) {
			t.Errorf("offer lacks %q", want)
		}
	}
	if !strings.HasPrefix(sdp, "v=0\r\n") {
		t.Error("offer must start with v=0")
	}
}

func TestParseAnswer(t *testing.T) {
	sdp := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\nm=application 9 imm 6001\r\na=ice-ufrag:FjqB\r\n" +
		"a=ice-pwd:abcdefghijklmnopqrstuvwx\r\na=aes-key:ffeeddccbbaa99887766554433221100\r\na=rtpmap:6001 AES/KCP 3\r\n"
	a, err := parseAnswer(sdp)
	if err != nil {
		t.Fatal(err)
	}
	if a.iceUfrag != "FjqB" || a.icePassword != "abcdefghijklmnopqrstuvwx" || hex.EncodeToString(a.aesKey) != "ffeeddccbbaa99887766554433221100" {
		t.Fatalf("parsed %+v", a)
	}
	if _, err := parseAnswer("v=0\r\n"); err == nil {
		t.Fatal("answer without credentials accepted")
	}
}

func TestParseCandidate(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
		ip   string
		port int
		typ  string
	}{
		{"a=candidate:2008532637 1 UDP 2130706431 10.0.40.155 58962 typ host\r\n", true, "10.0.40.155", 58962, "host"},
		{"candidate:1 1 udp 1694498815 91.226.145.238 58962 typ srflx raddr 0.0.0.0 rport 0", true, "91.226.145.238", 58962, "srflx"},
		{"a=candidate:1 1 TCP 1 10.0.0.1 9 typ host", false, "", 0, ""},
		{"a=candidate:1 1 UDP 1 fe80::1 9 typ host", false, "", 0, ""},
		{"garbage", false, "", 0, ""},
	}
	for _, c := range cases {
		got, ok := parseCandidate(c.line)
		if ok != c.ok || (ok && (got.ip != c.ip || got.port != c.port || got.typ != c.typ)) {
			t.Errorf("%q: got %+v %v", c.line, got, ok)
		}
	}
}

func TestBindingRequestAndSuccess(t *testing.T) {
	raw, err := bindingRequest("dev", "cli", "devpwd", 42)
	if err != nil {
		t.Fatal(err)
	}
	m := &stun.Message{Raw: raw}
	if err := m.Decode(); err != nil {
		t.Fatal(err)
	}
	var user stun.Username
	if err := user.GetFrom(m); err != nil || user.String() != "dev:cli" {
		t.Fatalf("username %q err %v", user, err)
	}
	if err := stun.NewShortTermIntegrity("devpwd").Check(m); err != nil {
		t.Fatalf("integrity: %v", err)
	}
	if err := stun.Fingerprint.Check(m); err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if !m.Contains(stun.AttrICEControlled) || m.Contains(stun.AttrICEControlling) {
		t.Fatal("the client must claim the controlled role")
	}

	from := &net.UDPAddr{IP: net.IPv4(10, 0, 40, 155), Port: 4000}
	resp, err := bindingSuccess(m, from, "clipwd")
	if err != nil {
		t.Fatal(err)
	}
	r := &stun.Message{Raw: resp}
	if err := r.Decode(); err != nil || r.Type != stun.BindingSuccess || r.TransactionID != m.TransactionID {
		t.Fatalf("response %v err %v", r.Type, err)
	}
	if err := stun.NewShortTermIntegrity("clipwd").Check(r); err != nil {
		t.Fatalf("response integrity: %v", err)
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(r); err != nil || !xor.IP.Equal(from.IP) || xor.Port != from.Port {
		t.Fatalf("mapped address %v err %v", xor, err)
	}
}

func TestLoginRecord(t *testing.T) {
	rec := loginRecord("ad1a2b3c", "0123456789abcdef")
	if len(rec) != 104 || binary.LittleEndian.Uint32(rec) != controlMark {
		t.Fatalf("record %x", rec[:8])
	}
	if string(bytes.TrimRight(rec[8:40], "\x00")) != "admin" {
		t.Fatalf("user %q", rec[8:40])
	}
	sum := md5.Sum([]byte("ad1a2b3c||0123456789abcdef"))
	if string(bytes.TrimRight(rec[40:], "\x00")) != hex.EncodeToString(sum[:]) {
		t.Fatalf("password field %q", rec[40:])
	}
}

func TestCommandLayout(t *testing.T) {
	// The app's PLAY request, byte for byte.
	want, _ := hex.DecodeString("78563412030001000000000006000000080000000000000000000000")
	if got := command(reqIDPlay, cmdIOCtrlVideo, opVideoPlay, 0, 0); !bytes.Equal(got, want) {
		t.Fatalf("PLAY\n got %x\nwant %x", got, want)
	}
	seq := startSequence("pw", "key", true)
	if len(seq) != 4 || len(seq[0]) != 104 {
		t.Fatalf("start sequence has %d messages", len(seq))
	}
	if len(startSequence("pw", "key", false)) != 3 {
		t.Fatal("audio must be optional")
	}
}

func mediaUnitBytes(timeMs uint64, iframe bool, rtpPacket []byte) []byte {
	ext := 0
	if iframe {
		ext = 8
	}
	b := make([]byte, 24+ext+4)
	binary.LittleEndian.PutUint32(b[0:], reqIDPlay)
	binary.LittleEndian.PutUint64(b[8:], timeMs)
	binary.LittleEndian.PutUint32(b[16:], uint32(ext))
	if iframe {
		b[24] = 1
		binary.LittleEndian.PutUint16(b[26:], 1280)
		binary.LittleEndian.PutUint16(b[28:], 720)
		binary.LittleEndian.PutUint16(b[30:], 30)
	}
	binary.LittleEndian.PutUint32(b[24+ext:], uint32(len(rtpPacket)))
	return append(b, rtpPacket...)
}

func rtpBytes(t *testing.T, seq uint16, ts uint32, marker bool, pt uint8, payload []byte) []byte {
	t.Helper()
	p := rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: pt, SequenceNumber: seq, Timestamp: ts, Marker: marker, SSRC: 10}, Payload: payload}
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnitParserAcrossRecordsAndGarbage(t *testing.T) {
	idr := rtpBytes(t, 1, 900, true, 96, []byte{0x65, 1, 2, 3})
	slice := rtpBytes(t, 2, 3960, true, 96, []byte{0x41, 4, 5})
	stream := append(mediaUnitBytes(10, true, idr), mediaUnitBytes(44, false, slice)...)

	var p unitParser
	var got []mediaUnit
	for i := 0; i < len(stream); i += 7 { // split at arbitrary points
		end := min(i+7, len(stream))
		got = append(got, p.feed(stream[i:end])...)
	}
	if len(got) != 2 || got[0].timeMs != 10 || got[1].timeMs != 44 || !bytes.Equal(got[1].rtp, slice) {
		t.Fatalf("units %+v", got)
	}

	var q unitParser
	units := q.feed(append([]byte{0xde, 0xad, 0xbe}, mediaUnitBytes(5, false, slice)...))
	if len(units) != 1 || q.resyncs == 0 {
		t.Fatalf("resync failed: %d units, %d resyncs", len(units), q.resyncs)
	}
}

func TestVideoUnpacker(t *testing.T) {
	var u videoUnpacker
	aud := rtpBytes(t, 20, 100, true, 96, []byte{0x09, 0x30})
	if u.packet(aud) != nil {
		t.Fatal("access unit delimiter must be dropped")
	}
	// The camera sets X on P-frame packets without an extension header.
	slice := rtpBytes(t, 21, 100, true, 96, []byte{0x5c, 0x81, 0xaa, 0xbb})
	slice[0] |= 0x10
	p := u.packet(slice)
	if p == nil || p.Extension || !bytes.Equal(p.Payload, []byte{0x5c, 0x81, 0xaa, 0xbb}) {
		t.Fatalf("slice %+v", p)
	}
	next := u.packet(rtpBytes(t, 22, 103, true, 96, []byte{0x41, 1}))
	if p.SequenceNumber != 0 || next.SequenceNumber != 1 {
		t.Fatalf("sequence %d, %d: want 0, 1 after the dropped delimiter", p.SequenceNumber, next.SequenceNumber)
	}
}

func TestAudioPacker(t *testing.T) {
	pcm := make([]byte, 0, 8)
	for _, s := range []int16{0, 32767, -32768, 1000} {
		pcm = binary.LittleEndian.AppendUint16(pcm, uint16(s))
	}
	var a audioPacker
	p := a.packet(rtpBytes(t, 1, 0, false, rtpPayloadPCM, pcm))
	if p == nil || p.PayloadType != 0 {
		t.Fatalf("packet %+v", p)
	}
	if want := []byte{0xff, 0x80, 0x00, 0xce}; !bytes.Equal(p.Payload, want) {
		t.Fatalf("mu-law %x, want %x", p.Payload, want)
	}
	p2 := a.packet(rtpBytes(t, 2, 0, false, rtpPayloadPCM, pcm))
	if p2.Timestamp != 4 || p2.SequenceNumber != 1 {
		t.Fatalf("second packet ts %d seq %d", p2.Timestamp, p2.SequenceNumber)
	}
	if a.packet(rtpBytes(t, 3, 0, false, 8, pcm)) != nil {
		t.Fatal("non-PCM payload must be ignored")
	}
}

func TestConversationOrdersAndAcks(t *testing.T) {
	var sent [][]byte
	var delivered [][]byte
	c := newConversation(1, func(b []byte) { sent = append(sent, b) }, func(m []byte) { delivered = append(delivered, m) })

	c.input(segment{conv: 1, cmd: kcpPush, sn: 1, ts: 7, data: []byte("b")})
	c.input(segment{conv: 1, cmd: kcpPush, sn: 0, ts: 8, data: []byte("a")})
	c.input(segment{conv: 1, cmd: kcpPush, sn: 0, ts: 9, data: []byte("a")}) // duplicate
	if len(delivered) != 2 || string(delivered[0]) != "a" || string(delivered[1]) != "b" {
		t.Fatalf("delivered %q", delivered)
	}
	acks := parseSegments(bytes.Join(sent, nil))
	if len(acks) != 3 || acks[0].cmd != kcpAck || acks[0].sn != 1 || acks[0].ts != 7 || acks[1].una != 2 {
		t.Fatalf("acks %+v", acks)
	}
	if acks[0].wnd != kcpReceiveWindow {
		t.Fatalf("advertised window %d", acks[0].wnd)
	}

	// The camera restarting a channel at sequence 0 must not stall it.
	for sn := uint32(2); sn < 2000; sn++ {
		c.input(segment{conv: 1, cmd: kcpPush, sn: sn, data: []byte{1}})
	}
	before := len(delivered)
	c.input(segment{conv: 1, cmd: kcpPush, sn: 0, data: []byte("restart")})
	if len(delivered) != before+1 || string(delivered[len(delivered)-1]) != "restart" {
		t.Fatal("a reset conversation was not followed")
	}
}

func TestConversationRetransmitsAndGivesUp(t *testing.T) {
	var sent int
	c := newConversation(0, func([]byte) { sent++ }, func([]byte) {})
	if err := c.send([]byte("login")); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 1; i < kcpMaxTransmits; i++ {
		now = now.Add(kcpRetransmitAfter)
		if err := c.tick(now); err != nil {
			t.Fatal(err)
		}
	}
	if sent != kcpMaxTransmits {
		t.Fatalf("transmitted %d times", sent)
	}
	if err := c.tick(now.Add(kcpRetransmitAfter)); err != errKcpGaveUp {
		t.Fatalf("got %v, want errKcpGaveUp", err)
	}

	c2 := newConversation(0, func([]byte) {}, func([]byte) {})
	_ = c2.send([]byte("x"))
	c2.input(segment{conv: 0, cmd: kcpAck, sn: 0})
	if err := c2.tick(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("acknowledged segment still pending: %v", err)
	}
}
