package imm

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/stun/v4"

	"avent-webrtc-bridge/pkg/tuya"
)

type fakeSignaling struct {
	mutex        sync.Mutex
	onAnswer     func(string)
	onCandidate  func(string)
	onDisconnect func(int)
	offers       chan string
	disconnects  int
}

func (f *fakeSignaling) SetHandlers(a func(string), c func(string), d func(int)) {
	f.onAnswer, f.onCandidate, f.onDisconnect = a, c, d
}
func (f *fakeSignaling) Start() error        { return nil }
func (f *fakeSignaling) Stop()               {}
func (f *fakeSignaling) SendSigQuery() error { return nil }
func (f *fakeSignaling) SendOffer(sdp, _ string, _ []tuya.ICEServer, _, _ json.RawMessage) error {
	f.offers <- sdp
	return nil
}
func (f *fakeSignaling) SendCandidate(string) error { return nil }
func (f *fakeSignaling) SendDisconnect() error {
	f.mutex.Lock()
	f.disconnects++
	f.mutex.Unlock()
	return nil
}

// fakeCamera plays the device side over loopback: it answers, nominates the
// client's address once the client's check arrives, checks the channel-0 login,
// and sends one video record after PLAY. Like the SCD860 it encrypts and tags
// with the offer key, not the key in its own answer.
type fakeCamera struct {
	t        *testing.T
	conn     *net.UDPConn
	password string
	localKey string
	loggedIn chan struct{}
}

const fakeCamPwd = "camerapassword0123456789"

func (cam *fakeCamera) run(sig *fakeSignaling) {
	offer := <-sig.offers
	o, err := parseAnswer(offer) // the offer carries the same three fields
	if err != nil {
		cam.t.Errorf("offer: %v", err)
		return
	}
	port := cam.conn.LocalAddr().(*net.UDPAddr).Port
	sig.onAnswer("v=0\r\na=ice-ufrag:cam1\r\na=ice-pwd:" + fakeCamPwd + "\r\na=aes-key:ffeeddccbbaa99887766554433221100\r\n")
	sig.onCandidate(fmt.Sprintf("a=candidate:1 1 UDP 2130706431 127.0.0.1 %d typ host\r\n", port))

	buf := make([]byte, 2048)
	var control []byte
	nominated := false
	for {
		_ = cam.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, from, err := cam.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		data := append([]byte(nil), buf[:n]...)
		if stun.IsMessage(data) {
			m := &stun.Message{Raw: data}
			if m.Decode() != nil || m.Type != stun.BindingRequest {
				continue
			}
			if err := stun.NewShortTermIntegrity(fakeCamPwd).Check(m); err != nil {
				cam.t.Errorf("client check integrity: %v", err)
			}
			resp, _ := bindingSuccess(m, from, fakeCamPwd)
			_, _ = cam.conn.WriteToUDP(resp, from)
			if !nominated {
				nominated = true
				tb := make([]byte, 8)
				req, _ := stun.Build(stun.TransactionID, stun.BindingRequest,
					stun.NewUsername(o.iceUfrag+":cam1"),
					rawAttr{stun.AttrICEControlling, tb},
					rawAttr{stun.AttrUseCandidate, nil},
					stun.NewShortTermIntegrity(o.icePassword), stun.Fingerprint)
				_, _ = cam.conn.WriteToUDP(req.Raw, from)
			}
			continue
		}
		if !tagValid(o.aesKey, data) {
			cam.t.Errorf("datagram not tagged with the offer key")
			continue
		}
		for _, seg := range parseSegments(data[:len(data)-tagSize]) {
			if seg.conv != convControl || seg.cmd != kcpPush {
				continue
			}
			ack := segment{conv: 0, cmd: kcpAck, wnd: 128, ts: seg.ts, sn: seg.sn, una: seg.sn + 1}.marshal()
			_, _ = cam.conn.WriteToUDP(append(ack, tag(o.aesKey, ack)...), from)
			plain, _, err := decryptRecord(o.aesKey, seg.data)
			if err != nil {
				cam.t.Errorf("control record: %v", err)
				continue
			}
			control = append(control, plain...)
		}
		if len(control) >= 104+28 && cam.loginOK(control) {
			close(cam.loggedIn)
			cam.sendVideo(o.aesKey, from)
			return
		}
	}
}

func (cam *fakeCamera) loginOK(control []byte) bool {
	sum := md5.Sum([]byte(cam.password + "||" + cam.localKey))
	ok := binary.LittleEndian.Uint32(control) == controlMark &&
		string(bytes.TrimRight(control[40:104], "\x00")) == hex.EncodeToString(sum[:])
	if !ok {
		cam.t.Errorf("bad login record %x", control[:104])
	}
	return ok
}

func (cam *fakeCamera) sendVideo(key []byte, to *net.UDPAddr) {
	idr, _ := (&rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 96, SequenceNumber: 7, Timestamp: 9000, Marker: true, SSRC: 10},
		Payload: []byte{0x65, 0x88, 0x84}}).Marshal()
	record, _ := encryptRecord(key, mediaUnitBytes(1000, true, idr))
	seg := segment{conv: convVideo, cmd: kcpPush, wnd: 128, sn: 0, data: record}.marshal()
	_, _ = cam.conn.WriteToUDP(append(seg, tag(key, seg)...), to)
}

func TestSessionAgainstFakeCamera(t *testing.T) {
	camConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip("no loopback UDP:", err)
	}
	defer camConn.Close()

	sig := &fakeSignaling{offers: make(chan string, 1)}
	cam := &fakeCamera{t: t, conn: camConn, password: "ad1a2b3c", localKey: "fakelocalkey0000", loggedIn: make(chan struct{})}

	session := NewSession(Config{
		DeviceID: "dev1",
		UID:      "uid1",
		LocalKey: cam.localKey,
		Password: cam.password,
		P2PConfig: tuya.P2PConfig{
			Transmission: "kcp",
			Session: &tuya.P2PSession{
				SessionId:   "dev1sess",
				AesKey:      "00112233445566778899aabbccddeeff",
				IceUfrag:    "cli1",
				IcePassword: "clientpassword0123456789",
			},
		},
	}, sig)
	videos := make(chan *rtp.Packet, 4)
	session.OnVideo = func(p *rtp.Packet) { videos <- p }

	go cam.run(sig)
	if err := session.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer session.Close()

	select {
	case p := <-videos:
		if p.PayloadType != 96 || !bytes.Equal(p.Payload, []byte{0x65, 0x88, 0x84}) {
			t.Fatalf("video packet %+v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no video packet")
	}

	session.Close()
	session.Close()
	if sig.disconnects != 1 {
		t.Fatalf("sent %d disconnects, want exactly 1", sig.disconnects)
	}
}

func newTestSession(t *testing.T, sig *fakeSignaling, cam *fakeCamera) *Session {
	t.Helper()
	return NewSession(Config{
		DeviceID: "dev1",
		UID:      "uid1",
		LocalKey: cam.localKey,
		Password: cam.password,
		P2PConfig: tuya.P2PConfig{
			Transmission: "kcp",
			Session: &tuya.P2PSession{
				SessionId:   "dev1sess",
				AesKey:      "00112233445566778899aabbccddeeff",
				IceUfrag:    "cli1",
				IcePassword: "clientpassword0123456789",
			},
		},
	}, sig)
}

func TestCameraDisconnectDuringStartAbortsStart(t *testing.T) {
	sig := &fakeSignaling{offers: make(chan string, 1)}
	cam := &fakeCamera{t: t, password: "pw", localKey: "fakelocalkey0000"}
	session := newTestSession(t, sig, cam)
	reported := make(chan error, 1)
	session.OnError = func(err error) { reported <- err }

	go func() {
		<-sig.offers
		sig.onDisconnect(12)
	}()

	began := time.Now()
	err := session.Start()
	session.Close()
	if err == nil || !strings.Contains(err.Error(), "close_reason=12") {
		t.Fatalf("Start returned %v, want the camera's close reason", err)
	}
	if time.Since(began) > 2*time.Second {
		t.Fatalf("Start took %v; it must not wait for its timeouts", time.Since(began))
	}
	select {
	case err := <-reported:
		t.Fatalf("OnError called during Start: %v", err)
	default:
	}
}

func TestStallAfterStartIsReported(t *testing.T) {
	camConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip("no loopback UDP:", err)
	}
	defer camConn.Close()

	sig := &fakeSignaling{offers: make(chan string, 1)}
	cam := &fakeCamera{t: t, conn: camConn, password: "ad1a2b3c", localKey: "fakelocalkey0000", loggedIn: make(chan struct{})}
	session := newTestSession(t, sig, cam)
	session.stallTimeout = 300 * time.Millisecond
	reported := make(chan error, 1)
	session.OnError = func(err error) { reported <- err }

	go cam.run(sig) // sends one video record, then goes quiet
	if err := session.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer session.Close()

	select {
	case err := <-reported:
		if !strings.Contains(err.Error(), "no video") {
			t.Fatalf("reported %v, want a stall", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a stalled stream was never reported")
	}
}
