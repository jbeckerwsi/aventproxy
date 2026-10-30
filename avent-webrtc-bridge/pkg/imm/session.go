package imm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/stun/v4"

	"avent-webrtc-bridge/pkg/core"
	"avent-webrtc-bridge/pkg/tuya"
)

const (
	convControl = 0
	convVideo   = 1
	convAudio   = 2

	answerTimeout     = 20 * time.Second
	nominationTimeout = 15 * time.Second
	firstVideoTimeout = 20 * time.Second
	stallTimeout      = 15 * time.Second
	checkInterval     = 200 * time.Millisecond
	tickInterval      = 50 * time.Millisecond
	// The camera installs its keys when its nominating check completes;
	// anything sent earlier is acknowledged but dropped, which stalls channel 0.
	settleAfterNomination = 300 * time.Millisecond
)

// Signaling is the MQTT side of a session, see tuya.ImmSignalingClient.
type Signaling interface {
	SetHandlers(onAnswer func(sdp string), onCandidate func(candidate string), onDisconnect func(closeReason int))
	Start() error
	Stop()
	SendSigQuery() error
	SendOffer(sdp, traceID string, ices []tuya.ICEServer, tcpRelay, logConfig json.RawMessage) error
	SendCandidate(candidate string) error
	SendDisconnect() error
}

type Config struct {
	DeviceID string
	UID      string
	LocalKey string
	// Password is the camera's P2P password from the rtc config.
	Password  string
	P2PConfig tuya.P2PConfig
	Audio     bool
}

// Session is one live imm stream.
type Session struct {
	cfg       Config
	signaling Signaling

	OnVideo func(*rtp.Packet)
	OnAudio func(*rtp.Packet)
	OnError func(error)

	ctx    context.Context
	cancel context.CancelFunc
	conn   *net.UDPConn

	offerKey  []byte
	answerKey []byte

	mutex        sync.Mutex
	remoteUfrag  string
	remotePwd    string
	candidates   []*net.UDPAddr
	peer         *net.UDPAddr
	mediaKey     []byte
	tagKey       []byte
	lastVideo    time.Time
	videoStarted bool
	running      bool
	failure      error

	// stallTimeout is how long video may stop before the session fails.
	stallTimeout time.Duration

	answered   chan answer
	nominated  chan struct{}
	firstVideo chan struct{}
	firstOnce  sync.Once
	nomOnce    sync.Once
	closeOnce  sync.Once

	fps        *fpsGuard
	lastTs     uint32
	haveTs     bool
	restarts   int
	restartGap time.Duration

	convs map[uint32]*conversation
	video unitParser
	audio unitParser
	vpack videoUnpacker
	apack audioPacker
}

func NewSession(cfg Config, signaling Signaling) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{
		cfg:        cfg,
		signaling:  signaling,
		ctx:        ctx,
		cancel:     cancel,
		answered:   make(chan answer, 1),
		nominated:  make(chan struct{}),
		firstVideo: make(chan struct{}),
		convs:      make(map[uint32]*conversation),

		stallTimeout: stallTimeout,
		restartGap:   50 * time.Millisecond,
	}
}

// Start runs the session until video flows, or returns why it could not.
func (s *Session) Start() error {
	session := s.cfg.P2PConfig.Session
	if session == nil {
		return errors.New("imm: the rtc config carries no p2p session")
	}
	key, err := hex.DecodeString(session.AesKey)
	if err != nil || len(key) < 16 {
		return errors.New("imm: the p2p session has no usable AES key")
	}
	s.offerKey = key[:16]
	s.tagKey = s.offerKey

	if err := s.listen(); err != nil {
		return err
	}
	if err := s.startSignaling(); err != nil {
		return err
	}

	now := time.Now()
	traceID := fmt.Sprintf("%s_%s_%d", session.TraceId, s.cfg.DeviceID, now.UnixMilli())
	offer := buildOffer(s.cfg.UID, session.SessionId, session.IceUfrag, session.IcePassword, hex.EncodeToString(s.offerKey), now.Unix())
	if err := s.signaling.SendSigQuery(); err != nil {
		core.Logger.Debug().Err(err).Msg("imm: signal query failed (non-fatal)")
	}
	if err := s.signaling.SendOffer(offer, traceID, s.cfg.P2PConfig.Ices, s.cfg.P2PConfig.TcpRelay, s.cfg.P2PConfig.Log); err != nil {
		return fmt.Errorf("imm: sending the offer: %w", err)
	}
	s.trickleLocalCandidates()

	select {
	case a := <-s.answered:
		s.mutex.Lock()
		s.remoteUfrag, s.remotePwd, s.answerKey = a.iceUfrag, a.icePassword, a.aesKey
		s.mutex.Unlock()
	case <-time.After(answerTimeout):
		return errors.New("imm: the camera sent no answer")
	case <-s.ctx.Done():
		return s.closedErr()
	}
	go s.checkLoop()

	select {
	case <-s.nominated:
	case <-time.After(nominationTimeout):
		return errors.New("imm: the camera nominated no candidate pair (is it reachable over UDP from this host?)")
	case <-s.ctx.Done():
		return s.closedErr()
	}
	core.Logger.Info().Msgf("imm: media path to %s", s.peerAddr())
	time.Sleep(settleAfterNomination)

	s.openConversations()
	go s.tickLoop()
	for _, msg := range startSequence(s.cfg.Password, s.cfg.LocalKey, s.cfg.Audio) {
		record, err := encryptRecord(s.offerKey, msg)
		if err != nil {
			return err
		}
		if err := s.convs[convControl].send(record); err != nil {
			return err
		}
	}

	select {
	case <-s.firstVideo:
		s.mutex.Lock()
		s.running = true
		s.mutex.Unlock()
		return nil
	case <-time.After(firstVideoTimeout):
		return errors.New("imm: logged in but the camera sent no video")
	case <-s.ctx.Done():
		return s.closedErr()
	}
}

// Close releases the camera and the socket. Safe to call more than once.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.cancel()
		if err := s.signaling.SendDisconnect(); err != nil {
			core.Logger.Debug().Err(err).Msg("imm: sending disconnect failed")
		}
		s.signaling.Stop()
		if s.conn != nil {
			_ = s.conn.Close()
		}
	})
}

func (s *Session) closedErr() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.failure != nil {
		return s.failure
	}
	return errors.New("imm: session closed")
}

// fail ends the session once. While Start is still running it only aborts
// Start, which returns the error; the caller holds its stream lock then, so
// calling OnError from here could not be handled before Start gave up anyway.
// Once streaming, OnError reports it so the stream is torn down and retried.
func (s *Session) fail(err error) {
	s.mutex.Lock()
	if s.failure != nil {
		s.mutex.Unlock()
		return
	}
	s.failure = err
	running := s.running
	s.mutex.Unlock()

	core.Logger.Warn().Err(err).Msg("imm: session failed")
	s.cancel()
	if running && s.OnError != nil {
		s.OnError(err)
	}
}

// --- signaling -------------------------------------------------------------

func (s *Session) startSignaling() error {
	s.signaling.SetHandlers(
		func(sdp string) {
			a, err := parseAnswer(sdp)
			if err != nil {
				core.Logger.Warn().Err(err).Msg("imm: unusable answer")
				return
			}
			select {
			case s.answered <- a:
			default:
			}
		},
		s.addRemoteCandidate,
		func(reason int) {
			s.fail(fmt.Errorf("imm: the camera closed the session (close_reason=%d)", reason))
		},
	)
	return s.signaling.Start()
}

func (s *Session) addRemoteCandidate(line string) {
	c, ok := parseCandidate(line)
	if !ok || (c.typ != "host" && c.typ != "srflx") {
		return
	}
	addr := &net.UDPAddr{IP: net.ParseIP(c.ip), Port: c.port}
	if addr.IP == nil {
		return
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, known := range s.candidates {
		if known.String() == addr.String() {
			return
		}
	}
	s.candidates = append(s.candidates, addr)
	core.Logger.Debug().Msgf("imm: camera candidate %s (%s)", addr, c.typ)
}

func (s *Session) trickleLocalCandidates() {
	port := s.conn.LocalAddr().(*net.UDPAddr).Port
	for _, ip := range localIPv4s() {
		line := hostCandidateLine(ip, port, crc32.ChecksumIEEE([]byte(ip)))
		if err := s.signaling.SendCandidate(line); err != nil {
			core.Logger.Debug().Err(err).Msg("imm: sending a candidate failed")
		}
	}
}

func localIPv4s() []string {
	var out []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			out = append(out, ip4.String())
		}
	}
	return out
}

// --- UDP / ICE ---------------------------------------------------------------

func (s *Session) listen() error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return fmt.Errorf("imm: opening the media socket: %w", err)
	}
	s.conn = conn
	go s.readLoop()
	return nil
}

func (s *Session) checkLoop() {
	tiebreaker := rand.Uint64()
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.nominated:
			return
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
		s.mutex.Lock()
		targets := append([]*net.UDPAddr(nil), s.candidates...)
		ufrag, pwd := s.remoteUfrag, s.remotePwd
		s.mutex.Unlock()
		for _, addr := range targets {
			req, err := bindingRequest(ufrag, s.cfg.P2PConfig.Session.IceUfrag, pwd, tiebreaker)
			if err == nil {
				_, _ = s.conn.WriteToUDP(req, addr)
			}
		}
	}
}

func (s *Session) readLoop() {
	buf := make([]byte, 2048)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
			default:
				s.fail(fmt.Errorf("imm: media socket: %w", err))
			}
			return
		}
		datagram := buf[:n]
		if stun.IsMessage(datagram) {
			s.handleSTUN(datagram, from)
			continue
		}
		s.handleDatagram(append([]byte(nil), datagram...))
	}
}

func (s *Session) handleSTUN(datagram []byte, from *net.UDPAddr) {
	msg := &stun.Message{Raw: append([]byte(nil), datagram...)}
	if err := msg.Decode(); err != nil || msg.Type != stun.BindingRequest {
		return
	}
	resp, err := bindingSuccess(msg, from, s.cfg.P2PConfig.Session.IcePassword)
	if err != nil {
		return
	}
	_, _ = s.conn.WriteToUDP(resp, from)
	if msg.Contains(stun.AttrUseCandidate) {
		s.nomOnce.Do(func() {
			s.mutex.Lock()
			s.peer = from
			s.mutex.Unlock()
			close(s.nominated)
		})
	}
}

func (s *Session) peerAddr() *net.UDPAddr {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.peer
}

// --- KCP / channels ----------------------------------------------------------

func (s *Session) openConversations() {
	write := func(seg []byte) {
		peer := s.peerAddr()
		if peer == nil {
			return
		}
		s.mutex.Lock()
		key := s.tagKey
		s.mutex.Unlock()
		_, _ = s.conn.WriteToUDP(append(seg, tag(key, seg)...), peer)
	}
	s.mutex.Lock()
	s.convs[convControl] = newConversation(convControl, write, s.onControl)
	s.convs[convVideo] = newConversation(convVideo, write, s.onVideoRecord)
	s.convs[convAudio] = newConversation(convAudio, write, s.onAudioRecord)
	s.lastVideo = time.Now()
	s.fps = newFPSGuard()
	s.mutex.Unlock()
}

func (s *Session) handleDatagram(datagram []byte) {
	if len(datagram) < kcpHeaderSize+tagSize {
		return
	}
	s.mutex.Lock()
	key, answerKey := s.tagKey, s.answerKey
	s.mutex.Unlock()
	if !tagValid(key, datagram) {
		// The tag key has always been the offer key on the SCD860; accept the
		// answer key too in case other firmware follows the reference code.
		if answerKey == nil || !tagValid(answerKey, datagram) {
			return
		}
		s.mutex.Lock()
		s.tagKey = answerKey
		s.mutex.Unlock()
	}
	for _, seg := range parseSegments(datagram[:len(datagram)-tagSize]) {
		s.mutex.Lock()
		conv := s.convs[seg.conv]
		s.mutex.Unlock()
		if conv != nil {
			conv.input(seg)
		}
	}
}

// decrypt opens a record from the camera. The SCD860 encrypts with the offer
// key in both directions, where the reference implementation uses the answer
// key; a wrong key still passes the padding check about once in 256 records,
// so the key is settled on the first full-block record and then kept.
func (s *Session) decrypt(record []byte) []byte {
	s.mutex.Lock()
	settled, offerKey, answerKey := s.mediaKey, s.offerKey, s.answerKey
	s.mutex.Unlock()
	if settled != nil {
		plain, _, err := decryptRecord(settled, record)
		if err != nil {
			return nil
		}
		return plain
	}
	for _, key := range [][]byte{offerKey, answerKey} {
		if key == nil {
			continue
		}
		plain, fullPad, err := decryptRecord(key, record)
		if err != nil {
			continue
		}
		if fullPad {
			s.mutex.Lock()
			s.mediaKey = key
			s.mutex.Unlock()
		}
		return plain
	}
	return nil
}

func (s *Session) onControl(record []byte) {
	plain := s.decrypt(record)
	if len(plain) >= 20 {
		core.Logger.Debug().Msgf("imm: control reply cmd=%d/%d payload=%x",
			uint16(plain[12])|uint16(plain[13])<<8, uint16(plain[14])|uint16(plain[15])<<8, plain[20:])
	}
}

func (s *Session) onVideoRecord(record []byte) {
	plain := s.decrypt(record)
	if plain == nil {
		return
	}
	s.mutex.Lock()
	s.lastVideo = time.Now()
	s.videoStarted = true
	s.mutex.Unlock()
	for _, unit := range s.video.feed(plain) {
		if pkt := s.vpack.packet(unit.rtp); pkt != nil {
			s.watchFrameRate(pkt.Timestamp)
			s.firstOnce.Do(func() { close(s.firstVideo) })
			if s.OnVideo != nil {
				s.OnVideo(pkt)
			}
		}
	}
}

// watchFrameRate feeds the camera's frame intervals to the fps guard and
// restarts live video when the camera has fallen back to its idle rate because
// another viewer stopped. Called before OnVideo, which may rewrite timestamps.
func (s *Session) watchFrameRate(ts uint32) {
	s.mutex.Lock()
	if s.haveTs && ts == s.lastTs {
		s.mutex.Unlock()
		return
	}
	interval := time.Duration(int32(ts-s.lastTs)) * time.Second / 90000
	first := !s.haveTs
	s.lastTs, s.haveTs = ts, true
	restart := !first && s.fps != nil && s.fps.observe(interval)
	if restart {
		s.restarts++
	}
	n := s.restarts
	s.mutex.Unlock()

	if restart {
		core.Logger.Info().Msgf("imm: the camera fell back to its idle frame rate (another viewer stopped); restarting live video (#%d)", n)
		go s.restartLive()
	}
}

func (s *Session) restartLive() {
	for i, msg := range restartSequence() {
		if i > 0 {
			select {
			case <-time.After(s.restartGap):
			case <-s.ctx.Done():
				return
			}
		}
		record, err := encryptRecord(s.offerKey, msg)
		if err != nil {
			return
		}
		s.mutex.Lock()
		conv := s.convs[convControl]
		s.mutex.Unlock()
		if err := conv.send(record); err != nil {
			core.Logger.Debug().Err(err).Msg("imm: restart command failed")
			return
		}
	}
}

func (s *Session) onAudioRecord(record []byte) {
	plain := s.decrypt(record)
	if plain == nil {
		return
	}
	for _, unit := range s.audio.feed(plain) {
		if pkt := s.apack.packet(unit.rtp); pkt != nil && s.OnAudio != nil {
			s.OnAudio(pkt)
		}
	}
}

func (s *Session) tickLoop() {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			s.mutex.Lock()
			convs := make([]*conversation, 0, len(s.convs))
			for _, c := range s.convs {
				convs = append(convs, c)
			}
			stalled := s.videoStarted && now.Sub(s.lastVideo) > s.stallTimeout
			s.mutex.Unlock()
			for _, c := range convs {
				if err := c.tick(now); err != nil {
					s.fail(err)
					return
				}
			}
			if stalled {
				s.fail(errors.New("imm: no video from the camera"))
				return
			}
		}
	}
}
