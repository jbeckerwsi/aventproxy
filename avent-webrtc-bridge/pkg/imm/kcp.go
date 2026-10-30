package imm

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// KCP as the camera speaks it: the stock 24-byte little-endian segment header,
// unchanged. Only what a receiving client needs is implemented: in-order
// delivery with immediate ACKs, and retransmission for the few commands sent.

const (
	kcpPush       = 81
	kcpAck        = 82
	kcpWindowAsk  = 83
	kcpWindowTell = 84

	kcpHeaderSize = 24
	kcpMSS        = 1376
	// The camera paces its sending from the window advertised in our ACKs, so
	// it must stay well open for video.
	kcpReceiveWindow = 512

	kcpRetransmitAfter = 300 * time.Millisecond
	kcpMaxTransmits    = 10
)

var errKcpGaveUp = errors.New("kcp: the camera stopped acknowledging")

type segment struct {
	conv uint32
	cmd  byte
	frg  byte
	wnd  uint16
	ts   uint32
	sn   uint32
	una  uint32
	data []byte
}

func (s segment) marshal() []byte {
	b := make([]byte, kcpHeaderSize, kcpHeaderSize+len(s.data))
	binary.LittleEndian.PutUint32(b[0:], s.conv)
	b[4] = s.cmd
	b[5] = s.frg
	binary.LittleEndian.PutUint16(b[6:], s.wnd)
	binary.LittleEndian.PutUint32(b[8:], s.ts)
	binary.LittleEndian.PutUint32(b[12:], s.sn)
	binary.LittleEndian.PutUint32(b[16:], s.una)
	binary.LittleEndian.PutUint32(b[20:], uint32(len(s.data)))
	return append(b, s.data...)
}

// parseSegments splits a datagram (tag already removed) into its segments.
func parseSegments(b []byte) []segment {
	var out []segment
	for len(b) >= kcpHeaderSize {
		n := int(binary.LittleEndian.Uint32(b[20:]))
		if n < 0 || kcpHeaderSize+n > len(b) {
			break
		}
		out = append(out, segment{
			conv: binary.LittleEndian.Uint32(b[0:]),
			cmd:  b[4],
			frg:  b[5],
			wnd:  binary.LittleEndian.Uint16(b[6:]),
			ts:   binary.LittleEndian.Uint32(b[8:]),
			sn:   binary.LittleEndian.Uint32(b[12:]),
			una:  binary.LittleEndian.Uint32(b[16:]),
			data: b[kcpHeaderSize : kcpHeaderSize+n],
		})
		b = b[kcpHeaderSize+n:]
	}
	return out
}

type pendingSegment struct {
	sn        uint32
	raw       []byte
	sentAt    time.Time
	transmits int
}

// conversation is one KCP conversation (channel).
type conversation struct {
	conv     uint32
	transmit func([]byte)
	deliver  func([]byte)
	epoch    time.Time

	mutex     sync.Mutex
	sndNxt    uint32
	rcvNxt    uint32
	received  map[uint32]segment
	fragments [][]byte
	pending   []pendingSegment
}

func newConversation(conv uint32, transmit func([]byte), deliver func([]byte)) *conversation {
	return &conversation{
		conv:     conv,
		transmit: transmit,
		deliver:  deliver,
		epoch:    time.Now(),
		received: make(map[uint32]segment),
	}
}

func (c *conversation) now() uint32 {
	return uint32(time.Since(c.epoch).Milliseconds())
}

func (c *conversation) input(s segment) {
	c.mutex.Lock()
	c.retire(s.una)
	var messages [][]byte
	switch s.cmd {
	case kcpAck:
		c.retireOne(s.sn)
	case kcpPush:
		// The camera recreates a channel's KCP state (sequence back to 0) when
		// a stream on it restarts; follow it instead of discarding everything.
		if int32(s.sn-c.rcvNxt) < -kcpReceiveWindow {
			c.rcvNxt = s.sn
			c.received = make(map[uint32]segment)
			c.fragments = nil
		}
		messages = c.accept(s)
		c.transmit(segment{conv: c.conv, cmd: kcpAck, wnd: kcpReceiveWindow, ts: s.ts, sn: s.sn, una: c.rcvNxt}.marshal())
	case kcpWindowAsk:
		c.transmit(segment{conv: c.conv, cmd: kcpWindowTell, wnd: kcpReceiveWindow, ts: c.now(), una: c.rcvNxt}.marshal())
	}
	c.mutex.Unlock()

	for _, m := range messages {
		c.deliver(m)
	}
}

func (c *conversation) accept(s segment) [][]byte {
	diff := int32(s.sn - c.rcvNxt)
	if diff < 0 || diff >= kcpReceiveWindow {
		return nil
	}
	if _, dup := c.received[s.sn]; dup {
		return nil
	}
	s.data = append([]byte(nil), s.data...)
	c.received[s.sn] = s

	var messages [][]byte
	for {
		next, ok := c.received[c.rcvNxt]
		if !ok {
			break
		}
		delete(c.received, c.rcvNxt)
		c.rcvNxt++
		c.fragments = append(c.fragments, next.data)
		if next.frg == 0 {
			var msg []byte
			for _, f := range c.fragments {
				msg = append(msg, f...)
			}
			c.fragments = nil
			if len(msg) > 0 {
				messages = append(messages, msg)
			}
		}
	}
	return messages
}

func (c *conversation) retire(una uint32) {
	for len(c.pending) > 0 && int32(c.pending[0].sn-una) < 0 {
		c.pending = c.pending[1:]
	}
}

func (c *conversation) retireOne(sn uint32) {
	for i, p := range c.pending {
		if p.sn == sn {
			c.pending = append(c.pending[:i], c.pending[i+1:]...)
			return
		}
	}
}

// send queues one message; it must fit a single segment.
func (c *conversation) send(msg []byte) error {
	if len(msg) > kcpMSS {
		return errors.New("kcp: message larger than one segment")
	}
	c.mutex.Lock()
	raw := segment{conv: c.conv, cmd: kcpPush, wnd: kcpReceiveWindow, ts: c.now(), sn: c.sndNxt, una: c.rcvNxt, data: msg}.marshal()
	c.pending = append(c.pending, pendingSegment{sn: c.sndNxt, raw: raw, sentAt: time.Now(), transmits: 1})
	c.sndNxt++
	c.mutex.Unlock()
	c.transmit(raw)
	return nil
}

// tick retransmits what the camera has not acknowledged in time.
func (c *conversation) tick(now time.Time) error {
	c.mutex.Lock()
	var resend [][]byte
	for i := range c.pending {
		p := &c.pending[i]
		if now.Sub(p.sentAt) < kcpRetransmitAfter {
			continue
		}
		if p.transmits >= kcpMaxTransmits {
			c.mutex.Unlock()
			return errKcpGaveUp
		}
		p.transmits++
		p.sentAt = now
		resend = append(resend, p.raw)
	}
	c.mutex.Unlock()
	for _, raw := range resend {
		c.transmit(raw)
	}
	return nil
}
