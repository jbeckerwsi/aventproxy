package imm

import (
	"encoding/binary"

	"github.com/pion/rtp"
)

// Video and audio channels carry a byte stream of media units, independent of
// record boundaries:
//
//	request_id u32 | reserved u32 | time_ms u64 | ext_len i32 | reserved u32
//	extension[ext_len]  (8 bytes: type 1 = video I-frame params, 2 = audio params)
//	rtp_len u32 | RTP packet
//
// all little-endian except the RTP packet itself.

const (
	unitHeaderSize = 24
	maxRTPSize     = 4096 // the camera keeps RTP packets under its MTU

	rtpPayloadPCM = 99 // raw 16-bit little-endian PCM, 8 kHz mono on the SCD860
	h264NALAUD    = 9
)

type mediaUnit struct {
	timeMs uint64
	rtp    []byte
}

type unitParser struct {
	buf     []byte
	resyncs int
}

func (p *unitParser) feed(data []byte) []mediaUnit {
	p.buf = append(p.buf, data...)
	var out []mediaUnit
	for len(p.buf) >= unitHeaderSize+4 {
		extLen := int32(binary.LittleEndian.Uint32(p.buf[16:]))
		// Both reserved words are zero; checking them keeps a misaligned
		// header from passing as a plausible length.
		if (extLen != 0 && extLen != 8) || binary.LittleEndian.Uint32(p.buf[4:]) != 0 ||
			binary.LittleEndian.Uint32(p.buf[20:]) != 0 {
			p.resync()
			continue
		}
		hdr := unitHeaderSize + int(extLen)
		if len(p.buf) < hdr+4 {
			break
		}
		rtpLen := int(binary.LittleEndian.Uint32(p.buf[hdr:]))
		if rtpLen < 12 || rtpLen > maxRTPSize {
			p.resync()
			continue
		}
		// Check the RTP version as soon as its byte is here, before waiting
		// for a length that may come from a misaligned header.
		if len(p.buf) > hdr+4 && p.buf[hdr+4]>>6 != 2 {
			p.resync()
			continue
		}
		if len(p.buf) < hdr+4+rtpLen {
			break
		}
		out = append(out, mediaUnit{
			timeMs: binary.LittleEndian.Uint64(p.buf[8:]),
			rtp:    append([]byte(nil), p.buf[hdr+4:hdr+4+rtpLen]...),
		})
		p.buf = p.buf[hdr+4+rtpLen:]
	}
	return out
}

func (p *unitParser) resync() {
	p.resyncs++
	p.buf = p.buf[1:]
}

// videoUnpacker turns the camera's H.264 RTP into packets for the forwarder.
type videoUnpacker struct {
	seq uint16
}

// packet returns the forwardable packet for one unit, or nil to drop it.
//
// Two quirks of the camera are corrected here. It sets the RTP X bit on
// P-frame packets without carrying a header extension, which a standard
// parser would read into the payload. And it sends an access unit delimiter
// with the marker bit set ahead of every frame, which would end the frame in
// the forwarder's frame clock before its slices arrive. Delimiters carry no
// picture data, so they are dropped and the sequence is renumbered.
func (u *videoUnpacker) packet(raw []byte) *rtp.Packet {
	raw[0] &^= 0x10
	pkt := &rtp.Packet{}
	if err := pkt.Unmarshal(raw); err != nil || len(pkt.Payload) == 0 {
		return nil
	}
	if pkt.Payload[0]&0x1f == h264NALAUD {
		return nil
	}
	pkt.SequenceNumber = u.seq
	u.seq++
	return pkt
}

// audioPacker converts the camera's 16-bit PCM to G.711 µ-law, the codec the
// RTSP side advertises when a camera reports no audio skill.
type audioPacker struct {
	seq uint16
	ts  uint32
}

func (a *audioPacker) packet(raw []byte) *rtp.Packet {
	pkt := &rtp.Packet{}
	if err := pkt.Unmarshal(raw); err != nil || pkt.PayloadType != rtpPayloadPCM {
		return nil
	}
	samples := len(pkt.Payload) / 2
	payload := make([]byte, samples)
	for i := 0; i < samples; i++ {
		payload[i] = linearToMulaw(int16(binary.LittleEndian.Uint16(pkt.Payload[2*i:])))
	}
	out := &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    0,
			SequenceNumber: a.seq,
			Timestamp:      a.ts,
			SSRC:           pkt.SSRC,
		},
		Payload: payload,
	}
	a.seq++
	a.ts += uint32(samples)
	return out
}

// linearToMulaw is the ITU-T G.711 µ-law encoder.
func linearToMulaw(sample int16) byte {
	const bias = 0x84
	const clip = 32635
	s := int(sample)
	sign := 0
	if s < 0 {
		s = -s
		sign = 0x80
	}
	if s > clip {
		s = clip
	}
	s += bias
	exponent := 7
	for mask := 0x4000; s&mask == 0 && exponent > 0; mask >>= 1 {
		exponent--
	}
	mantissa := (s >> (exponent + 3)) & 0x0f
	return ^byte(sign | exponent<<4 | mantissa)
}
