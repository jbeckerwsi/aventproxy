package imm

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
)

// Channel 0 carries a login record followed by commands. Every field is a
// little-endian u32 and every message starts with this mark.
const controlMark = 0x12345678

// Command ids (high_cmd) and IO_CTRL_VIDEO operations used for live view.
const (
	cmdProtocolVersion = 10
	cmdIOCtrlVideo     = 6

	opVideoPlay = 0
	opAudioOn   = 4
)

// The ids the app uses; the camera echoes them in responses and stamps media
// units with the play/audio ones.
const (
	reqIDVersion   = 0
	reqIDPlay      = 0x00010003
	reqIDAudioOn   = 0x00010005
	clarityDefault = 0
)

// loginRecord is the 104-byte P2P_CMD_PASSWD record: mark, request id,
// user "admin" and hex(md5(password + "||" + localKey)) in a 64-byte field.
func loginRecord(password, localKey string) []byte {
	sum := md5.Sum([]byte(password + "||" + localKey))
	rec := make([]byte, 104)
	binary.LittleEndian.PutUint32(rec[0:], controlMark)
	binary.LittleEndian.PutUint32(rec[4:], 1)
	copy(rec[8:40], "admin")
	copy(rec[40:104], hex.EncodeToString(sum[:]))
	return rec
}

// command builds one request: mark, reqId, type 0, high_cmd, low_cmd, length, payload.
func command(reqID uint32, high, low uint16, args ...uint32) []byte {
	b := make([]byte, 20, 20+4*len(args))
	binary.LittleEndian.PutUint32(b[0:], controlMark)
	binary.LittleEndian.PutUint32(b[4:], reqID)
	binary.LittleEndian.PutUint16(b[12:], high)
	binary.LittleEndian.PutUint16(b[14:], low)
	binary.LittleEndian.PutUint32(b[16:], uint32(4*len(args)))
	for _, a := range args {
		b = binary.LittleEndian.AppendUint32(b, a)
	}
	return b
}

// startSequence is what releases live media: login, protocol version, play,
// and optionally camera audio. Clarity is deliberately not sent: it changes
// the camera's shared encoder state for every viewer, including the phone app.
func startSequence(password, localKey string, audio bool) [][]byte {
	seq := [][]byte{
		loginRecord(password, localKey),
		command(reqIDVersion, cmdProtocolVersion, 0, 0x00010001),
		command(reqIDPlay, cmdIOCtrlVideo, opVideoPlay, clarityDefault, opVideoPlay),
	}
	if audio {
		seq = append(seq, command(reqIDAudioOn, cmdIOCtrlVideo, opAudioOn, 0, opAudioOn))
	}
	return seq
}
