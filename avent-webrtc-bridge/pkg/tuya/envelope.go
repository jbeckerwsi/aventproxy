package tuya

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
)

// The binary envelope the app's per-device signaling topics carry
// (smart/mb/out/<devId> and smart/mb/in/<devId>):
//
//	"2.2" | crc32(rest) BE | seq BE | source[4] | AES-128-ECB(localKey, PKCS#7(json))
//
// The CRC covers everything after the CRC field. The JSON is
// {"data": {...}, "protocol": N, "t": <unix seconds>}.
const (
	envelopeVersion  = "2.2"
	envelopeHeader   = 15
	envelopeSourceSz = 4
)

type envelopeBody struct {
	Data     json.RawMessage `json:"data"`
	Protocol int             `json:"protocol"`
	T        int64           `json:"t"`
}

// EncodeEnvelope serializes, encrypts and frames one signaling payload.
func EncodeEnvelope(localKey []byte, seq uint32, source []byte, protocol int, t int64, data any) ([]byte, error) {
	rawData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(envelopeBody{Data: rawData, Protocol: protocol, T: t})
	if err != nil {
		return nil, err
	}
	body, err := ecbEncrypt(localKey, plain)
	if err != nil {
		return nil, err
	}
	tail := make([]byte, 0, 8+len(body))
	tail = binary.BigEndian.AppendUint32(tail, seq)
	src := make([]byte, envelopeSourceSz)
	copy(src, source)
	tail = append(tail, src...)
	tail = append(tail, body...)

	out := []byte(envelopeVersion)
	out = binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(tail))
	return append(out, tail...), nil
}

// DecodeEnvelope verifies and decrypts one payload, returning its protocol and data.
func DecodeEnvelope(localKey []byte, payload []byte) (int, json.RawMessage, error) {
	if len(payload) < envelopeHeader || string(payload[:3]) != envelopeVersion {
		return 0, nil, errors.New("not a 2.2 envelope")
	}
	if want, got := binary.BigEndian.Uint32(payload[3:7]), crc32.ChecksumIEEE(payload[7:]); want != got {
		return 0, nil, fmt.Errorf("envelope crc %08x, want %08x", got, want)
	}
	plain, err := ecbDecrypt(localKey, payload[envelopeHeader:])
	if err != nil {
		return 0, nil, err
	}
	var body envelopeBody
	if err := json.Unmarshal(plain, &body); err != nil {
		return 0, nil, err
	}
	return body.Protocol, body.Data, nil
}

func ecbEncrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	buf := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	for i := 0; i < len(buf); i += aes.BlockSize {
		block.Encrypt(buf[i:i+aes.BlockSize], buf[i:i+aes.BlockSize])
	}
	return buf, nil
}

func ecbDecrypt(key, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("envelope body is not whole AES blocks")
	}
	out := make([]byte, len(ct))
	for i := 0; i < len(ct); i += aes.BlockSize {
		block.Decrypt(out[i:i+aes.BlockSize], ct[i:i+aes.BlockSize])
	}
	pad := int(out[len(out)-1])
	if pad < 1 || pad > aes.BlockSize || !bytes.Equal(out[len(out)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, errors.New("bad envelope padding")
	}
	return out[:len(out)-pad], nil
}
