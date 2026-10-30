// Package imm implements Tuya's proprietary "imm" P2P transport, which cameras
// such as the Philips Avent SCD860 use instead of WebRTC (issue #59).
//
// After an offer/answer over MQTT the camera, as ICE controlling agent,
// nominates a UDP path. Every datagram on it is one or more KCP segments of a
// single conversation followed by HMAC-SHA1 over them (security level 3). KCP
// payloads are records: a random IV and AES-128-CBC with PKCS#7 padding.
// Conversation 0 carries login and commands, 1 video and 2 audio.
package imm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"errors"
)

const tagSize = sha1.Size

// encryptRecord builds one record: a fresh IV followed by the CBC ciphertext.
func encryptRecord(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	out := make([]byte, aes.BlockSize, aes.BlockSize+len(plain)+pad)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	out = append(out, plain...)
	out = append(out, bytes.Repeat([]byte{byte(pad)}, pad)...)
	cipher.NewCBCEncrypter(block, out[:aes.BlockSize]).CryptBlocks(out[aes.BlockSize:], out[aes.BlockSize:])
	return out, nil
}

// decryptRecord reverses encryptRecord. fullPad reports a whole block of
// padding, which a wrong key produces with negligible probability; the caller
// uses it to settle which key the camera encrypts with.
func decryptRecord(key, record []byte) (plain []byte, fullPad bool, err error) {
	if len(record) < 2*aes.BlockSize || len(record)%aes.BlockSize != 0 {
		return nil, false, errors.New("record is not an IV plus whole AES blocks")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false, err
	}
	out := make([]byte, len(record)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, record[:aes.BlockSize]).CryptBlocks(out, record[aes.BlockSize:])
	pad := int(out[len(out)-1])
	if pad < 1 || pad > aes.BlockSize || !bytes.Equal(out[len(out)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, false, errors.New("bad record padding")
	}
	return out[:len(out)-pad], pad == aes.BlockSize, nil
}

// tag is the per-datagram HMAC-SHA1 of security level 3.
func tag(key, kcpBytes []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(kcpBytes)
	return mac.Sum(nil)
}

func tagValid(key, datagram []byte) bool {
	if len(datagram) < tagSize {
		return false
	}
	body := datagram[:len(datagram)-tagSize]
	return hmac.Equal(tag(key, body), datagram[len(datagram)-tagSize:])
}
