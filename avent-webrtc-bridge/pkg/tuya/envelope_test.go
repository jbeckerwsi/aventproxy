package tuya

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// pythonEnvelope was produced by tuya-ipc-p2p-sdk's encode_payload, whose
// output a real SCD860 answers, with key "0123456789abcdef", seq 7, source
// 01020304, protocol 302, t 1793390000.
const pythonEnvelope = "322e32edb6327800000007010203046d91e50bf1cc7865a74577284a9ee9a338a37bc05c4e339cefa0b4c1d7f9545970fea839e5cd60a4a5b5c7818cc8c301eb5de1d534121ebf8ce93b307b7d1443072abc7d2712ac30d912d7f58d3a026cc886feabe0fe819470ffcb8213f344b38b9723fe2e109e60ef74108deea49031"

func TestDecodeEnvelopeFromReference(t *testing.T) {
	payload, _ := hex.DecodeString(pythonEnvelope)
	protocol, data, err := DecodeEnvelope([]byte("0123456789abcdef"), payload)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != 302 {
		t.Fatalf("protocol = %d, want 302", protocol)
	}
	var frame struct {
		Header struct {
			Type      string `json:"type"`
			SessionID string `json:"sessionid"`
		} `json:"header"`
		Msg struct {
			Sdp string `json:"sdp"`
		} `json:"msg"`
	}
	if err := json.Unmarshal(data, &frame); err != nil {
		t.Fatal(err)
	}
	if frame.Header.Type != "answer" || frame.Header.SessionID != "s1" || frame.Msg.Sdp != "v=0" {
		t.Fatalf("decoded %+v", frame)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	key := []byte("fedcba9876543210")
	data := map[string]any{"reqType": "sigQry"}
	payload, err := EncodeEnvelope(key, 3, []byte{9, 9, 9, 9}, 22, 1700000000, data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(payload, []byte("2.2")) {
		t.Fatalf("missing version prefix: %x", payload[:3])
	}
	protocol, raw, err := DecodeEnvelope(key, payload)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != 22 || string(raw) != `{"reqType":"sigQry"}` {
		t.Fatalf("got protocol %d data %s", protocol, raw)
	}
}

func TestDecodeEnvelopeRejectsCorruption(t *testing.T) {
	payload, _ := hex.DecodeString(pythonEnvelope)
	payload[len(payload)-1] ^= 0xff
	if _, _, err := DecodeEnvelope([]byte("0123456789abcdef"), payload); err == nil {
		t.Fatal("corrupted envelope decoded without error")
	}
}
