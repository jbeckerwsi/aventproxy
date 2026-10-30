package tuya

import (
	"encoding/json"
	"testing"
)

// scd860RTCConfig has the shape of smartlife.m.rtc.config.get for an SCD860
// (#59), with every credential replaced.
const scd860RTCConfig = `{
  "audioAttributes": {"callMode": [1, 2], "hardwareCapability": [1, 2]},
  "auth": "redacted",
  "id": "bf00000000000000000000",
  "motoId": "signaling00000",
  "p2pConfig": {
    "auth": "redacted",
    "ices": [{"urls": "stun:192.0.2.1:3478"}, {"urls": "turn:192.0.2.1:3478", "username": "u", "credential": "c", "ttl": 3600}],
    "log": {"api": "thing.m.rtc.log", "interval": 60, "level": 2},
    "motoId": "signaling00000",
    "preconnect": true,
    "session": {
      "aesKey": "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
      "devId": "bf00000000000000000000",
      "iceUfrag": "abcd",
      "icePassword": "redacted",
      "sessionId": "bf000000000000000000001793389571AbCdEfGh",
      "traceId": "8f466005d49a11f1b48ca20535d9a5f0"
    },
    "tcpRelay": {"credential": "c", "sessionId": "s", "urls": ["tcp4:192.0.2.2:1443"], "username": "1793425571:bf00000000000000000000"},
    "transmission": "kcp"
  },
  "password": "redacted",
  "skill": "{\"localStorage\":1,\"sdk_version\":\"4.5.1\",\"video_num\":2}",
  "supportsWebrtc": false,
  "vedioClarity": 4,
  "vedioClaritys": [2, 4]
}`

// A WebRTC camera's config: supportsWebrtc and no kcp transmission.
const webrtcRTCConfig = `{
  "auth": "redacted",
  "motoId": "signaling00000",
  "p2pConfig": {"auth": "redacted", "ices": [{"urls": "stun:192.0.2.1:3478"}], "motoId": "signaling00000"},
  "skill": "{\"webrtc\":3,\"videos\":[{\"streamType\":2,\"codecType\":2,\"width\":1920,\"height\":1080}]}",
  "supportsWebrtc": true
}`

func parseConfig(t *testing.T, raw string) WebRTCConfig {
	t.Helper()
	var c WebRTCConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUsesImmOnSCD860Config(t *testing.T) {
	c := parseConfig(t, scd860RTCConfig)
	if !c.UsesImm() {
		t.Fatal("the SCD860 config must select the imm transport")
	}
	s := c.P2PConfig.Session
	if s.SessionId == "" || s.AesKey == "" || s.IceUfrag == "" || s.IcePassword == "" || s.TraceId == "" {
		t.Fatalf("session not parsed: %+v", s)
	}
	if c.Password != "redacted" || len(c.P2PConfig.TcpRelay) == 0 || len(c.P2PConfig.Log) == 0 {
		t.Fatal("password, tcpRelay and log must be carried for the offer and login")
	}
}

func TestWebRTCConfigStaysOnWebRTC(t *testing.T) {
	webrtc := parseConfig(t, webrtcRTCConfig)
	if webrtc.UsesImm() {
		t.Fatal("a WebRTC camera must not be switched to imm")
	}
	// kcp without a minted session cannot be streamed; stay on the old path
	// rather than failing differently.
	c := parseConfig(t, scd860RTCConfig)
	c.P2PConfig.Session = nil
	if c.UsesImm() {
		t.Fatal("imm without a session must not be selected")
	}
}

func TestICEServersStillMarshalForWebRTC(t *testing.T) {
	// setupPeerConnection marshals P2PConfig.Ices; the new fields must not leak into it.
	c := parseConfig(t, scd860RTCConfig)
	raw, err := json.Marshal(c.P2PConfig.Ices)
	if err != nil {
		t.Fatal(err)
	}
	var back []ICEServer
	if err := json.Unmarshal(raw, &back); err != nil || len(back) != 2 || back[1].Username != "u" {
		t.Fatalf("ices round trip: %s", raw)
	}
}
