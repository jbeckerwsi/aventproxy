package tuya

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"avent-webrtc-bridge/pkg/core"
)

// Signaling protocols on the per-device topics.
const (
	immProtocolSigQuery = 22
	immProtocolSession  = 302
)

// ImmSignalingClient carries the offer/answer/candidate exchange for cameras on
// the imm transport. Unlike WebRTC signaling (JSON on /av/moto/...), the camera
// only answers imm offers on smart/mb/out/<devId>, wrapped in the binary 2.2
// envelope under its local key; replies arrive on smart/mb/in/<devId>.
type ImmSignalingClient struct {
	mqtt      *MQTTClient
	localKey  []byte
	deviceID  string
	sessionID string
	source    []byte

	mutex       sync.Mutex
	seq         uint32
	unsubscribe func()

	HandleAnswer     func(sdp string)
	HandleCandidate  func(candidate string)
	HandleDisconnect func(closeReason int)
}

type immHeader struct {
	Type          string `json:"type"`
	From          string `json:"from"`
	To            string `json:"to"`
	SessionID     string `json:"sessionid"`
	MotoID        string `json:"moto_id"`
	Path          string `json:"path"`
	TraceID       string `json:"trace_id,omitempty"`
	IsPre         *int   `json:"is_pre,omitempty"`
	P2PSkill      int    `json:"p2p_skill,omitempty"`
	SecurityLevel int    `json:"security_level,omitempty"`
}

type immFrame struct {
	Header immHeader       `json:"header"`
	Msg    json.RawMessage `json:"msg"`
}

func NewImmSignalingClient(mqttClient *MQTTClient, deviceID, localKey, sessionID string) *ImmSignalingClient {
	source := make([]byte, 4)
	_, _ = rand.Read(source)
	return &ImmSignalingClient{
		mqtt:      mqttClient,
		localKey:  []byte(localKey),
		deviceID:  deviceID,
		sessionID: sessionID,
		source:    source,
	}
}

// SetHandlers installs the callbacks for the camera's answer, its trickled
// candidates and a disconnect. Call before Start.
func (c *ImmSignalingClient) SetHandlers(onAnswer func(sdp string), onCandidate func(candidate string), onDisconnect func(closeReason int)) {
	c.HandleAnswer = onAnswer
	c.HandleCandidate = onCandidate
	c.HandleDisconnect = onDisconnect
}

// Start subscribes to the camera's reply topic.
func (c *ImmSignalingClient) Start() error {
	unsubscribe, err := c.mqtt.Subscribe(fmt.Sprintf("smart/mb/in/%s", c.deviceID), c.consume)
	if err != nil {
		return err
	}
	c.unsubscribe = unsubscribe
	return nil
}

func (c *ImmSignalingClient) Stop() {
	if c.unsubscribe != nil {
		c.unsubscribe()
		c.unsubscribe = nil
	}
}

func (c *ImmSignalingClient) consume(payload []byte) {
	protocol, data, err := DecodeEnvelope(c.localKey, payload)
	if err != nil {
		core.Logger.Trace().Err(err).Msg("Discarded an undecodable imm signaling payload")
		return
	}
	if protocol != immProtocolSession {
		return
	}
	var frame immFrame
	if err := json.Unmarshal(data, &frame); err != nil || frame.Header.SessionID != c.sessionID {
		return
	}
	var msg struct {
		Sdp         string `json:"sdp"`
		Candidate   string `json:"candidate"`
		CloseReason int    `json:"close_reason"`
	}
	_ = json.Unmarshal(frame.Msg, &msg)

	switch frame.Header.Type {
	case "answer":
		if c.HandleAnswer != nil && msg.Sdp != "" {
			c.HandleAnswer(msg.Sdp)
		}
	case "candidate":
		if c.HandleCandidate != nil && msg.Candidate != "" {
			c.HandleCandidate(msg.Candidate)
		}
	case "disconnect":
		if c.HandleDisconnect != nil {
			c.HandleDisconnect(msg.CloseReason)
		}
	}
}

// SendSigQuery is the signal query the app sends ahead of an offer.
func (c *ImmSignalingClient) SendSigQuery() error {
	return c.publish(immProtocolSigQuery, map[string]string{"reqType": "sigQry"})
}

// SendOffer publishes the imm offer. The header fields mirror the app's: a
// security level of 3 selects the per-datagram HMAC the transport implements.
func (c *ImmSignalingClient) SendOffer(sdp, traceID string, ices []ICEServer, tcpRelay, logConfig json.RawMessage) error {
	isPre := 0
	header := c.header("offer")
	header.TraceID = traceID
	header.IsPre = &isPre
	header.P2PSkill = 1635
	header.SecurityLevel = 3

	msg := map[string]any{"sdp": sdp, "preconnect": true, "token": ices}
	if len(tcpRelay) > 0 {
		msg["tcp_token"] = tcpRelay
	}
	if len(logConfig) > 0 {
		msg["log"] = logConfig
	}
	return c.sendFrame(header, msg)
}

func (c *ImmSignalingClient) SendCandidate(candidate string) error {
	return c.sendFrame(c.header("candidate"), map[string]string{"candidate": candidate})
}

// SendDisconnect releases the camera's session. Without it the camera keeps the
// session until its own timer fires.
func (c *ImmSignalingClient) SendDisconnect() error {
	return c.sendFrame(c.header("disconnect"), map[string]int{"close_reason": 4, "close_reason_local": 0})
}

func (c *ImmSignalingClient) header(kind string) immHeader {
	return immHeader{
		Type:      kind,
		From:      c.mqtt.UID(),
		To:        c.deviceID,
		SessionID: c.sessionID,
		Path:      "mqtt",
	}
}

func (c *ImmSignalingClient) sendFrame(header immHeader, msg any) error {
	rawMsg, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return c.publish(immProtocolSession, immFrame{Header: header, Msg: rawMsg})
}

func (c *ImmSignalingClient) publish(protocol int, data any) error {
	c.mutex.Lock()
	c.seq++
	seq := c.seq
	c.mutex.Unlock()

	payload, err := EncodeEnvelope(c.localKey, seq, c.source, protocol, time.Now().Unix(), data)
	if err != nil {
		return err
	}
	return c.mqtt.Publish(fmt.Sprintf("smart/mb/out/%s", c.deviceID), payload)
}
