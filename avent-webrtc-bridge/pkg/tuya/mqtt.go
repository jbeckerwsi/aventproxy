package tuya

import (
	"avent-webrtc-bridge/pkg/core"
	"avent-webrtc-bridge/pkg/utils"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type MQTTClient struct {
	mqtt           mqtt.Client
	uid            string
	subscribeTopic string
	cameras        map[string]*MQTTCameraClient // sessionId -> camera
	closed         bool
	Connected      utils.Waiter

	rawMutex    sync.Mutex
	rawHandlers map[string]map[int]func([]byte) // topic -> handler id -> handler
	rawNextID   int
}

type MqttFrameHeader struct {
	Type          string `json:"type"`
	From          string `json:"from"`
	To            string `json:"to"`
	SubDevID      string `json:"sub_dev_id"`
	SessionID     string `json:"sessionid"`
	MotoID        string `json:"moto_id"`
	TransactionID string `json:"tid"`
	Seq           int    `json:"seq"`
	Rtx           int    `json:"rtx"`
}

type MqttFrame struct {
	Header  MqttFrameHeader `json:"header"`
	Message json.RawMessage `json:"msg"`
}

type MqttMessage struct {
	Protocol int       `json:"protocol"`
	Pv       string    `json:"pv"`
	T        int64     `json:"t"`
	Data     MqttFrame `json:"data"`
}

func NewMqttClient(clientId, mobileMqttsUrl string, mqttConfig *MQTConfig) (*MQTTClient, error) {
	client := &MQTTClient{
		uid:            mqttConfig.Msid,
		subscribeTopic: fmt.Sprintf("/av/u/%s", mqttConfig.Msid),
		Connected:      utils.Waiter{},
	}

	wssUrl := fmt.Sprintf("wss://%s/mqtt", mobileMqttsUrl)
	username := fmt.Sprintf("web_%s", mqttConfig.Msid)
	password := mqttConfig.Password

	opts := mqtt.NewClientOptions()
	opts.AddBroker(wssUrl)
	opts.SetClientID(username)
	opts.SetUsername(username)
	opts.SetPassword(password)
	opts.SetOnConnectHandler(client.onConnect)
	opts.SetConnectionLostHandler(client.onDisconnect)
	opts.SetAutoReconnect(false)
	opts.SetConnectTimeout(10 * time.Second)
	opts.SetKeepAlive(60 * time.Second)
	opts.SetCleanSession(true)

	client.mqtt = mqtt.NewClient(opts)
	if token := client.mqtt.Connect(); token.Wait() && token.Error() != nil {
		return nil, token.Error()
	}

	return client, nil
}

type MobileMQTTConfig struct {
	Username       string
	Password       string
	ClientID       string
	SubscribeTopic string
	UID            string
	BrokerURL      string
}

func NewMobileMqttClient(config *MobileMQTTConfig) (*MQTTClient, error) {
	client := &MQTTClient{
		uid:            config.UID,
		subscribeTopic: config.SubscribeTopic,
		Connected:      utils.Waiter{},
	}

	opts := mqtt.NewClientOptions()
	opts.AddBroker(config.BrokerURL)
	opts.SetClientID(config.ClientID)
	opts.SetUsername(config.Username)
	opts.SetPassword(config.Password)
	opts.SetOnConnectHandler(client.onConnect)
	opts.SetConnectionLostHandler(client.onDisconnect)
	opts.SetAutoReconnect(false)
	opts.SetConnectTimeout(10 * time.Second)
	opts.SetKeepAlive(60 * time.Second)
	opts.SetCleanSession(true)

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	opts.SetTLSConfig(tlsConfig)

	client.mqtt = mqtt.NewClient(opts)
	if token := client.mqtt.Connect(); token.Wait() && token.Error() != nil {
		return nil, token.Error()
	}

	return client, nil
}

func (c *MQTTClient) Stop() {
	if c.mqtt != nil {
		c.mqtt.Disconnect(250)
		c.closed = true
	}
}

func (c *MQTTClient) IsConnected() bool {
	return c.mqtt != nil && c.mqtt.IsConnected() && !c.closed
}

func (c *MQTTClient) AddCameraClient(sessionId string, cameraClient *MQTTCameraClient) {
	if c.cameras == nil {
		c.cameras = make(map[string]*MQTTCameraClient)
	}
	c.cameras[sessionId] = cameraClient
}

func (c *MQTTClient) RemoveCameraClient(sessionId string) {
	if c.cameras == nil {
		return
	}
	delete(c.cameras, sessionId)
}

// UID is the account uid the client signs signaling messages with.
func (c *MQTTClient) UID() string {
	return c.uid
}

// Subscribe adds a raw subscription next to the WebRTC one and returns a
// function that removes it again. The imm transport signals on a per-device
// topic with a binary payload, which the JSON consumer cannot parse, so it
// brings its own handler. Several handlers may share a topic (two streams of
// one camera); each filters by its own session id.
func (c *MQTTClient) Subscribe(topic string, handler func(payload []byte)) (func(), error) {
	if c.closed {
		return nil, errors.New("mqtt client is closed")
	}
	c.rawMutex.Lock()
	defer c.rawMutex.Unlock()
	if c.rawHandlers == nil {
		c.rawHandlers = make(map[string]map[int]func([]byte))
	}
	if _, subscribed := c.rawHandlers[topic]; !subscribed {
		token := c.mqtt.Subscribe(topic, 1, func(_ mqtt.Client, msg mqtt.Message) {
			c.rawMutex.Lock()
			handlers := make([]func([]byte), 0, len(c.rawHandlers[topic]))
			for _, h := range c.rawHandlers[topic] {
				handlers = append(handlers, h)
			}
			c.rawMutex.Unlock()
			for _, h := range handlers {
				h(msg.Payload())
			}
		})
		if token.Wait() && token.Error() != nil {
			return nil, token.Error()
		}
		c.rawHandlers[topic] = make(map[int]func([]byte))
	}
	c.rawNextID++
	id := c.rawNextID
	c.rawHandlers[topic][id] = handler

	return func() {
		c.rawMutex.Lock()
		defer c.rawMutex.Unlock()
		delete(c.rawHandlers[topic], id)
		if len(c.rawHandlers[topic]) == 0 {
			delete(c.rawHandlers, topic)
			if !c.closed && c.mqtt != nil {
				c.mqtt.Unsubscribe(topic)
			}
		}
	}, nil
}

func (c *MQTTClient) Publish(topic string, payload []byte) error {
	if c.closed {
		return errors.New("mqtt client is closed")
	}
	token := c.mqtt.Publish(topic, 1, false, payload)
	token.Wait()
	return token.Error()
}

func (c *MQTTClient) onConnect(client mqtt.Client) {
	core.Logger.Trace().Msgf("Connected to mqtt broker")
	core.Logger.Trace().Msgf("Subscribing to topic: %s", c.subscribeTopic)

	if token := client.Subscribe(c.subscribeTopic, 1, c.consume); token.Wait() && token.Error() != nil {
		c.Connected.Done(token.Error())
		return
	}

	core.Logger.Trace().Msgf("Subscribed")
	c.Connected.Done(nil)
}

func (c *MQTTClient) onDisconnect(client mqtt.Client, err error) {
	if err != nil {
		c.Connected.Done(err)
	} else {
		c.Connected.Done(errors.New("mqtt client disconnected"))
	}

	c.closed = true
}

func (c *MQTTClient) consume(client mqtt.Client, msg mqtt.Message) {
	var rmqtt MqttMessage
	if err := json.Unmarshal(msg.Payload(), &rmqtt); err != nil {
		core.Logger.Error().Err(err).Msg("Failed to unmarshal mqtt message: %s")
		return
	}

	sessionId := rmqtt.Data.Header.SessionID
	cameraClient, ok := c.cameras[sessionId]
	if !ok {
		core.Logger.Warn().Msgf("No camera client found for sessionId: %s", sessionId)
		return
	}

	switch rmqtt.Data.Header.Type {
	case "answer":
		cameraClient.onMqttAnswer(&rmqtt)
	case "candidate":
		cameraClient.onMqttCandidate(&rmqtt)
	case "disconnect":
		cameraClient.onMqttDisconnect()
	}
}
