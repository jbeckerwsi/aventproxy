package imm

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// buildOffer returns the SDP the app offers. The ICE credentials and the AES
// key must be the server-minted ones from the config's p2pConfig.session: the
// camera does not answer an offer carrying the client's own.
func buildOffer(uid, sessionID, iceUfrag, icePassword, aesKeyHex string, epoch int64) string {
	lines := []string{
		"v=0",
		fmt.Sprintf("o=- %d 1 IN IP4 127.0.0.1", epoch),
		"s=-",
		"t=0 0",
		"a=group:BUNDLE imm0",
		"a=msid-semantic: WMS " + sessionID,
		"m=application 9 imm 6001",
		"c=IN IP4 0.0.0.0",
		"a=rtcp:9 IN IP4 0.0.0.0",
		"a=ice-ufrag:" + iceUfrag,
		"a=ice-pwd:" + icePassword,
		"a=ice-options:trickle",
		"a=aes-key:" + aesKeyHex,
		"a=mid:imm0",
		"a=rtpmap:6001 AES/KCP 330",
		"a=ssrc:0 cname:" + uid,
		"",
	}
	return strings.Join(lines, "\r\n")
}

type answer struct {
	iceUfrag    string
	icePassword string
	aesKey      []byte
}

func parseAnswer(sdp string) (answer, error) {
	var a answer
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "a=ice-ufrag:"):
			a.iceUfrag = strings.TrimPrefix(line, "a=ice-ufrag:")
		case strings.HasPrefix(line, "a=ice-pwd:"):
			a.icePassword = strings.TrimPrefix(line, "a=ice-pwd:")
		case strings.HasPrefix(line, "a=aes-key:"):
			key, err := hex.DecodeString(strings.TrimPrefix(line, "a=aes-key:"))
			if err == nil && len(key) >= 16 {
				a.aesKey = key[:16]
			}
		}
	}
	if a.iceUfrag == "" || a.icePassword == "" {
		return a, errors.New("answer has no ICE credentials")
	}
	return a, nil
}

// candidate is a remote ICE candidate as the camera trickles it:
// "a=candidate:<foundation> 1 UDP <prio> <ip> <port> typ <type>[ ...]\r\n".
type candidate struct {
	ip   string
	port int
	typ  string
}

func parseCandidate(line string) (candidate, bool) {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "a=")
	line = strings.TrimPrefix(line, "candidate:")
	f := strings.Fields(line)
	if len(f) < 8 || !strings.EqualFold(f[2], "udp") || f[6] != "typ" || strings.Contains(f[4], ":") {
		return candidate{}, false
	}
	var port int
	if _, err := fmt.Sscanf(f[5], "%d", &port); err != nil || port <= 0 || port > 65535 {
		return candidate{}, false
	}
	return candidate{ip: f[4], port: port, typ: f[7]}, true
}

func hostCandidateLine(ip string, port int, foundation uint32) string {
	return fmt.Sprintf("a=candidate:%d 1 udp 2130706431 %s %d typ host\r\n", foundation, ip, port)
}
