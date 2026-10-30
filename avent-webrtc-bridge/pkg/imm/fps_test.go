package imm

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

const (
	fullRate = 33 * time.Millisecond
	idleRate = 92 * time.Millisecond // the SCD860's idle encoder rate, ~10.8 fps
)

func feed(g *fpsGuard, interval time.Duration, n int) (fired int) {
	for i := 0; i < n; i++ {
		if g.observe(interval) {
			fired++
		}
	}
	return fired
}

func TestFPSGuardIgnoresFullRate(t *testing.T) {
	if feed(newFPSGuard(), fullRate, 500) != 0 {
		t.Fatal("restarted a camera running at full rate")
	}
}

func TestFPSGuardLeavesASlowStartAlone(t *testing.T) {
	// Slow from the start (low light, or a state a restart does not fix).
	if feed(newFPSGuard(), idleRate, 500) != 0 {
		t.Fatal("restarted a camera that never ran at full rate")
	}
}

func TestFPSGuardRestartsOncePerFall(t *testing.T) {
	g := newFPSGuard()
	feed(g, fullRate, 50)
	if feed(g, idleRate, 12) != 1 {
		t.Fatal("did not restart after falling from full rate to idle")
	}
	// The restart did not help: no loop.
	if feed(g, idleRate, 500) != 0 {
		t.Fatal("restarted again while still slow")
	}
	// Full rate again re-arms; the next fall restarts again.
	feed(g, fullRate, 50)
	if feed(g, idleRate, 12) != 1 {
		t.Fatal("did not re-arm after full rate came back")
	}
}

func TestFPSGuardIgnoresClockJumps(t *testing.T) {
	g := newFPSGuard()
	for i := 0; i < 50; i++ {
		g.observe(fullRate)
		if g.observe(-700*time.Millisecond) || g.observe(5*time.Second) {
			t.Fatal("an out-of-range interval caused a restart")
		}
	}
}

func TestRestartSequenceBytes(t *testing.T) {
	stop, _ := hex.DecodeString("78563412060001000000000006000300080000000000000003000000")
	play, _ := hex.DecodeString("78563412030001000000000006000000080000000000000000000000")
	seq := restartSequence()
	if len(seq) != 2 || !bytes.Equal(seq[0], stop) || !bytes.Equal(seq[1], play) {
		t.Fatalf("restart sequence\n got %x\nwant %x %x", seq, stop, play)
	}
}

func TestSessionRestartsLiveVideoWhenTheCameraSlowsDown(t *testing.T) {
	s := NewSession(Config{}, &fakeSignaling{})
	defer s.cancel()
	s.offerKey = testKey
	s.restartGap = time.Millisecond
	s.fps = newFPSGuard()

	sent := make(chan []byte, 8)
	s.convs[convControl] = newConversation(convControl, func(raw []byte) { sent <- raw }, func([]byte) {})

	ts := uint32(1_000_000)
	for i := 0; i < 30; i++ { // full rate first, which arms the guard
		s.watchFrameRate(ts)
		ts += 33 * 90
	}
	for i := 0; i < 20; i++ { // then the camera's idle rate
		s.watchFrameRate(ts)
		ts += 92 * 90
	}

	var commands [][]byte
	for len(commands) < 2 {
		select {
		case raw := <-sent:
			for _, seg := range parseSegments(raw) {
				plain, _, err := decryptRecord(testKey, seg.data)
				if err != nil {
					t.Fatal(err)
				}
				commands = append(commands, plain)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("sent %d restart commands, want 2", len(commands))
		}
	}
	want := restartSequence()
	if !bytes.Equal(commands[0], want[0]) || !bytes.Equal(commands[1], want[1]) {
		t.Fatalf("commands %x", commands)
	}
}
