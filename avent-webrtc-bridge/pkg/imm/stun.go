package imm

import (
	"encoding/binary"
	"net"

	"github.com/pion/stun/v4"
)

// The camera runs ICE as the controlling agent even though it answers, so the
// client is controlled: it answers the camera's checks and accepts the pair
// the camera nominates with USE-CANDIDATE. Its own checks only serve to open
// stateful firewalls between the two (they may sit in different VLANs).

type rawAttr struct {
	t stun.AttrType
	v []byte
}

func (a rawAttr) AddTo(m *stun.Message) error {
	m.Add(a.t, a.v)
	return nil
}

// bindingRequest builds a controlled-role connectivity check towards the camera.
func bindingRequest(remoteUfrag, localUfrag, remotePassword string, tiebreaker uint64) ([]byte, error) {
	priority := make([]byte, 4)
	binary.BigEndian.PutUint32(priority, 1853824767)
	tb := make([]byte, 8)
	binary.BigEndian.PutUint64(tb, tiebreaker)
	m, err := stun.Build(
		stun.TransactionID,
		stun.BindingRequest,
		stun.NewUsername(remoteUfrag+":"+localUfrag),
		rawAttr{stun.AttrPriority, priority},
		rawAttr{stun.AttrICEControlled, tb},
		stun.NewShortTermIntegrity(remotePassword),
		stun.Fingerprint,
	)
	if err != nil {
		return nil, err
	}
	return m.Raw, nil
}

// bindingSuccess answers one of the camera's checks.
func bindingSuccess(req *stun.Message, from *net.UDPAddr, localPassword string) ([]byte, error) {
	m, err := stun.Build(
		stun.NewTransactionIDSetter(req.TransactionID),
		stun.BindingSuccess,
		&stun.XORMappedAddress{IP: from.IP, Port: from.Port},
		stun.NewShortTermIntegrity(localPassword),
		stun.Fingerprint,
	)
	if err != nil {
		return nil, err
	}
	return m.Raw, nil
}
