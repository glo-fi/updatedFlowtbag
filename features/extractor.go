package features

import (
	flowpkg "github.com/glo-fi/Flowtbag/types"
)

type FeatureExtractor interface {
	ProcessPacket(pkt *flowpkg.ParsedPacket) error
	Export() ([]string, error)
	GetHeaders() []string
	Reset()
}
