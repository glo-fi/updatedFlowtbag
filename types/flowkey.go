package types

import (
	"fmt"
)

type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

func (fk FlowKey) String() string {
	return fmt.Sprintf("%s:%d<->%s:%d/%d",
		fk.SrcIP, fk.SrcPort, fk.DstIP, fk.DstPort, fk.Protocol)
}

func (fk FlowKey) IsEqual(other FlowKey) bool {
	return fk.SrcIP == other.SrcIP &&
		fk.DstIP == other.DstIP &&
		fk.SrcPort == other.SrcPort &&
		fk.DstPort == other.DstPort &&
		fk.Protocol == other.Protocol
}
func (p *ParsedPacket) GetFlowKey() FlowKey {
	if p.SrcIP.String() < p.DstIP.String() {
		return FlowKey{
			SrcIP:    p.SrcIP.String(),
			DstIP:    p.DstIP.String(),
			SrcPort:  p.SrcPort,
			DstPort:  p.DstPort,
			Protocol: p.Protocol,
		}
	}

	return FlowKey{
		SrcIP:    p.DstIP.String(),
		DstIP:    p.SrcIP.String(),
		SrcPort:  p.DstPort,
		DstPort:  p.SrcPort,
		Protocol: p.Protocol,
	}
}
