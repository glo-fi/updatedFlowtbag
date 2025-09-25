package flow

import (
	flowpkg "github.com/glo-fi/Flowtbag/types"
)

// FlowType represents different types of flow analysis
type FlowType int

const (
	FlowTypeStatistical FlowType = iota // Traditional aggregate statistics
	FlowTypePacketLevel                 // Packet-level time series data (LUCID)
	FlowTypeHybrid                      // Both statistical and packet-level (future)
)

// FlowFactory creates flow processors of different types
type FlowFactory interface {
	// CreateFlow creates a new flow processor of the configured type
	CreateFlow(key FlowKey, firstPacket *flowpkg.ParsedPacket) FlowProcessor

	// GetFlowType returns what type of flows this factory creates
	GetFlowType() FlowType
}

// StatisticalFlowFactory creates flows that compute aggregate statistics
type StatisticalFlowFactory struct{}

func (f *StatisticalFlowFactory) CreateFlow(key FlowKey, firstPacket *flowpkg.ParsedPacket) FlowProcessor {
	// TODO: Implement in Stage 2
	return nil
}

func (f *StatisticalFlowFactory) GetFlowType() FlowType {
	return FlowTypeStatistical
}

// PacketLevelFlowFactory creates flows that collect packet-level data
type PacketLevelFlowFactory struct{}

func (f *PacketLevelFlowFactory) CreateFlow(key FlowKey, firstPacket *flowpkg.ParsedPacket) FlowProcessor {
	// TODO: Implement in Stage 2
	return nil
}

func (f *PacketLevelFlowFactory) GetFlowType() FlowType {
	return FlowTypePacketLevel
}

