package flow

import (
	"net"
	"time"

	flowpkg "github.com/glo-fi/Flowtbag/types"
)

// FowProcessor is Core abstraction for all flow types
type FlowProcessor interface {
	// Add processes a single packet and updates the flow's internal state
	Add(pkt *flowpkg.ParsedPacket, direction int8) error
	// Export outputs flow statistics in the configured format
	Export() error

	// IsExpired checks if a flow was removed due to inactivity
	IsExpired(currentTime time.Time) bool
	// GetMetadata returns basic information about this flow
	GetMetadata() *FlowMetadata
}

// BaseFlow is Common flow data
type BaseFlow struct {
	SrcIP     net.IP
	SrcPort   uint16
	DstIP     net.IP
	DstPort   uint16
	Protocol  uint8
	FirstTime time.Time
	LastTime  time.Time
	Valid     bool
}

// Flow key is Flow identification
type FlowKey struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Protocol         uint8
}

// FlowMetadata contains basic flow information
type FlowMetadata struct {
	FlowKey
	FirstTime   time.Time
	LastTime    time.Time
	PacketCount int64
	IsValid     bool
	IsBidir     bool
}
