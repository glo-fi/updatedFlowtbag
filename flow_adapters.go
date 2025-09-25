package main

import (
	"fmt"
	"io"
	"time"

	"github.com/glo-fi/Flowtbag/flow"
	flowpkg "github.com/glo-fi/Flowtbag/types"
)

// StatisticalFlowAdapter wraps the existing Flow struct to implement flow.FlowProcessor
type StatisticalFlowAdapter struct {
	flowInstance Flow          // Embedded original Flow struct
	key          flow.FlowKey  // Flow identification
	outputWriter io.Writer
}

func NewStatisticalFlowAdapter(key flow.FlowKey, firstPacket *flowpkg.ParsedPacket, writer io.Writer) *StatisticalFlowAdapter {
	adapter := &StatisticalFlowAdapter{
		key:          key,
		outputWriter: writer,
	}
	
	// Initialize the embedded Flow with the first packet
	pkt := convertParsedPacketToMap(firstPacket)
	adapter.flowInstance.Init(key.SrcIP, key.SrcPort, key.DstIP, key.DstPort, key.Protocol, pkt, firstPacket.SequenceNum)
	
	return adapter
}

func (a *StatisticalFlowAdapter) Add(pkt *flowpkg.ParsedPacket, direction int8) error {
	// Convert ParsedPacket to the old map format expected by Flow.Add()
	packetMap := convertParsedPacketToMap(pkt)
	
	// Determine source IP for direction calculation (similar to existing logic)
	srcIP := pkt.SrcIP.String()
	
	result := a.flowInstance.Add(packetMap, srcIP)
	
	// Convert old return codes to errors
	switch result {
	case ADD_SUCCESS:
		return nil
	case ADD_CLOSED:  
		return fmt.Errorf("flow is closed")
	case ADD_IDLE:
		return fmt.Errorf("flow is idle")
	default:
		return fmt.Errorf("unknown add result: %d", result)
	}
}

func (a *StatisticalFlowAdapter) Export() error {
	// The original Flow.Export() writes to stdout, we need to capture or redirect it
	// For now, call the original export method
	a.flowInstance.Export()
	return nil
}

func (a *StatisticalFlowAdapter) IsExpired(currentTime time.Time) bool {
	// Convert to nanoseconds since Unix epoch (matching original format)
	timeNanos := currentTime.UnixNano()
	return a.flowInstance.CheckIdle(timeNanos)
}

func (a *StatisticalFlowAdapter) GetMetadata() *flow.FlowMetadata {
	return &flow.FlowMetadata{
		FlowKey:     a.key,
		FirstTime:   time.Unix(0, a.flowInstance.firstTime),
		LastTime:    time.Unix(0, a.flowInstance.getLastTime()),
		PacketCount: a.flowInstance.f[TOTAL_FPACKETS].Get() + a.flowInstance.f[TOTAL_BPACKETS].Get(),
		IsValid:     a.flowInstance.valid,
		IsBidir:     a.flowInstance.isBidir,
	}
}

// PacketLevelFlowAdapter wraps the existing LucidFlow struct to implement flow.FlowProcessor  
type PacketLevelFlowAdapter struct {
	flowInstance LucidFlow     // Embedded original LucidFlow struct
	key          flow.FlowKey  // Flow identification
	outputWriter io.Writer
}

func NewPacketLevelFlowAdapter(key flow.FlowKey, firstPacket *flowpkg.ParsedPacket, writer io.Writer) *PacketLevelFlowAdapter {
	adapter := &PacketLevelFlowAdapter{
		key:          key,
		outputWriter: writer,
	}
	
	// Initialize the embedded LucidFlow with the first packet
	pkt := convertParsedPacketToMap(firstPacket)
	adapter.flowInstance.LucidInit(key.SrcIP, key.SrcPort, key.DstIP, key.DstPort, key.Protocol, pkt)
	
	return adapter
}

func (a *PacketLevelFlowAdapter) Add(pkt *flowpkg.ParsedPacket, direction int8) error {
	// Convert ParsedPacket to the old map format expected by LucidFlow.LucidAdd()
	packetMap := convertParsedPacketToMap(pkt)
	
	// Determine source IP for direction calculation
	srcIP := pkt.SrcIP.String()
	
	result := a.flowInstance.LucidAdd(packetMap, srcIP)
	
	// Convert old return codes to errors
	switch result {
	case ADD_SUCCESS:
		return nil
	case ADD_CLOSED:
		return fmt.Errorf("flow is closed")  
	case ADD_IDLE:
		return fmt.Errorf("flow is idle")
	default:
		return fmt.Errorf("unknown add result: %d", result)
	}
}

func (a *PacketLevelFlowAdapter) Export() error {
	// The original LucidFlow.LucidExport() writes to stdout
	a.flowInstance.LucidExport()
	return nil
}

func (a *PacketLevelFlowAdapter) IsExpired(currentTime time.Time) bool {
	// LucidFlow doesn't have CheckIdle, but we can implement similar logic
	timeNanos := currentTime.UnixNano()
	idleTime := timeNanos - a.flowInstance.last
	return idleTime > IDLE_THRESHOLD
}

func (a *PacketLevelFlowAdapter) GetMetadata() *flow.FlowMetadata {
	return &flow.FlowMetadata{
		FlowKey:     a.key,
		FirstTime:   time.Unix(0, a.flowInstance.firstTime),
		LastTime:    time.Unix(0, a.flowInstance.last),
		PacketCount: a.flowInstance.packetCount,
		IsValid:     a.flowInstance.valid,
		IsBidir:     true, // LucidFlow doesn't track bidirectionality explicitly
	}
}

// convertParsedPacketToMap converts our new ParsedPacket to the old map format
// This is a temporary bridge function during the refactoring
func convertParsedPacketToMap(pkt *flowpkg.ParsedPacket) packet {
	return packet{
		"time":   pkt.Timestamp.UnixNano(),
		"len":    pkt.TotalLength,
		"iphlen": pkt.IPHeaderLen,
		"dscp":   int64(pkt.DSCP),
		"prhlen": pkt.TransportHeaderLen,
		"flags":  int64(pkt.TCPFlags),
		"num":    pkt.SequenceNum,
	}
}