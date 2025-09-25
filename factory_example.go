package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/glo-fi/Flowtbag/flow"
	flowpkg "github.com/glo-fi/Flowtbag/types"
)

// Example showing how to use the improved factories
func demonstrateFactories() {
	fmt.Println("=== Factory Pattern Demonstration ===")

	// Create sample packet data
	samplePacket := &flowpkg.ParsedPacket{
		Timestamp:          time.Now(),
		SrcIP:              net.ParseIP("192.168.1.1"),
		DstIP:              net.ParseIP("192.168.1.2"),
		Protocol:           6, // TCP
		DSCP:               0,
		TotalLength:        1024,
		IPHeaderLen:        20,
		SrcPort:            12345,
		DstPort:            80,
		TransportHeaderLen: 20,
		TCPFlags:           0x0018, // ACK + PSH
		Direction:          0,      // Forward
		SequenceNum:        1,
	}

	// Create flow key
	flowKey := flow.FlowKey{
		SrcIP:    "192.168.1.1",
		DstIP:    "192.168.1.2",
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6,
	}

	// Demonstrate Statistical Flow Factory
	fmt.Println("\n--- Statistical Flow Factory ---")
	var statBuffer bytes.Buffer
	statFactory := flow.NewStatisticalFlowFactory(&statBuffer, 
		func(key flow.FlowKey, packet *flowpkg.ParsedPacket, writer io.Writer) flow.FlowProcessor {
			return NewStatisticalFlowAdapter(key, packet, writer)
		})

	fmt.Printf("Factory Type: %v\n", statFactory.GetFlowType())
	
	statFlow := statFactory.CreateFlow(flowKey, samplePacket)
	if statFlow != nil {
		fmt.Println("✓ Successfully created statistical flow")
		
		// Add another packet to test the interface
		samplePacket2 := *samplePacket
		samplePacket2.SequenceNum = 2
		samplePacket2.TotalLength = 512
		
		err := statFlow.Add(&samplePacket2, 0)
		if err != nil {
			fmt.Printf("Error adding packet: %v\n", err)
		} else {
			fmt.Println("✓ Successfully added packet to flow")
		}

		// Get metadata
		metadata := statFlow.GetMetadata()
		fmt.Printf("Flow metadata: Valid=%v, Packets=%v, Bidir=%v\n", 
			metadata.IsValid, metadata.PacketCount, metadata.IsBidir)

		// Check if flow is expired
		isExpired := statFlow.IsExpired(time.Now().Add(10 * time.Second))
		fmt.Printf("Flow expired: %v\n", isExpired)
	} else {
		fmt.Println("✗ Failed to create statistical flow")
	}

	// Demonstrate Packet-Level Flow Factory  
	fmt.Println("\n--- Packet-Level Flow Factory ---")
	var lucidBuffer bytes.Buffer
	packetFactory := flow.NewPacketLevelFlowFactory(&lucidBuffer,
		func(key flow.FlowKey, packet *flowpkg.ParsedPacket, writer io.Writer) flow.FlowProcessor {
			return NewPacketLevelFlowAdapter(key, packet, writer)  
		})

	fmt.Printf("Factory Type: %v\n", packetFactory.GetFlowType())
	
	packetFlow := packetFactory.CreateFlow(flowKey, samplePacket)
	if packetFlow != nil {
		fmt.Println("✓ Successfully created packet-level flow")
		
		// Add another packet
		samplePacket3 := *samplePacket
		samplePacket3.SequenceNum = 3
		samplePacket3.TotalLength = 256
		
		err := packetFlow.Add(&samplePacket3, 1) // Backward direction
		if err != nil {
			fmt.Printf("Error adding packet: %v\n", err)
		} else {
			fmt.Println("✓ Successfully added packet to flow")
		}

		// Get metadata
		metadata := packetFlow.GetMetadata()
		fmt.Printf("Flow metadata: Valid=%v, Packets=%v, Bidir=%v\n", 
			metadata.IsValid, metadata.PacketCount, metadata.IsBidir)
	} else {
		fmt.Println("✗ Failed to create packet-level flow")
	}

	// Demonstrate factory extensibility
	fmt.Println("\n--- Factory Extensibility ---")
	fmt.Println("✓ Factories support custom output writers")
	fmt.Println("✓ Factories can be configured with different adapters")  
	fmt.Println("✓ New flow types can be added by implementing FlowProcessor interface")
	fmt.Println("✓ Bridges existing Flow and LucidFlow implementations seamlessly")
}

// This function can be called from main() to test the factories
// Uncomment the line below to run the demonstration
// func init() { demonstrateFactories() }