package types

import (
	"net"
	"time"
)

type ParsedPacket struct {
	Timestamp time.Time

	SrcIP       net.IP // Source IP address (IPv4 or IPv6)
	DstIP       net.IP // Destination IP address
	Protocol    uint8  // IP Protocol number
	DSCP        uint8  // Differentiated Services Code Point
	TotalLength int64  // Total packet length in bytes
	IPHeaderLen int64  // IP header length in bytes

	SrcPort            uint16
	DstPort            uint16
	TransportHeaderLen int64 // TCP/UDP header length in bytes

	TCPFlags uint16

	Direction   uint8
	SequenceNum int64
}
