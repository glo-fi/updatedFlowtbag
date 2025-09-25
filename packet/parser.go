package packet

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	flowpkg "github.com/glo-fi/Flowtbag/types"
)

type PacketParser interface {
	ParsePacket(raw gopacket.Packet) (*flowpkg.ParsedPacket, error)

	// SupportedProtocols returns protocols this parser can handle
	// Returns:
	//    []uint8: Protocol numbers (6=TCP, 17=UDP, 1=ICMP etc.)
	SupportedProtocols() []uint8
}

type StandardPacketParser struct{}

func (p *StandardPacketParser) ParsePacket(raw gopacket.Packet) (*flowpkg.ParsedPacket, error) {
	pkt := &flowpkg.ParsedPacket{
		Timestamp: raw.Metadata().Timestamp,
		// SequenceNum will be set by caller
	}

	if err := p.parseIPLayer(raw, pkt); err != nil {
		return nil, fmt.Errorf("IP layer parsing failed: %w", err)
	}
	if err := p.parseTransportLayer(raw, pkt); err != nil {
		return nil, fmt.Errorf("transport layer parsing failed: %w", err)
	}

	return pkt, nil
}

func (p *StandardPacketParser) parseIPLayer(raw gopacket.Packet, pkt *flowpkg.ParsedPacket) error {
	if ipv4Layer := raw.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		return p.parseIPv4(ipv4Layer.(*layers.IPv4), pkt)
	}

	if ipv6Layer := raw.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		return p.parseIPv6(ipv6Layer.(*layers.IPv6), pkt)
	}

	return fmt.Errorf("no supported IP layer found")
}

func (p *StandardPacketParser) parseIPv4(ipv4 *layers.IPv4, pkt *flowpkg.ParsedPacket) error {
	pkt.SrcIP = ipv4.SrcIP
	pkt.DstIP = ipv4.DstIP
	pkt.Protocol = uint8(ipv4.Protocol)
	pkt.TotalLength = int64(ipv4.Length)
	pkt.IPHeaderLen = int64(ipv4.IHL * 4)
	pkt.DSCP = uint8(ipv4.TOS >> 2)
	return nil
}

func (p *StandardPacketParser) parseIPv6(ipv6 *layers.IPv6, pkt *flowpkg.ParsedPacket) error {
	pkt.SrcIP = ipv6.SrcIP
	pkt.DstIP = ipv6.DstIP
	pkt.Protocol = uint8(ipv6.NextHeader)
	pkt.TotalLength = int64(ipv6.Length)
	pkt.IPHeaderLen = 40 // IPv6 header is always 40 bytes
	pkt.DSCP = uint8(ipv6.TrafficClass >> 2)
	return nil
}

func (p *StandardPacketParser) parseTransportLayer(raw gopacket.Packet, pkt *flowpkg.ParsedPacket) error {
	switch pkt.Protocol {
	case 6: // TCP
		return p.parseTCP(raw, pkt)
	case 17: // UDP
		return p.parseUDP(raw, pkt)
	default:
		return fmt.Errorf("unsupported protocol: %d", pkt.Protocol)
	}
}

func (p *StandardPacketParser) parseTCP(raw gopacket.Packet, pkt *flowpkg.ParsedPacket) error {
	tcpLayer := raw.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return fmt.Errorf("no TCP layer found")
	}

	tcp := tcpLayer.(*layers.TCP)
	pkt.SrcPort = uint16(tcp.SrcPort)
	pkt.DstPort = uint16(tcp.DstPort)
	pkt.TransportHeaderLen = int64(tcp.DataOffset * 4)
	pkt.TCPFlags = flagsAndOffset(tcp)
	return nil
}

func (p *StandardPacketParser) parseUDP(raw gopacket.Packet, pkt *flowpkg.ParsedPacket) error {
	udpLayer := raw.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return fmt.Errorf("no UDP layer found")
	}

	udp := udpLayer.(*layers.UDP)
	pkt.SrcPort = uint16(udp.SrcPort)
	pkt.DstPort = uint16(udp.DstPort)
	pkt.TransportHeaderLen = int64(udp.Length)
	pkt.TCPFlags = 0 // UDP has no flags
	return nil
}

func (p *StandardPacketParser) SupportedProtocols() []uint8 {
	return []uint8{6, 17} // TCP, UDP
}

// flagsAndOffset extracts TCP flags as a uint16 (borrowed from existing code)
func flagsAndOffset(t *layers.TCP) uint16 {
	f := uint16(0)
	if t.FIN {
		f |= 0x0001
	}
	if t.SYN {
		f |= 0x0002
	}
	if t.RST {
		f |= 0x0004
	}
	if t.PSH {
		f |= 0x0008
	}
	if t.ACK {
		f |= 0x0010
	}
	if t.URG {
		f |= 0x0020
	}
	if t.ECE {
		f |= 0x0040
	}
	if t.CWR {
		f |= 0x0080
	}
	if t.NS {
		f |= 0x0100
	}
	return f
}
