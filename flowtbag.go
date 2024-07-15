/*
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

package main

import "C"

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Create some constants
const (
	TAB       = "\t"
	COPYRIGHT = "Licensed under the Apache License, Version 2.0 (the \"License\"); " +
		"you may not use this file except in compliance with the License. " +
		"You may obtain a copy of the License at\n" +
		"\n    http://www.apache.org/licenses/LICENSE-2.0\n"
)

// Converts flow tuple properties into a deterministic string
func stringTuple(ip1 string, port1 uint16, ip2 string, port2 uint16, proto uint8) string {
	if ip1 > ip2 {
		return fmt.Sprintf("%s,%d,%s,%d,%d", ip1, port1, ip2, port2, proto)
	}
	return fmt.Sprintf("%s,%d,%s,%d,%d", ip2, port2, ip1, port1, proto)
}

// Converts IPs and protocol into a deterministic string
func reducedStringTuple(ip1 string, ip2 string, proto uint8) string {
	if ip1 > ip2 {
		return fmt.Sprintf("%s,%s,%d", ip1, ip2, proto)
	}
	return fmt.Sprintf("%s,%s,%d", ip2, ip1, proto)
}

// Display a welcome message
func displayWelcome() {
	log.Println("\nWelcome to Flowtbag2 0.1b")
	log.Println("\n" + COPYRIGHT)
}

// Display usage
func usage() {
	fmt.Fprintf(os.Stderr, "%s [options] <capture file>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "options:\n")
	flag.PrintDefaults()
}

// Export Idle flows
func cleanupActive(time int64) {
	count := 0
	for tuple, flow := range activeFlows {
		if flow.CheckIdle(time) {
			count++
			flow.Export()
			delete(activeFlows, tuple)
		}
	}
	log.Printf("Removed %d flows. Currently at %d\n", count, time)
}

var (
	fileName           string          // Input PCAP filename
	reportInterval     int64           // Print out update every n flows
	liveCapture        bool            // Capture from eth0
	unidirectional     bool            // Include unidirectional flows in capture
	lucidCapture       bool            // Capture packets in "LUCID" format (i.e., packet-level statistics)
	cryptoPanOn        bool            // Anonymise IPs using CryptoPAN
	outputFolder       string          // Output stats to folder
	keyFile            string          // Input Key file for CryptoPAN
	flowStatBuffer     [][][]int64     // Buffer for flow stats (used when calculated LUCID stats)
	flowMetadataBuffer [][]interface{} // Buffer for flow metadata (used when calculated LUCID stats)
	initTime           string          // Start time
	ctx                *Cryptopan      // CryptoPAN object
	diffPriv           bool            // Anoymise flows statistics by adding noise via the Laplace Mechanism.
	// I have no idea if this actually meets the requirements for global differential privacy.
	// I don't think it does if there is a lot of repitition in the original PCAP file, but otherwise
	// it should provide some privacy guarantees (I think)
)

// Init Flowtbag with default values
func init() {
	flag.Int64Var(&reportInterval, "r", 500000,
		"The interval at which to report the current state of Flowtbag")
	flag.BoolVar(&liveCapture, "l", false,
		"Capture traffic live from wlo0")
	flag.BoolVar(&lucidCapture, "d", false, "Capture flows in Lucid format")
	flag.BoolVar(&cryptoPanOn, "c", false, "Apply CryptoPan to IPs")
	flag.StringVar(&keyFile, "k", "", "Provide key file for crypto-pan")
	flag.BoolVar(&unidirectional, "u", false, "Export flows stats for unidirectional flows")
	flag.BoolVar(&diffPriv, "p", false, "Export flow stats with diffpriv")
	flag.StringVar(&outputFolder, "o", "results", "Output flow statistics to specified folder")
	flag.Parse()
	fullInitTime := time.Now()
	initTime = fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d",
		fullInitTime.Year(), fullInitTime.Month(), fullInitTime.Day(),
		fullInitTime.Hour(), fullInitTime.Minute(), fullInitTime.Second())
	err := os.MkdirAll(fmt.Sprintf("%s/%s/", outputFolder, initTime), 0755)
	if err != nil {
		panic(err)
	}
	if cryptoPanOn {
		key := randomKey()
		cpan, err := New(key)
		if err != nil {
			panic(err)
		}
		ctx = cpan
	}
	fileName = flag.Arg(0)
	if !liveCapture {
		if fileName == "" {
			usage()
			fmt.Println()
			log.Fatalln("Missing required filename.")
		}
	}
}

// Print features for CSV header.
// Really annoying to add new features and I assume there's some better way of doing this.
func printFeatures() {
	fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
		"Process Time",
		"Src IP",
		"Src Port",
		"Dst IP",
		"Dst Port",
		"Protocol",
		"Total Fwd Pkts",
		"Total Fwd Vol",
		"Total Bwd Pkts",
		"Total Bwd Vol",
		"Fwd Pkt Len Min",
		"Fwd Pkt Len Mean",
		"Fwd Pkt Len Max",
		"Fwd Pkt Len Std",
		"Bwd Pkt Len Min",
		"Bwd Pkt Len Mean",
		"Bwd Pkt Len Max",
		"Bwd Pkt Len Std",
		"Fwd IAT Min",
		"Fwd IAT Mean",
		"Fwd IAT Max",
		"Fwd IAT Std",
		"Bwd IAT Min",
		"Bwd IAT Mean",
		"Bwd IAT Max",
		"Bwd IAT Std",
		"Duration",
		"Active Min",
		"Active Mean",
		"Active Max",
		"Active Std",
		"Idle Min",
		"Idle Mean",
		"Idle Max",
		"Idle Std",
		"SFlow Fwd Pkts",
		"SFlow Fwd Bytes",
		"SFlow Bwd Pkts",
		"SFlow bwd Bytes",
		"FPSH Count",
		"BPSH Count",
		"FURG Count",
		"BURG Count",
		"Total FHLen",
		"Total BHLen",
		"Previous Flow Time",
		"DSCP")
}

// Print LUCID features for CSV header. Features printed as arrays that need to be parsed to be used later.
// Really annoying to add new features and I assume there's some better way of doing this.
func printLucidFeatures() {
	fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
		"Process Time",
		"Unix Time",
		"Src IP",
		"Src Port",
		"Dst IP",
		"Dst Port",
		"Protocol",
		"Packet Count",
		"Direction",
		"Packet Sizes",
		"Header Sizes",
		"IP Headers Lens",
		"IATs",
		"Flags")

}

// Begin collection
func collection() {
	displayWelcome()
	// This will be our capture file
	var (
		p   *pcap.Handle
		err error
	)
	log.Printf("%s\n", pcap.Version())
	if !liveCapture {
		p, err = pcap.OpenOffline(fileName) // Capture packets from offline file
		if p == nil {
			log.Fatalf("OpenOffline(%s) failed: %s\n", fileName, err)
		}
	} else {
		p, err = pcap.OpenLive("wlo1", 1600, true, pcap.BlockForever) // Capture packets from live "wlo1" interface
		if p == nil {
			log.Fatalf("OpenLive(wlo1) failed: %s\n", err)
		}
	}

	p.SetBPFFilter("ip and (tcp or udp)")

	log.Println("Starting Flowtbag")
	startTime = time.Now()
	packetSource := gopacket.NewPacketSource(p, p.LinkType())
	if !lucidCapture {
		printFeatures()
	} else {
		printLucidFeatures()
	}
	if lucidCapture {
		flowStatBuffer = make([][][]int64, 0)
		flowMetadataBuffer = make([][]interface{}, 0)
		for packet := range packetSource.Packets() {
			lucidProcess(packet)
		}
		for _, lucidFlow := range activeLucidFlows {
			lucidFlow.LucidExport()
			flow_metadata, flow_stats := lucidFlow.splitLucidFlow()
			flowStatBuffer = append(flowStatBuffer, flow_stats)
			flowMetadataBuffer = append(flowMetadataBuffer, flow_metadata)
		}
		flushFlowStatsBuffer(flowStatBuffer, initTime, true)
		flushMetadataBuffer(flowMetadataBuffer, initTime, true)
	} else {
		for packet := range packetSource.Packets() {
			process(packet)
		}
		for _, flow := range activeFlows {
			flow.Export()
		}
	}
}

func main() {
	collection()
}

var (
	pCount            int64                 = 0                           // Packet Count
	flowCount         int64                 = 0                           // Flow Count
	startTime         time.Time                                           // Start Time
	endTime           time.Time                                           // End Time
	elapsed           time.Duration                                       // Duration
	activeFlows       map[string]*Flow      = make(map[string]*Flow)      // Active Flows
	activeLucidFlows  map[string]*LucidFlow = make(map[string]*LucidFlow) // Active Lucid Flows
	activeFlowTimings map[string][]int64    = make(map[string][]int64)    // Flow Timings
)

func printStackTrace() {
	n := 1
	for {
		p, f, l, ok := runtime.Caller(n)
		if !ok {
			break
		}
		log.Printf("%s (%s:%d)\n", runtime.FuncForPC(p).Name(), f, l)
		n++
	}
}

func catchPanic() {
	if err := recover(); err != nil {
		log.Printf("Error processing packet %d: %s", pCount, err)
		printStackTrace()
	}
}

// Bitwise TCP flags
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

// Process packets into flows
func process(raw gopacket.Packet) {
	defer catchPanic()
	pCount++
	if (pCount % reportInterval) == 0 {
		timeInt := raw.Metadata().Timestamp.Unix()
		endTime = time.Now()
		cleanupActive(timeInt)
		runtime.GC()
		elapsed = endTime.Sub(startTime)
		startTime = time.Now()
		log.Printf("Currently processing packet %d. Flowtbag size: %d", pCount,
			len(activeFlows))
		log.Printf("Took %vs to process %d packets", elapsed, reportInterval)
	}

	ipLayer := raw.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)
	if ip.Version != 4 {
		log.Print("Not IPv4. Packet should not have made it this far")
		return
	}
	pkt := make(map[string]int64, 10)
	var (
		srcip   string
		srcport uint16
		dstip   string
		dstport uint16
		proto   uint8
	)
	pkt["num"] = pCount
	pkt["iphlen"] = int64(ip.IHL * 4)
	pkt["dscp"] = int64(ip.TOS >> 2)
	pkt["len"] = int64(ip.Length)
	proto = uint8(ip.Protocol)
	srcip = ip.SrcIP.String()
	dstip = ip.DstIP.String()

	if proto == 6 {
		tcpLayer := raw.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		srcport = uint16(tcp.SrcPort)
		dstport = uint16(tcp.DstPort)
		pkt["prhlen"] = int64(tcp.DataOffset * 4)
		pkt["flags"] = int64(flagsAndOffset(tcp))
	} else if proto == 17 {
		udpLayer := raw.Layer(layers.LayerTypeUDP)
		udp, _ := udpLayer.(*layers.UDP)
		pkt["prhlen"] = int64(udp.Length)
		srcport = uint16(udp.SrcPort)
		dstport = uint16(udp.DstPort)
	} else {
		fmt.Printf("%s : %s : %d : %d \n", srcip, dstip, raw.Metadata().Timestamp.Unix(), proto)
		log.Fatal("Not TCP or UDP (Perhaps?). Packet should not have made it this far.")
	}
	pkt["time"] = raw.Metadata().Timestamp.UnixNano()
	ts := stringTuple(srcip, srcport, dstip, dstport, proto)
	reduced_ts := reducedStringTuple(srcip, dstip, proto)
	flow, exists := activeFlows[ts]
	if exists {
		return_val := flow.Add(pkt, srcip)
		if return_val == ADD_SUCCESS {
			// The flow was successfully added
			return
		} else if return_val == ADD_CLOSED {
			flow.Export()
			delete(activeFlows, ts)
			return
		} else {
			// Already in, but has expired
			flow.Export()
			delete(activeFlows, ts)
			flowCount++
			f := new(Flow)
			f.Init(srcip, srcport, dstip, dstport, proto, pkt, flowCount)
			// Add flow to timing map
			activeFlowTimings[reduced_ts] = append(activeFlowTimings[reduced_ts], f.firstTime)
			// Find whether other flows with same source/destination IP are also in the flowmap
			prev_time := f.getPreviousFlowStart(reduced_ts, activeFlowTimings)
			f.f[TIME_PREV_SAME_HOST].Set(prev_time)
			activeFlows[ts] = f
			return
		}
	} else {
		// This flow does not yet exist in the map
		flowCount++
		f := new(Flow)
		f.Init(srcip, srcport, dstip, dstport, proto, pkt, flowCount)
		// Add flow to timing map
		activeFlowTimings[reduced_ts] = append(activeFlowTimings[reduced_ts], f.firstTime)
		// Find whether other flows with same source/destination IP are also in the flowmap
		prev_time := f.getPreviousFlowStart(reduced_ts, activeFlowTimings)
		f.f[TIME_PREV_SAME_HOST].Set(prev_time)
		activeFlows[ts] = f
		return
	}
}

// Process packets into LUCID flows (should combine this with process())
func lucidProcess(raw gopacket.Packet) {
	defer catchPanic()
	pCount++
	if (pCount % reportInterval) == 0 {
		timeInt := raw.Metadata().Timestamp.Unix()
		endTime = time.Now()
		cleanupActive(timeInt)
		runtime.GC()
		elapsed = endTime.Sub(startTime)
		startTime = time.Now()
		log.Printf("Currently processing packet %d. Flowtbag size: %d", pCount,
			len(activeFlows))
		log.Printf("Took %vs to process %d packets", elapsed, reportInterval)
	}

	ipLayer := raw.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)
	if ip.Version != 4 {
		log.Fatal("Not IPv4. Packet should not have made it this far")
	}
	pkt := make(map[string]int64, 10)
	var (
		srcip   string
		srcport uint16
		dstip   string
		dstport uint16
		proto   uint8
	)
	pkt["num"] = pCount
	pkt["iphlen"] = int64(ip.IHL * 4)
	pkt["dscp"] = int64(ip.TOS >> 2)
	pkt["len"] = int64(ip.Length)
	proto = uint8(ip.Protocol)
	srcip = ip.SrcIP.String()
	dstip = ip.DstIP.String()

	if proto == 6 {
		tcpLayer := raw.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		srcport = uint16(tcp.SrcPort)
		dstport = uint16(tcp.DstPort)
		pkt["prhlen"] = int64(tcp.DataOffset * 4)
		pkt["flags"] = int64(flagsAndOffset(tcp))
	} else if proto == 17 {
		udpLayer := raw.Layer(layers.LayerTypeUDP)
		udp, _ := udpLayer.(*layers.UDP)
		pkt["prhlen"] = int64(udp.Length)
		srcport = uint16(udp.SrcPort)
		dstport = uint16(udp.DstPort)
	} else {
		fmt.Printf("%s : %s : %d : %d \n", srcip, dstip, raw.Metadata().Timestamp.Unix(), proto)
		log.Fatal("Not TCP or UDP. Packet should not have made it this far.")
	}
	pkt["time"] = raw.Metadata().Timestamp.UnixNano()
	ts := stringTuple(srcip, srcport, dstip, dstport, proto)
	flow, exists := activeLucidFlows[ts]
	if exists {
		return_val := flow.LucidAdd(pkt, srcip)
		if return_val == ADD_SUCCESS {
			// The flow was successfully added
			return
		} else if return_val == ADD_CLOSED {
			flow.LucidExport()
			flow_metadata, flow_stats := flow.splitLucidFlow()
			flowStatBuffer = append(flowStatBuffer, flow_stats)
			flowMetadataBuffer = append(flowMetadataBuffer, flow_metadata)
			flowStatBuffer = flushFlowStatsBuffer(flowStatBuffer, initTime, false)
			flowMetadataBuffer = flushMetadataBuffer(flowMetadataBuffer, initTime, false)
			delete(activeLucidFlows, ts)
			return
		} else {
			// Already in, but has expired
			flow.LucidExport()
			flow_metadata, flow_stats := flow.splitLucidFlow()
			flowStatBuffer = append(flowStatBuffer, flow_stats)
			flowMetadataBuffer = append(flowMetadataBuffer, flow_metadata)
			flowStatBuffer = flushFlowStatsBuffer(flowStatBuffer, initTime, false)
			flowMetadataBuffer = flushMetadataBuffer(flowMetadataBuffer, initTime, false)
			delete(activeLucidFlows, ts) // This feels like it should be necessary?
			flowCount++
			f := new(LucidFlow)
			f.LucidInit(srcip, srcport, dstip, dstport, proto, pkt)
			activeLucidFlows[ts] = f
			return
		}
	} else {
		// This flow does not yet exist in the map
		flowCount++
		f := new(LucidFlow)
		f.LucidInit(srcip, srcport, dstip, dstport, proto, pkt)
		activeLucidFlows[ts] = f
		return
	}
}

// Export for use in C code. I don't actually use this in any way, but sure it's a bit of fun, isn't it?
//
//export CollectLiveFlowStats
func CollectLiveFlowStats() {
	var (
		p   *pcap.Handle
		err error
	)
	p, err = pcap.OpenLive("wlo1", 10000, true, pcap.BlockForever)
	if p == nil {
		log.Fatalf("OpenLive(wlo1) failed: %s\n", err)
	}
	startTime = time.Now()
	p.SetBPFFilter("ip and (tcp or udp)")
	printFeatures()
	packetSource := gopacket.NewPacketSource(p, p.LinkType())
	for packet := range packetSource.Packets() {
		process(packet)
	}

	for _, flow := range activeFlows {
		flow.Export()
	}
}

//export CollectPcapFlowStats
func CollectPcapFlowStats(pcapfile string) {
	var (
		p   *pcap.Handle
		err error
	)
	p, err = pcap.OpenOffline(pcapfile)
	if p == nil {
		log.Fatalf("Openoffline(%s) failed: %s\n", pcapfile, err)
	}

	p.SetBPFFilter("ip and (tcp or udp)")

	startTime = time.Now()
	packetSource := gopacket.NewPacketSource(p, p.LinkType())
	for packet := range packetSource.Packets() {
		process(packet)
	}
	for _, flow := range activeFlows {
		flow.Export()
	}
}

//func main() {}
