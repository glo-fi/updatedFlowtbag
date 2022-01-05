/*
 *  Copyright 2011 Daniel Arndt
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
 *  @author: Daniel Arndt <danielarndt@gmail.com>
 *
 */

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/google/gopacket/pcap"
        "github.com/google/gopacket"
        "github.com/google/gopacket/layers"
)

// Create some constants
const (
	TAB       = "\t"
	COPYRIGHT = "Copyright (C) 2010 Daniel Arndt\n" +
		"Licensed under the Apache License, Version 2.0 (the \"License\"); " +
		"you may not use this file except in compliance with the License. " +
		"You may obtain a copy of the License at\n" +
		"\n    http://www.apache.org/licenses/LICENSE-2.0\n" +
		"\nFor more information, please visit: \n" +
		"http://web.cs.dal.ca/~darndt/projects/flowtbag"
)

func stringTuple(ip1 string, port1 uint16, ip2 string, port2 uint16, proto uint8) string {
	if ip1 > ip2 {
		return fmt.Sprintf("%s,%d,%s,%d,%d", ip1, port1, ip2, port2, proto)
	}
	return fmt.Sprintf("%s,%d,%s,%d,%d", ip2, port2, ip1, port1, proto)
}

// Display a welcome message
func displayWelcome() {
	log.Println("\nWelcome to Flowtbag2 0.1b")
	log.Println("\n" + COPYRIGHT + "\n")
}

func usage() {
	fmt.Fprintf(os.Stderr, "%s [options] <capture file>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "options:\n")
	flag.PrintDefaults()
}

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
	fileName       string
	reportInterval int64
)

func init() {
	flag.Int64Var(&reportInterval, "r", 500000,
		"The interval at which to report the current state of Flowtbag")
	flag.Parse()
	fileName = flag.Arg(0)
	if fileName == "" {
		usage()
		fmt.Println()
		log.Fatalln("Missing required filename.")
	}
}

func printFeatures() {
    fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
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
             "DSCP")
}

func main() {
	displayWelcome()
	// This will be our capture file
	var (
		p   *pcap.Handle
		err error
	)
	log.Printf("%s\n", pcap.Version())
	p, err = pcap.OpenOffline(fileName)
	if p == nil {
		log.Fatalf("Openoffline(%s) failed: %s\n", fileName, err)
	}

	p.SetBPFFilter("ip and (tcp or udp)")

	log.Println("Starting Flowtbag")
	startTime = time.Now()
        packetSource := gopacket.NewPacketSource(p, p.LinkType())
	printFeatures()
	for packet := range packetSource.Packets() {
		process(packet)
	}
	for _, flow := range activeFlows {
		flow.Export()
	}
}

var (
	pCount      int64 = 0
	flowCount   int64 = 0
	startTime   time.Time
	endTime     time.Time
	elapsed     time.Duration
	activeFlows map[string]*Flow = make(map[string]*Flow)
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
		log.Printf("Took %fs to process %d packets", elapsed, reportInterval)
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
			flowCount++
			f := new(Flow)
			f.Init(srcip, srcport, dstip, dstport, proto, pkt, flowCount)
			activeFlows[ts] = f
			return
		}
	} else {
		// This flow does not yet exist in the map
		flowCount++
		f := new(Flow)
		f.Init(srcip, srcport, dstip, dstport, proto, pkt, flowCount)
		activeFlows[ts] = f
		return
	}
}
