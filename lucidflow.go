package main

import (
	"fmt"
	"time"
)

const (
	LUCID_SIZES = iota
	LUCID_HEADER_SIZES
	LUCID_IP_SIZES
	LUCID_IATS
	LUCID_FLAGS
	LUCID_DIR
	LUCID_STATES
	LUCID_NUM_FEATURES
)

var (
	LUCID_CUTOFF = 600000000000 //25000000000
	//25000000000
	LUCID_FEATURE_NAME_MAP = map[int]string{LUCID_SIZES: "Pkt_Sizes",
		LUCID_HEADER_SIZES: "Pkt_Header_Sizes",
		LUCID_IP_SIZES:     "Pkt_IP_Sizes",
		LUCID_IATS:         "Pkt_IATs",
		LUCID_FLAGS:        "Pkt_Flags",
		LUCID_DIR:          "Pkt_Direction",
		LUCID_STATES:       "Pkt_States"}
)

type LucidFlow struct {
	// Features
	f [][]int64

	valid       bool
	activeStart int64
	firstTime   int64
	last        int64
	cstate      tcpState
	sstate      tcpState
	pdir        int8
	unixTime    string
	srcip       string // IP address of the source (client)
	srcport     uint16 // Port number of the source connection
	dstip       string // IP address of the destination (server)
	dstport     uint16 // Port number of the destionation connection.
	proto       uint8  // The IP protocol being used for the connection.
	packetCount int64
}

func (lf *LucidFlow) updateTcpState(pkt packet) {
	lf.cstate.TcpUpdate(pkt["flags"], P_FORWARD, lf.pdir)
	lf.sstate.TcpUpdate(pkt["flags"], P_BACKWARD, lf.pdir)
}

func (lf *LucidFlow) LucidInit(srcip string,
	srcport uint16,
	dstip string,
	dstport uint16,
	proto uint8,
	pkt packet) {
	lf.valid = false
	lf.srcip = srcip
	lf.srcport = srcport
	lf.dstip = dstip
	lf.dstport = dstport
	lf.proto = proto

	lf.f = make([][]int64, LUCID_NUM_FEATURES)
	lf.f[LUCID_SIZES] = make([]int64, 0)
	lf.f[LUCID_HEADER_SIZES] = make([]int64, 0)
	lf.f[LUCID_IP_SIZES] = make([]int64, 0)
	lf.f[LUCID_IATS] = make([]int64, 0)
	lf.f[LUCID_FLAGS] = make([]int64, 0)
	lf.f[LUCID_STATES] = make([]int64, 0)
	lf.f[LUCID_DIR] = make([]int64, 0)

	lf.f[LUCID_SIZES] = append(lf.f[LUCID_SIZES], pkt["len"]) // Original Two Features used to test LUCID
	lf.f[LUCID_HEADER_SIZES] = append(lf.f[LUCID_HEADER_SIZES], pkt["prhlen"])
	lf.f[LUCID_IP_SIZES] = append(lf.f[LUCID_IP_SIZES], pkt["iphlen"])
	lf.f[LUCID_IATS] = append(lf.f[LUCID_IATS], 0) // Original Two Features used to test LUCID
	lf.f[LUCID_FLAGS] = append(lf.f[LUCID_FLAGS], pkt["flags"])
	lf.f[LUCID_DIR] = append(lf.f[LUCID_DIR], P_FORWARD)

	lf.firstTime = pkt["time"]
	lf.unixTime = time.Unix(0, lf.firstTime).UTC().String()

	lf.last = lf.firstTime
	lf.activeStart = lf.firstTime

	lf.packetCount = 1

	if lf.proto == IP_TCP {
		// TCP specific code:
		lf.cstate.State = TCP_STATE_START
		lf.sstate.State = TCP_STATE_START
		lf.f[LUCID_STATES] = append(lf.f[LUCID_STATES], int64(lf.cstate.State))
		lf.f[LUCID_STATES] = append(lf.f[LUCID_STATES], int64(lf.sstate.State))
	}
}

func (lf *LucidFlow) LucidAdd(pkt packet, srcip string) int {
	lf.valid = true
	now := pkt["time"]
	diff := now - lf.last
	if diff > int64(LUCID_CUTOFF) {
		return ADD_IDLE
	}
	//tot_time := now - lf.firstTime
	lf.last = now
	//fmt.Printf("Diff: %d\n", diff)
	//fmt.Printf("Tot Time: %d\n", tot_time)

	lf.f[LUCID_SIZES] = append(lf.f[LUCID_SIZES], pkt["len"]) // Original Two Features used to test LUCID
	lf.f[LUCID_HEADER_SIZES] = append(lf.f[LUCID_HEADER_SIZES], pkt["prhlen"])
	lf.f[LUCID_IP_SIZES] = append(lf.f[LUCID_IP_SIZES], pkt["iphlen"])
	lf.f[LUCID_IATS] = append(lf.f[LUCID_IATS], diff) // Original Two Features used to test LUCID
	lf.f[LUCID_FLAGS] = append(lf.f[LUCID_FLAGS], pkt["flags"])

	lf.packetCount += 1

	if srcip == lf.srcip {
		lf.pdir = P_FORWARD // Forward
		lf.f[LUCID_DIR] = append(lf.f[LUCID_DIR], P_FORWARD)
	} else {
		lf.pdir = P_BACKWARD
		lf.f[LUCID_DIR] = append(lf.f[LUCID_DIR], P_BACKWARD)
	}

	lf.updateTcpState(pkt)
	lf.f[LUCID_STATES] = append(lf.f[LUCID_STATES], int64(lf.cstate.State))
	lf.f[LUCID_STATES] = append(lf.f[LUCID_STATES], int64(lf.sstate.State))

	if lf.proto == IP_TCP &&
		(lf.cstate.State == TCP_STATE_CLOSED &&
			lf.sstate.State == TCP_STATE_CLOSED) {
		return ADD_CLOSED
	} else {
		return ADD_SUCCESS
	}

}

func (lf *LucidFlow) LucidExport() {
	if !lf.valid {
		return
	}
	fmt.Printf("%s, %d, %s, %d, %s, %d, %d",
		lf.unixTime,
		lf.firstTime,
		string(lf.srcip),
		lf.srcport,
		string(lf.dstip),
		lf.dstport,
		lf.proto)
	fmt.Printf(",%d", lf.packetCount)
	fmt.Printf(",%v", lf.f[LUCID_DIR])
	fmt.Printf(",%v", lf.f[LUCID_SIZES])
	fmt.Printf(",%v", lf.f[LUCID_HEADER_SIZES])
	fmt.Printf(",%v", lf.f[LUCID_IP_SIZES])
	fmt.Printf(",%v", lf.f[LUCID_IATS])
	fmt.Printf(",%v", lf.f[LUCID_FLAGS])
	fmt.Printf(",%v", lf.f[LUCID_STATES])
	fmt.Println()
}
