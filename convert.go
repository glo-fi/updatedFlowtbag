package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/sbinet/npyio"
)

const (
	FLOW_CUTOFF  = 100
	BUFFER_LIMIT = 5000
)

func suppressError() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var m []float64
	err = npyio.Read(f, &m)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("data = %v\n", m)
}

func (f *Flow) flowToInterface() []interface{} {
	stats := []interface{}{f.unixTime, string(f.srcip), f.srcport, string(f.dstip), f.dstport, f.proto}
	for i := 0; i < NUM_FEATURES; i++ {
		stats = append(stats, f.f[i].Export())
	}
	return stats
}

func (lf *LucidFlow) padLucidFlow() (return_lf *LucidFlow) {
	rlf := new(LucidFlow)
	rlf.valid = lf.valid
	rlf.activeStart = lf.activeStart
	rlf.firstTime = lf.firstTime
	rlf.last = lf.last
	rlf.cstate = lf.cstate
	rlf.sstate = lf.sstate
	rlf.pdir = lf.pdir
	rlf.unixTime = lf.unixTime
	rlf.srcip = lf.srcip
	rlf.srcport = lf.srcport
	rlf.dstip = lf.dstip
	rlf.dstport = lf.dstport
	rlf.proto = lf.proto
	rlf.packetCount = lf.packetCount
	if lf.packetCount > FLOW_CUTOFF {
		for i := 0; i < LUCID_NUM_FEATURES; i++ {
			rlf.f[i] = lf.f[i][:FLOW_CUTOFF]
		}
	} else {
		for i := 0; i < LUCID_NUM_FEATURES; i++ {
			for j := 0; j < FLOW_CUTOFF; j++ {
				if j < int(rlf.packetCount) {
					rlf.f[i][j] = lf.f[i][j]
				} else {
					rlf.f[i][j] = -1
				}
			}
		}
	}
	return rlf
}

func (lf *LucidFlow) splitLucidFlow() ([]interface{}, [][]int64) {
	flow_metadata := []interface{}{lf.unixTime, lf.firstTime, string(lf.srcip), lf.srcport, string(lf.dstip), lf.dstport, lf.proto}
	flow_stats := lf.f

	return flow_metadata, flow_stats
}

func splitLucidFlows(flows map[string]*LucidFlow) ([][]interface{}, [][][]int64) {
	flows_metadata := make([][]interface{}, len(flows))
	flows_stats := make([][][]int64, len(flows))
	for _, i := range flows {
		flow_metadata, flow_stats := i.splitLucidFlow()
		flows_metadata = append(flows_metadata, flow_metadata)
		flows_stats = append(flows_stats, flow_stats)
	}
	return flows_metadata, flows_stats
}

func flowStatsToFile(flow_stats [][]int64, filename string) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	for i := 0; i < len(flow_stats); i++ {
		var to_print []string
		for j := 0; j < len(flow_stats[i]); j++ {
			to_print = append(to_print, strconv.Itoa(int(flow_stats[i][j])))
		}
		_, err := f.WriteString(strings.Join(to_print, ",") + "\n")

		if err != nil {
			log.Fatalf("error writing to file: %v\n", err)
		}

	}

	err = f.Close()
	if err != nil {
		log.Fatalf("error closing file: %v\n", err)
	}
}

func flushFlowStatsBuffer(buffer [][][]int64, initTime string, force bool) [][][]int64 {
	empty_buffer := make([][][]int64, 0)
	if (len(buffer) < BUFFER_LIMIT) && !force {
		return buffer
	} else {
		for i := 0; i < LUCID_NUM_FEATURES; i++ {
			single_buffer := make([][]int64, len(buffer))
			for j := 0; j < len(buffer); j++ {
				single_buffer[j] = buffer[j][i]
			}
			flowStatsToFile(single_buffer, fmt.Sprintf("%s/%s/%s-%s.csv", outputFolder, initTime, initTime, LUCID_FEATURE_NAME_MAP[i])) // Need Unique Name of File for Each Output
		}
	}
	return empty_buffer
}

func flushMetadataBuffer(buffer [][]interface{}, initTime string, force bool) [][]interface{} {
	empty_buffer := make([][]interface{}, 0)
	if (len(buffer) < BUFFER_LIMIT) && !force {
		return buffer
	} else {
		filename := fmt.Sprintf("%s/%s/%s-%s.csv", outputFolder, initTime, initTime, "metadata")
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		for i := 0; i < len(buffer); i++ {
			print_string := fmt.Sprintf("%s, %d, %s, %d, %s, %d, %d",
				buffer[i][0],
				buffer[i][1],
				buffer[i][2],
				buffer[i][3],
				buffer[i][4],
				buffer[i][5],
				buffer[i][6])
			_, err = f.WriteString(print_string + "\n")
		}

		if err != nil {
			log.Fatalf("error writing to file: %v\n", err)
		}

		err = f.Close()
		if err != nil {
			log.Fatalf("error closing file: %v\n", err)
		}
	}
	return empty_buffer
}
