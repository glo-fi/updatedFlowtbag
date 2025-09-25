package main

import (
	"fmt"
	"log"
	"os"

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






