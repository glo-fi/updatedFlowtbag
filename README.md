## License

Copyright 2011 Daniel Arndt

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Author: 
    Daniel Arndt <danielarndt@gmail.com> (http://dan.arndt.ca)

Code edited and updated (extensively) by Robert Flood <r.flood@ed.ac.uk>

## Purpose

The purpose of this program is to calculate flow statistics from a given 
capture file. Flowtbag was designed with offline processing as the primary
focus, but has been extended to include online processing. Note: this seems
to mess with closing flows via timeouts. Make sure to choose a sesible
timeout value!

## Requirements

To run the executable, you will need libpcap installed. On a debian based
system, the following command will install the appropriate library:

    apt-get install libpcap

Other distributions will likely have a similar package name.

To compile from source, you'll need a Go compiler, libpcap headers, and
gopcap.

### Go compiler:

Please see http://golang.org/doc/install.html

### libpcap headers:

On a debian based system, you can execute the following command:

    apt-get install libpcap-dev

Other distributions will likely have a similar package name. It is
important that if you are compiling the program from source, you install
the developement headers.

## Compilation

Once libpcap is installed, `go` will install the necessary go dependencies. Just
build and install using go.

   go get github.com/danielarndt/flowtbag


## Privacy Features

Flowtbag has been updated to include two ways of perturbing output
and provide some privacy guarentees. 

Firstly, IP addresses can be anonymised via the 
[Crypto-PAn](https://en.wikipedia.org/wiki/Crypto-PAn) algorithm. 
This maps IP addressed whilst maintaining their subnet structure. 
Keys are currently generated randomly and then discarded, making this process irreversible.
Support for key input and de-anonymisation should be easy to add.

Secondly, features can be collected in accordance with
Google's [dpagg](https://pkg.go.dev/github.com/google/differential-privacy/go/dpagg?utm_source=godoc) library. Thus, all
statistics will be calculated in a differentially private manner, if
you're convinced that, say, the standard deviation of packet lengths
is a particularly sensitive attribute. We do this via the Laplace mechanism, as it requires fewer hyperparameters. Note that it's 
unlikely we achieve 'true' local differential privacy e.g, webpages can be visited multiple times, using up the privacy budget in an 
unpredictable way. However, rarely accessed services should have stronger guarantees.

Currently, the hyperparameters for the differential private feature
collection are fixed across all features. This is stupid: they 
need to be read individually from a file in order to have any sort
of meaning. However, this shouldn't be complicated to add.


## Usage

Standard Usage: `./Flowtbag [FLAGS] [PCAP]`

`-l: Capture traffic live from wlo0` (requires root permissions)

`-d: Capture flows in LUCID format` (i.e., packet-level stats)

`-c: Apply Crypto-PAn to IPs`

`-k: Provide Crypto-PAn key file` (not implemented)

`-o: Output folder (default ./results/)` (for LUCID format flows)

`-p: Collect stats in differential private manner`

`-r: The interval at which to report the current state of Flowtbag (default 500000)`

`-u: Export flows stats for unidirectional flows`


## Output

Flowtbag currently has two seperate channels for output. To stdout, a stream
of comma seperated values is output. Line by line, these represent the flows
in the capture. The features output are given, in order, in section 4.1. The
second output channel is stderr. This is where reports, as well as any
debugging information is displayed. This allows the user to redirect output
to a text file, and still receive updates as the program runs. Output should probably sent to a specified file in the future.


### Statistics

    srcip STRINGq
    srcport NUMERIC
    dstip STRING
    dstport NUMERIC
    proto NUMERIC
    total_fpackets NUMERIC
    total_fvolume NUMERIC
    total_bpackets NUMERIC
    total_bvolume NUMERIC
    min_fpktl NUMERIC
    mean_fpktl NUMERIC
    max_fpktl NUMERIC
    std_fpktl NUMERIC
    min_bpktl NUMERIC
    mean_bpktl NUMERIC
    max_bpktl NUMERIC
    std_bpktl NUMERIC
    min_fiat NUMERIC
    mean_fiat NUMERIC
    max_fiat NUMERIC
    std_fiat NUMERIC
    min_biat NUMERIC
    mean_biat NUMERIC
    max_biat NUMERIC
    std_biat NUMERIC
    duration NUMERIC
    min_active NUMERIC
    mean_active NUMERIC
    max_active NUMERIC
    std_active NUMERIC
    min_idle NUMERIC
    mean_idle NUMERIC
    max_idle NUMERIC
    std_idle NUMERIC
    sflow_fpackets NUMERIC
    sflow_fbytes NUMERIC
    sflow_bpackets NUMERIC
    sflow_bbytes NUMERIC
    fpsh_cnt NUMERIC
    bpsh_cnt NUMERIC
    furg_cnt NUMERIC
    burg_cnt NUMERIC
    total_fhlen NUMERIC
    total_bhlen NUMERIC
    dscp NUMERIC
