package main

import (
	"flag"
)

type Config struct {
	Interface   string
	Filter      string
	PcapFile    string
	SaveResults string
}

func main() {
	// We parse the command line operations directly here before
	// passing off the arguments to begin the capture and inspect loop
	var config Config

	flag.StringVar(&config.Interface, "interface", "", "Interface to run the capture loop on")
	flag.StringVar(&config.Interface, "i", "", "Interface to run the capture loop on")

	flag.StringVar(&config.Filter, "filter", "tcp", "BPF filter to apply")
	flag.StringVar(&config.Filter, "f", "tcp", "BPF filter to apply")

	flag.StringVar(&config.PcapFile, "pcap", "", "Read from a pcap file instead of an interface")
	flag.StringVar(&config.PcapFile, "p", "", "Read from a pcap file instead of an interface")

	flag.StringVar(&config.SaveResults, "save-results", "", "Save results into a pcap file")
	flag.StringVar(&config.SaveResults, "s", "", "Save results into a pcap file")

	flag.Parse()

}
