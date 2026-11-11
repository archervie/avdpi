package main

import (
	"flag"
	"log"

	"avdpi/internal/capture"
	"avdpi/internal/parser"
	"avdpi/internal/ui"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// We parse the command line operations directly here before
	// passing off the arguments to begin the capture and inspect loop
	var config capture.Config

	flag.StringVar(&config.Interface, "interface", "", "Interface to run the capture loop on")
	flag.StringVar(&config.Interface, "i", "", "Interface to run the capture loop on")

	flag.StringVar(&config.Filter, "filter", "", "BPF filter to apply")
	flag.StringVar(&config.Filter, "f", "", "BPF filter to apply")

	// Feature is currently unsupported, support will be added with time
	// 	flag.StringVar(&config.PcapFile, "pcap", "", "Read from a pcap file instead of an interface")
	// 	flag.StringVar(&config.PcapFile, "p", "", "Read from a pcap file instead of an interface")
	//
	// 	flag.StringVar(&config.SaveResults, "save-results", "", "Save results into a pcap file")
	// 	flag.StringVar(&config.SaveResults, "s", "", "Save results into a pcap file")

	flag.Parse()

	if err := capture.ResolveConfig(&config); err != nil {
		log.Fatalf("Configuration error: %v\n", err)
	}

	if config.Filter != "" {
		_, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 2048, config.Filter)
		if err != nil {
			log.Fatalf("Invalid BPF filter %q: %v\n", config.Filter, err) // Exits immediately, UI never starts
		}
	}

	packetChan := make(chan parser.PacketData, 1000)

	go func() {
		if err := capture.Start(config, packetChan); err != nil {
			log.Fatalf("Capture error: %v\n", err)
		}
	}()

	if err := ui.Start(config, packetChan); err != nil {
		log.Fatalf("UI error: %v\n", err)
	}
}
