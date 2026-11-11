package capture

import (
	"fmt"
	"time"

	"avdpi/internal/parser"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gopacket/gopacket/afpacket"
	"golang.org/x/net/bpf"
)

type Config struct {
	Interface   string
	Filter      string
	PcapFile    string
	SaveResults string
}

// ResolveConfig verifies the interface before the app starts
func ResolveConfig(config *Config) error {
	if config.Interface == "" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return fmt.Errorf("Failed to find devices: %w", err)
		}
		if len(devices) == 0 {
			return fmt.Errorf("No interfaces found")
		}
		config.Interface = devices[0].Name
	}
	return nil
}

// Start initializes the AF_PACKET TPACKET_v3 socket and runs the capture loop
func Start(config Config, packetChan chan<- parser.PacketData) error {

	// 1. Open the ring-buffer backed socket
	tpacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(config.Interface),
		afpacket.OptFrameSize(2048),     // Maximum buffer size per frame
		afpacket.OptBlockSize(2048*128), // Size of memory block allocated in kernel
		afpacket.OptNumBlocks(128),      // Number of blocks in the ring buffer
		afpacket.OptPollTimeout(10*time.Millisecond),
	)
	if err != nil {
		return fmt.Errorf("Failed to create TPacket handle: %w", err)
	}
	defer tpacket.Close()

	// 2. Compile and apply the BPF filter if specified
	if config.Filter != "" {
		// Compile standard libpcap filter expression for Ethernet frames
		pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 2048, config.Filter)
		if err != nil {
			return fmt.Errorf("Failed to compile BPF filter %q: %w", config.Filter, err)
		}

		// Translate pcap.BPFInstruction slice into golang.org/x/net/bpf instructions
		bpfIns := make([]bpf.RawInstruction, len(pcapBPF))
		for i, ins := range pcapBPF {
			bpfIns[i] = bpf.RawInstruction{
				Op: ins.Code,
				Jt: ins.Jt,
				Jf: ins.Jf,
				K:  ins.K,
			}
		}

		// Apply the filter to the socket kernel-side
		if err := tpacket.SetBPF(bpfIns); err != nil {
			return fmt.Errorf("Failed to set BPF filter: %w", err)
		}
	}

	for {
		// ZeroCopyReadPacketData pulls the frame straight from the ring buffer
		data, _, err := tpacket.ZeroCopyReadPacketData()
		if err != nil {
			continue
		}

		packetData := parser.Parse(data)

		if packetData.Protocol != "" {
			select {
			case packetChan <- packetData:
			default:
			}
		}
	}
}
