package parser

import (
	"fmt"
	"net"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type PacketData struct {
	// Layer 2
	SrcMAC string
	DstMAC string
	// Layer 3
	SrcIP      string
	DstIP      string
	ARPPayload string
	TTL        uint8
	IPChecksum uint16
	// Layer 4
	Protocol      string
	SrcPort       int
	DstPort       int
	TCPFlags      string
	DomainQueried string
	TCPChecksum   uint16
	// Layer 7
	PayloadSize int
	Payload     []byte
}

func Parse(frame []byte) PacketData {
	var data PacketData
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)

	// Ethernet Layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		data.SrcMAC = eth.SrcMAC.String()
		data.DstMAC = eth.DstMAC.String()
	}

	// ARP Parsing
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		data.Protocol = "ARP"
		// ARP stores IP addresses as raw byte slices, so we convert them using net.IP
		data.SrcIP = net.IP(arp.SourceProtAddress).String()
		data.DstIP = net.IP(arp.DstProtAddress).String()

		switch arp.Operation {
		case layers.ARPRequest:
			data.ARPPayload = fmt.Sprintf("Who has %s? Tell %s", data.DstIP, data.SrcIP)
		case layers.ARPReply:
			data.ARPPayload = fmt.Sprintf("%s is at %s", data.SrcIP, net.HardwareAddr(arp.SourceHwAddress))
		}
		return data
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		data.SrcIP = ip.SrcIP.String()
		data.DstIP = ip.DstIP.String()
		data.TTL = ip.TTL
		data.IPChecksum = ip.Checksum

	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6, _ := ip6Layer.(*layers.IPv6)
		data.SrcIP = ip6.SrcIP.String()
		data.DstIP = ip6.DstIP.String()
		data.TTL = ip6.HopLimit
	}

	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		data.Protocol = "ICMP"
		return data
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		data.Protocol = "TCP"
		data.SrcPort = int(tcp.SrcPort)
		data.DstPort = int(tcp.DstPort)
		data.TCPChecksum = tcp.Checksum

		if tcp.SYN {
			data.TCPFlags += "SYN "
		}
		if tcp.ACK {
			data.TCPFlags += "ACK "
		}
		if tcp.PSH {
			data.TCPFlags += "PSH "
		}
		if tcp.FIN {
			data.TCPFlags += "FIN "
		}
		if tcp.RST {
			data.TCPFlags += "RST "
		}
		if tcp.URG {
			data.TCPFlags += "URG "
		}

	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		data.Protocol = "UDP"
		data.SrcPort = int(udp.SrcPort)
		data.DstPort = int(udp.DstPort)
	}

	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		data.Protocol = "DNS"

		dns, _ := dnsLayer.(*layers.DNS)
		if len(dns.Questions) > 0 {
			data.DomainQueried = string(dns.Questions[0].Name)
		}
	}

	// Application layer
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		data.Payload = appLayer.Payload()
		data.PayloadSize = len(data.Payload)

		// DPI Heuristics for HTTP/HTTPS
		if data.Protocol == "TCP" {
			payloadStr := string(data.Payload)

			// HTTP requests start with methods. HTTP responses start with "HTTP/"
			if strings.HasPrefix(payloadStr, "GET ") ||
				strings.HasPrefix(payloadStr, "POST ") ||
				strings.HasPrefix(payloadStr, "HTTP/") {
				data.Protocol = "HTTP"
				// Note: Actual DPI to be added later, but for now this quick
				// assumption is enough
			} else if data.SrcPort == 443 || data.DstPort == 443 {
				data.Protocol = "HTTPS"
			}
		}
	}

	return data
}
