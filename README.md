# avdpi

**avdpi** is a terminal-based packet capture and deep packet inspection (DPI) tool built in Go. It delivers real-time network traffic analysis through a terminal user interface (TUI) powered by `tview`.

---

## High-Performance Packet Capture: `AF_PACKET` & `TPACKET_V3`

Traditional packet capture methods (`PF_PACKET` sockets with raw system calls) suffer from significant CPU overhead due to frequent context switches and buffer copies between kernel space and user space for every captured frame.

`avdpi` bypasses this bottleneck by utilizing Linux **`AF_PACKET` sockets** configured with the **`TPACKET_V3`** capture ring buffer:

- **Direct Kernel Ring Buffer:** Creates a memory-mapped ring buffer shared directly between the Linux kernel and user space. Packets captured by the network interface card (NIC) are copied directly into pre-allocated kernel memory blocks.
- **Zero-Copy Reads:** Packets are processed via zero-copy semantics (`tpacket.ZeroCopyReadPacketData()`), extracting raw frame data directly from the active ring buffer without duplicating memory.
- **Variable Frame Sizing & Block Batches:** `TPACKET_V3` introduces dynamic block allocation, packing variable-length packets efficiently into memory blocks (configured at `2048 * 128` bytes across 128 blocks) and notifying user space via polling timeouts rather than per-packet interrupts.
- **Kernel-Level BPF Filtering:** User-specified BPF filter strings are compiled and attached directly to the socket at the kernel layer using `tpacket.SetBPF()`. Frames that do not match the filter are discarded before ever reaching user space or consuming ring buffer capacity.

---

## Supported Protocols & Layers

`avdpi` parses packet layers directly from raw Ethernet frames without unneeded allocations:

| Layer                     | Protocol        | Parsed Metadata & Features                                                               |
| :------------------------ | :-------------- | :--------------------------------------------------------------------------------------- |
| **Layer 2 (Data Link)**   | **Ethernet II** | Source and destination MAC addresses                                                     |
|                           | **ARP**         | Request/Reply operations, hardware-to-protocol address resolutions                       |
| **Layer 3 (Network)**     | **IPv4**        | Source/Destination IP, TTL, IP Header Checksum                                           |
|                           | **IPv6**        | Source/Destination IP, Hop Limit                                                         |
| **Layer 4 (Transport)**   | **TCP**         | Source/Destination ports, Checksum, TCP Flags (`SYN`, `ACK`, `PSH`, `FIN`, `RST`, `URG`) |
|                           | **UDP**         | Source/Destination ports                                                                 |
|                           | **ICMPv4**      | Packet identification                                                                    |
| **Layer 7 (Application)** | **DNS**         | Intercepts standard queries and extracts requested domain names                          |
|                           | **HTTP**        | Signature-based heuristic inspection (`GET`, `POST`, `HTTP/`)                            |
|                           | **HTTPS**       | Port-based identification (TCP 443)                                                      |
|                           | **Raw Payload** | Live hexadecimal and ASCII payload inspector (`hex.Dump`)                                |

---

## Prerequisites

Because `AF_PACKET` sockets interact directly with the Linux network stack and `pcap` BPF compilation tools are used:

- **Operating System:** Linux (Linux kernel 3.2+ required for `TPACKET_V3`).
- **C Libraries:** `libpcap` development headers (`libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on Fedora/RHEL/CentOS, `libpcap` on Arch).
- **Go Compiler:** Go 1.20 or newer.
- **Privileges:** `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities (or root access) to open raw sockets and toggle promiscuous mode.

---

## Installation & Setup

### 1. Install Dependencies

On Debian/Ubuntu-based distributions:

```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev build-essential
```

On Fedora/RHEL-based distributions:

```bash
sudo dnf install -y libpcap-devel gcc
```

On Arch-based distributions:

```bash
sudo pacman -S libpcap gcc
```

### 2. Clone and Build

```bash
git clone [https://github.com/your-username/avdpi.git](https://github.com/your-username/avdpi.git)
cd avdpi
go mod tidy
go build -o avdpi cmd/avdpi/main.go
```

### 3. Grant Permissions

To run `avdpi` without sudo every time, apply the following permissions:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./avdpi
```

---

## Usage

`./avdpi [flags]`

Command-line Options:

- `--interface, -i`: Network interface to run the capture loop on (default: first available interface)
- `--filter, -f`: Berkeley Packet Filter (BPF) expression to apply to the loop (default: none)

---

## Examples

1. Capture on default interface:
   `./avdpi`

2. Capture on a specific network interface:
   `./avdpi -i eth0`

3. Capture only HTTP/HTTPS traffic:
   `./avdpi -i wlan0 -f "tcp port 80 or tcp port 443"`

4. Filter for specific host traffic:
   `./avdpi -i eth0 -f "host 192.168.1.1 and not arp"`

---

## Interactive Navigation

- Up/Down Arrow Keys: Select the packet in the table to pause auto-scrolling and inspect header details and payload details
- Mouse Support: Use the mouse to select packets on the table.
- Exit: Press Ctrl+C in the terminal to stop capture and quit

---

## Disclaimer

This tool was created for proper use in a controlled environment. Always have permission to capture on a specific interface by the network's administration.
