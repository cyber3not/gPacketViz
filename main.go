package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func colorFlag(flag bool) string {
	if flag {
		return "\033[32mtrue\033[0m" // green
	}
	return "\033[31mfalse\033[0m"    //red
}

func main() {
	//Help & Arguments
	var ipFilter string
	var portFilter int
	flag.StringVar(&ipFilter, "ip", "", "Filter by IPv4")
	flag.IntVar(&portFilter, "port", 0, "Filter by Port")

	flag.Usage = func() {
		progName := filepath.Base(os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage: %s <interface> [options]\n", progName)
		flag.PrintDefaults()
	}

	flag.Parse()

	// Check for missing args
	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Missing interface!")
		flag.Usage()
		os.Exit(1)
	}

	// Open device
	iface := args[0]
	fmt.Println("Sniffing on interface:", iface)
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error Opening Device: %v\n", err)
		os.Exit(1)
	}
	defer handle.Close()

	// Start packet processing
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Set filter
	var filter string

	if portFilter != 0 {
		filter += fmt.Sprintf("port %d", portFilter)
	}

	if ipFilter != "" {
		if filter != "" {
			filter += " and "
		}
		filter += fmt.Sprintf("host %s", ipFilter)
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Only capturing ...", ipFilter)

	//
	for packet := range packetSource.Packets() {
		

		//Separate Layer
		eth := packet.Layer(layers.LayerTypeEthernet)
		ip4 := packet.Layer(layers.LayerTypeIPv4)
		ip6 := packet.Layer(layers.LayerTypeIPv6)
		tcp := packet.Layer(layers.LayerTypeTCP)
		udp := packet.Layer(layers.LayerTypeUDP)

		//Output
		fmt.Printf("[%s]Received Package:───────────────────────────────────────────── \n", time.Now().Format("15:04:05"))
		if eth != nil {
			ethernetLayer := eth.(*layers.Ethernet)
			fmt.Println("└───────────────────[Ethernet]────────────────────────────")
			fmt.Printf("    ├── DstMAC       : %s\n", ethernetLayer.DstMAC)
			fmt.Printf("    ├── SrcMAC       : %s\n", ethernetLayer.SrcMAC)
			fmt.Printf("    ├── EtherType    : %s\n", ethernetLayer.EthernetType)
			fmt.Printf("    └── Length       : %d\n", ethernetLayer.Length)
		}
		if ip4 != nil {
			ip4Layer := ip4.(*layers.IPv4)
			fmt.Println("    └─────────────────────[IPv4]──────────────────────────")
			fmt.Printf("        ├── Version        : %d\n", ip4Layer.Version)
			fmt.Printf("        ├── IHL            : %d\n", ip4Layer.IHL)
			fmt.Printf("        ├── TOS            : %d\n", ip4Layer.TOS)
			fmt.Printf("        ├── Length         : %d\n", ip4Layer.Length)
			fmt.Printf("        ├── ID             : %d\n", ip4Layer.Id)
			fmt.Printf("        ├── Flags          : %s\n", ip4Layer.Flags)
			fmt.Printf("        ├── FragOffset     : %d\n", ip4Layer.FragOffset)
			fmt.Printf("        ├── TTL            : %d\n", ip4Layer.TTL)
			fmt.Printf("        ├── Protocol       : %s\n", ip4Layer.Protocol)
			fmt.Printf("        ├── Checksum       : %d\n", ip4Layer.Checksum)
			fmt.Printf("        ├── SrcIP          : %s\n", ip4Layer.SrcIP)
			fmt.Printf("        └── DstIP          : %s\n", ip4Layer.DstIP)
		}
		if ip6 != nil {
			ip6Layer := ip6.(*layers.IPv6)
			fmt.Println("    └─────────────────────[IPv6]──────────────────────────")
			fmt.Printf("        ├── Version        : %d\n", ip6Layer.Version)
			fmt.Printf("        ├── Traffic Class  : %d\n", ip6Layer.TrafficClass)
			fmt.Printf("        ├── Flow Label     : %d\n", ip6Layer.FlowLabel)
			fmt.Printf("        ├── Length         : %d\n", ip6Layer.Length)
			fmt.Printf("        ├── Next Header    : %s\n", ip6Layer.NextHeader)
			fmt.Printf("        ├── Hop Limit      : %d\n", ip6Layer.HopLimit)
			fmt.Printf("        ├── SrcIP          : %s\n", ip6Layer.SrcIP)
			fmt.Printf("        └── DstIP          : %s\n", ip6Layer.DstIP)
		}
		if tcp != nil {	
			tcpLayer := tcp.(*layers.TCP)
			fmt.Println("        └──────────────────────[TCP]──────────────────────")
			fmt.Printf("            ├── SrcPort         : %d\n", tcpLayer.SrcPort)
			fmt.Printf("            ├── DstPort         : %d\n", tcpLayer.DstPort)
			fmt.Printf("            ├── Sequence Number : %d\n", tcpLayer.Seq)
			fmt.Printf("            ├── ACK Number      : %d\n", tcpLayer.Ack)
			fmt.Printf("            ├── Data Offset     : %d\n", tcpLayer.DataOffset)
			fmt.Printf("            ├── Flags           : SYN=%s ACK=%s RST=%s FIN=%s PSH=%s URG=%s\n",	colorFlag(tcpLayer.SYN), colorFlag(tcpLayer.ACK), colorFlag(tcpLayer.RST), colorFlag(tcpLayer.FIN), colorFlag(tcpLayer.PSH), colorFlag(tcpLayer.URG))		
			fmt.Printf("            ├── Window          : %d\n", tcpLayer.Window)
			fmt.Printf("            ├── Checksum        : %d\n", tcpLayer.Checksum)
			fmt.Printf("            └── Urgent Pointer  : %d\n", tcpLayer.Urgent)
		}
		if udp != nil {
			udpLayer := udp.(*layers.UDP)
			fmt.Println("        └──────────────────────[UDP]──────────────────────")
			fmt.Printf("            ├── SrcPort         : %d\n", udpLayer.SrcPort)
			fmt.Printf("            ├── DstPort         : %d\n", udpLayer.DstPort)
			fmt.Printf("            ├── Length          : %d\n", udpLayer.Length)
			fmt.Printf("            └── Checksum        : %X\n", udpLayer.Checksum)
		}
		fmt.Println("────────────────────────────────────────────────────────────────────────\n")
	}
}
