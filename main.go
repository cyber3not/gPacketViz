package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
	"path/filepath"
	"gPacketViz/printer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
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
	var macFilter string
	var bpf string
	var savePath string
	flag.StringVar(&ipFilter, "ip", "", "Filter by IPv4")
	flag.IntVar(&portFilter, "port", 0, "Filter by Port")
	flag.StringVar(&macFilter, "mac", "", "Filter by MAC")
	flag.StringVar(&bpf, "bpf", "", "Berkley Package Filter")
	flag.StringVar(&savePath, "out", "", "Save to pcap file")

	flag.Usage = func() {
		progName := filepath.Base(os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage: %s <Interface or Capture File> [options]\n", progName)
		flag.PrintDefaults()
	}

	flag.Parse()

	// Check for missing args
	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Missing Interface or Capture File!")
		flag.Usage()
		os.Exit(1)
	}

	

	// Open Input
	input := args[0]
	fmt.Println("Input:", input)

	var handle *pcap.Handle
	var err error
	isFile := false

	if _, err := os.Stat(input); err == nil {
		isFile = true
	}

	if isFile {
		fmt.Println("Reading from file:", input)
		handle, err = pcap.OpenOffline(input)
	} else {
		fmt.Println("Sniffing on interface:", input)
		handle, err = pcap.OpenLive(input, 1600, true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatalf("Error opening input: %v", err)
	}
	defer handle.Close()


	var outputFile *os.File
	var writer *pcapgo.Writer

	if savePath != "" {
		outputFile, err = os.Create(savePath)
		if err != nil {
			log.Fatalf("Failed to create output file: %v", err)
		}
		writer = pcapgo.NewWriter(outputFile)
		err = writer.WriteFileHeader(1600, layers.LinkTypeEthernet)
		if err != nil {
			log.Fatalf("Failed to write pcap header: %v", err)
		}
		fmt.Println("Saving packets to:", savePath)
		defer outputFile.Close()
	}

	

	// Start packet processing
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Filter Logic
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

    if macFilter != "" {
		if filter != ""{
			filter += " and "
		}
		filter += fmt.Sprintf("ether host %s", macFilter)
	}

	//BPF Filter
	if bpf != ""{
		filter = bpf
	}

	//Set Filter
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	if bpf != "" {
		fmt.Println("Using custom BPF filter:", bpf)
	} else if filter != "" {
		fmt.Println("Using generated filter:", filter)
	} else {
		fmt.Println("No filter applied – capturing all packets")
	}

	//Packet-Loop
	for packet := range packetSource.Packets() {
		if writer != nil {
			err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Printf("Warning: failed to write packet: %v", err)
			}
		}

		//Separate Layer
		eth := packet.Layer(layers.LayerTypeEthernet)
		  arp := packet.Layer(layers.LayerTypeARP)

		ip4 := packet.Layer(layers.LayerTypeIPv4)
          icmpv4 := packet.Layer(layers.LayerTypeICMPv4)
		  igmp := packet.Layer(layers.LayerTypeIGMP)
		  dhcpv4 := packet.Layer(layers.LayerTypeDHCPv4)

		ip6 := packet.Layer(layers.LayerTypeIPv6)
		  icmpv6 := packet.Layer(layers.LayerTypeICMPv6)

		tcp := packet.Layer(layers.LayerTypeTCP)
		udp := packet.Layer(layers.LayerTypeUDP)
	    	dns := packet.Layer(layers.LayerTypeDNS)
		  

		

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

		// Unhandled Ethernet payload
		if arp != nil {
			printer.PrintARP(arp.(*layers.ARP))
		} else if eth != nil && ip4 == nil && ip6 == nil {
			ethernetLayer := eth.(*layers.Ethernet)
			fmt.Printf("        └── Next protocol: %s\n", ethernetLayer.EthernetType)
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

		// Unhandled IPv4 payload
		if icmpv4 != nil {
			printer.PrintICMPv4(icmpv4.(*layers.ICMPv4))
		} else if igmp != nil {
				printer.PrintIGMP(packet)
		} else if ip4 != nil && tcp == nil && udp == nil {
			ip4Layer := ip4.(*layers.IPv4)
			fmt.Printf("        └── Next protocol %s\n", ip4Layer.Protocol)
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

		// Unhandled IPv6 payload
		if icmpv6 != nil {
			printer.PrintICMPv6(icmpv6.(*layers.ICMPv6))
		} else if ip6 != nil && tcp == nil && udp == nil {
			ip6Layer := ip6.(*layers.IPv6)
			fmt.Printf("        └── Next Header: %s\n", ip6Layer.NextHeader)
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

		if dhcpv4 != nil {
			printer.PrintDHCPv4(dhcpv4.(*layers.DHCPv4))
		}
		if dns != nil {
			printer.PrintDNS(dns.(*layers.DNS))
		}

		
		fmt.Println("────────────────────────────────────────────────────────────────────────")
	}
}
