package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"net"
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


func printARP(arp *layers.ARP) {
	fmt.Println("    └──────────────────────[ARP]───────────────────────────")
	fmt.Printf("        ├── Hardware Type     : %v\n", arp.AddrType)
	fmt.Printf("        ├── Protocol Type     : %v\n", arp.Protocol)
	fmt.Printf("        ├── HW Addr Length    : %d\n", arp.HwAddressSize)
	fmt.Printf("        ├── Proto Addr Length : %d\n", arp.ProtAddressSize)
	fmt.Printf("        ├── Operation         : %d\n", arp.Operation)
	fmt.Printf("        ├── Sender MAC        : %s\n", net.HardwareAddr(arp.SourceHwAddress))
	fmt.Printf("        ├── Sender IP         : %s\n", net.IP(arp.SourceProtAddress))
	fmt.Printf("        ├── Target MAC        : %s\n", net.HardwareAddr(arp.DstHwAddress))
	fmt.Printf("        └── Target IP         : %s\n", net.IP(arp.DstProtAddress))
}

func printICMPv4(icmpv4 *layers.ICMPv4) {
	fmt.Println("        └─────────────────────[ICMPv4]─────────────────────")
	fmt.Printf("            ├── Type             : %d\n", icmpv4.TypeCode.Type())
	fmt.Printf("            ├── Code             : %d\n", icmpv4.TypeCode.Code())
	fmt.Printf("            ├── Checksum         : %d\n", icmpv4.Checksum)
	fmt.Printf("            └── Payload Length    : %d bytes\n", len(icmpv4.Payload))
	fmt.Printf("            └── Payload (hex)     : % X\n", icmpv4.Payload)
}

func printICMPv6(icmpv6 *layers.ICMPv6) {
	fmt.Println("        └────────────────────[ICMPv6]──────────────────────")
	fmt.Printf("            ├── Type             : %d\n", icmpv6.TypeCode.Type())
	fmt.Printf("            ├── Code             : %d\n", icmpv6.TypeCode.Code())
	fmt.Printf("            ├── Checksum         : %d\n", icmpv6.Checksum)
	fmt.Printf("            └── Payload Length   : %d bytes\n", len(icmpv6.Payload))
	fmt.Printf("            └── Payload (hex)    : % X\n", icmpv6.Payload)
}

func printDNS(dns *layers.DNS){
	fmt.Println("            └──────────────────────[DNS]───────────────────────")
	fmt.Printf("                ├── ID                : %d\n", dns.ID)
	fmt.Printf("                ├── QR (Query/Resp)   : %t\n", dns.QR)
	fmt.Printf("                ├── OpCode            : %d\n", dns.OpCode)
	fmt.Printf("                ├── Authoritative     : %t\n", dns.AA)
	fmt.Printf("                ├── Truncated         : %t\n", dns.TC)
	fmt.Printf("                ├── Recursion Desired : %t\n", dns.RD)
	fmt.Printf("                ├── Recursion Avail.  : %t\n", dns.RA)
	fmt.Printf("                ├── Z (reserved)      : %d\n", dns.Z)
	fmt.Printf("                ├── Response Code     : %d\n", dns.ResponseCode)
	fmt.Printf("                ├── Questions         : %d\n", dns.QDCount)
	fmt.Printf("                ├── Answers           : %d\n", dns.ANCount)
	fmt.Printf("                ├── Authorities       : %d\n", dns.NSCount)
	fmt.Printf("                └── Additionals       : %d\n", dns.ARCount)

	// Questions
	if len(dns.Questions) > 0 {
		fmt.Println("                    Questions:")
		for _, q := range dns.Questions {
			fmt.Printf("                    - %s (%s)\n", string(q.Name), q.Type)
		}
	}

	
	// Answers
	if len(dns.Answers) > 0 {
		fmt.Println("                    Answers:")
		for _, a := range dns.Answers {
			fmt.Printf("                    - %s (%s) TTL=%ds Data=%X\n",
				string(a.Name), a.Type, a.TTL, a.Data)
		}
	}

	// Authorities
	if len(dns.Authorities) > 0 {
		fmt.Println("                   Authorities:")
		for _, a := range dns.Authorities {
			fmt.Printf("                    - %s (%s) TTL=%ds Data=%X\n",
				string(a.Name), a.Type, a.TTL, a.Data)
		}
	}

	// Additionals
	if len(dns.Additionals) > 0 {
		fmt.Println("                   Additionals:")
		for _, a := range dns.Additionals {
			fmt.Printf("                    - %s (%s) TTL=%ds Data=%X\n",
				string(a.Name), a.Type, a.TTL, a.Data)
		}
	}
}






func main() {
	//Help & Arguments
	var ipFilter string
	var portFilter int
	var macFilter string
	var bpf string
	flag.StringVar(&ipFilter, "ip", "", "Filter by IPv4")
	flag.IntVar(&portFilter, "port", 0, "Filter by Port")
	flag.StringVar(&macFilter, "mac", "", "Filter by MAC")
	flag.StringVar(&bpf, "bpf", "", "Berkley Package Filter")

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

	//
	for packet := range packetSource.Packets() {
		

		//Separate Layer
		eth := packet.Layer(layers.LayerTypeEthernet)
		  arp := packet.Layer(layers.LayerTypeARP)

		ip4 := packet.Layer(layers.LayerTypeIPv4)
          icmpv4 := packet.Layer(layers.LayerTypeICMPv4)

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
			printARP(arp.(*layers.ARP))
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
			printICMPv4(icmpv4.(*layers.ICMPv4))
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
			printICMPv6(icmpv6.(*layers.ICMPv6))
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

		if dns != nil {
			printDNS(dns.(*layers.DNS))
		}

		
		fmt.Println("────────────────────────────────────────────────────────────────────────")
	}
}
