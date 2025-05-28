package printer

import (
	"fmt"
	"net"
	"github.com/google/gopacket/layers"
)

func PrintARP(arp *layers.ARP) {
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
