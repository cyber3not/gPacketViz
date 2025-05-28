package printer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Entry point from main
func PrintIGMP(packet gopacket.Packet) {
	layer := packet.Layer(layers.LayerTypeIGMP)
	if layer == nil {
		return
	}

	switch igmp := layer.(type) {
	case *layers.IGMPv1or2:
		printIGMPv1v2(igmp)
	case *layers.IGMP:
		printIGMPv3(igmp)
	default:
		fmt.Println("        └── IGMP: Unrecognized IGMP version or type")
	}
}

func printIGMPv1v2(igmp *layers.IGMPv1or2) {
	fmt.Println("        └─────────────────────[IGMPv1/v2]────────────────────")
	fmt.Printf("            ├── Type         : %s\n", igmp.Type)
	fmt.Printf("            ├── Max Resp     : %s\n", igmp.MaxResponseTime)
	fmt.Printf("            ├── Checksum     : %d\n", igmp.Checksum)
	fmt.Printf("            └── Group Addr   : %s\n", igmp.GroupAddress)
	fmt.Printf("            └── Version      : %d\n", igmp.Version)
}

func printIGMPv3(igmp *layers.IGMP) {
	fmt.Println("        └──────────────────────[IGMPv3]──────────────────────")
	fmt.Printf("            ├── Type              : %s\n", igmp.Type)
	fmt.Printf("            ├── Checksum          : %d\n", igmp.Checksum)
	fmt.Printf("            ├── Group Address     : %s\n", igmp.GroupAddress)
	fmt.Printf("            ├── SuppressRP        : %t\n", igmp.SupressRouterProcessing)
	fmt.Printf("            ├── Robustness Value  : %d\n", igmp.RobustnessValue)
	fmt.Printf("            ├── Interval Time     : %s\n", igmp.IntervalTime)
	for i, src := range igmp.SourceAddresses {
		fmt.Printf("                Source[%d]        : %s\n", i, src)
	}
	fmt.Printf("            ├── Group Record Count: %d\n", igmp.NumberOfGroupRecords)
    fmt.Printf("            ├── Source Count      : %d\n", igmp.NumberOfSources)
	for i, rec := range igmp.GroupRecords {
		fmt.Printf("            ├── Record[%d] Type   : %s\n", i, rec.Type)
		fmt.Printf("            │   └── Group         : %s\n", rec.MulticastAddress)
		for j, sa := range rec.SourceAddresses {
			fmt.Printf("            │       Source[%d]    : %s\n", j, sa)
		}
	}	
	fmt.Printf("            ├── Version           : %d\n", igmp.Version)
}
