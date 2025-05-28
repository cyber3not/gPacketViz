package printer

import (
	"fmt"
	"net"
	"github.com/google/gopacket/layers"
)

func PrintDHCPv4(dhcpv4 *layers.DHCPv4) {
	fmt.Println("            └────────────────────[DHCPv4]────────────────────")
	fmt.Printf("                ├── Operation        : %s\n", dhcpv4.Operation)
	fmt.Printf("                ├── Hardware Type    : %d\n", dhcpv4.HardwareType)
	fmt.Printf("                ├── Hardware Len     : %d\n", dhcpv4.HardwareLen)
	fmt.Printf("                ├── Relay Hops       : %d\n")
	fmt.Printf("                ├── Transaction ID   : 0x%X\n", dhcpv4.Xid)
	fmt.Printf("                ├── Seconds Elapsed  : %d\n", dhcpv4.Secs)
	fmt.Printf("                ├── Flags            : 0x%X\n", dhcpv4.Flags)
	fmt.Printf("                ├── Client IP        : %s\n", dhcpv4.ClientIP)
	fmt.Printf("                ├── Your Client IP   : %s\n", dhcpv4.YourClientIP)
	fmt.Printf("                ├── Next Server IP   : %s\n", dhcpv4.NextServerIP)
	fmt.Printf("                ├── Relay Agent IP   : %s\n", dhcpv4.RelayAgentIP)
	fmt.Printf("                ├── Client HW Addr   : %s\n", net.HardwareAddr(dhcpv4.ClientHWAddr))
	fmt.Printf("                ├── Server Name      : %s\n", dhcpv4.ServerName)
	fmt.Printf("                ├── File             : %s\n", dhcpv4.File)
	fmt.Printf("                ├── DHCP Options     : %s\n", dhcpv4.Options)
}
