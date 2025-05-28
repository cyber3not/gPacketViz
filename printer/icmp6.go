package printer

import (
	"fmt"
	"github.com/google/gopacket/layers"
)

func PrintICMPv6(icmpv6 *layers.ICMPv6) {
	fmt.Println("        └────────────────────[ICMPv6]──────────────────────")
	fmt.Printf("            ├── Type             : %d\n", icmpv6.TypeCode.Type())
	fmt.Printf("            ├── Code             : %d\n", icmpv6.TypeCode.Code())
	fmt.Printf("            ├── Checksum         : %d\n", icmpv6.Checksum)
	fmt.Printf("            └── Payload Length   : %d bytes\n", len(icmpv6.Payload))
	fmt.Printf("            └── Payload (hex)    : % X\n", icmpv6.Payload)
}
