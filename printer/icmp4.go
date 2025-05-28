package printer

import (
	"fmt"
	"github.com/google/gopacket/layers"
)

func PrintICMPv4(icmpv4 *layers.ICMPv4) {
	fmt.Println("        └─────────────────────[ICMPv4]─────────────────────")
	fmt.Printf("            ├── Type             : %d\n", icmpv4.TypeCode.Type())
	fmt.Printf("            ├── Code             : %d\n", icmpv4.TypeCode.Code())
	fmt.Printf("            ├── Checksum         : %d\n", icmpv4.Checksum)
	fmt.Printf("            └── Payload Length   : %d bytes\n", len(icmpv4.Payload))
	fmt.Printf("            └── Payload (hex)    : % X\n", icmpv4.Payload)
}
