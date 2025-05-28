package printer

import (
	"fmt"
	"github.com/google/gopacket/layers"
)

func PrintDNS(dns *layers.DNS){
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
