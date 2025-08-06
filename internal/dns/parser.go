package dns

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

func ParsePacket(packet gopacket.Packet, cache *Cache) {
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dnsPacket, _ := dnsLayer.(*layers.DNS)
		
		msg := new(dns.Msg)
		if err := msg.Unpack(dnsPacket.Contents); err != nil {
			return
		}
		
		if msg.Response && len(msg.Question) > 0 {
			question := msg.Question[0].Name
			fmt.Printf("\n=== DNS Response ===\n")
			fmt.Printf("Time: %s\n", packet.Metadata().Timestamp.Format(time.RFC3339))
			fmt.Printf("Query: %s\n", question)
			
			for _, answer := range msg.Answer {
				switch rr := answer.(type) {
				case *dns.A:
					fmt.Printf("  A Record: %s -> %s\n", rr.Hdr.Name, rr.A.String())
					cache.Add(rr.A.String(), rr.Hdr.Name)
				case *dns.AAAA:
					fmt.Printf("  AAAA Record: %s -> %s\n", rr.Hdr.Name, rr.AAAA.String())
					cache.Add(rr.AAAA.String(), rr.Hdr.Name)
				case *dns.CNAME:
					fmt.Printf("  CNAME Record: %s -> %s\n", rr.Hdr.Name, rr.Target)
				}
			}
		} else if !msg.Response && len(msg.Question) > 0 {
			question := msg.Question[0].Name
			qtype := dns.TypeToString[msg.Question[0].Qtype]
			
			fmt.Printf("\n=== DNS Query ===\n")
			fmt.Printf("Time: %s\n", packet.Metadata().Timestamp.Format(time.RFC3339))
			fmt.Printf("Query: %s (Type: %s)\n", question, qtype)
		}
	}
}