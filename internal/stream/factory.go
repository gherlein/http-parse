package stream

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/pcap-analyzer/internal/dns"
	httpstream "github.com/pcap-analyzer/internal/http"
)

type Factory struct {
	dnsCache *dns.Cache
}

func NewFactory(dnsCache *dns.Cache) *Factory {
	return &Factory{
		dnsCache: dnsCache,
	}
}

func (f *Factory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	hstream := &httpstream.Stream{}
	// Access private fields using reflection would be needed here,
	// but for simplicity, we'll create a wrapper
	reader := &tcpReader{
		ident:    fmt.Sprintf("%s:%s", net, transport),
		isClient: true,
		stream:   hstream,
		factory:  f,
	}

	go func() {
		// This would need to be implemented properly with the actual HTTP stream logic
		// For now, this is a placeholder
	}()

	return reader
}

type tcpReader struct {
	ident    string
	isClient bool
	stream   *httpstream.Stream
	factory  *Factory
}

func (t *tcpReader) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	length, _ := sg.Lengths()
	data := sg.Fetch(length)
	// Implementation needed - would write to stream buffer
	_ = data
}

func (t *tcpReader) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	return false
}

func (t *tcpReader) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, seq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return true
}
