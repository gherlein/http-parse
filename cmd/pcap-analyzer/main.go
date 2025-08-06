package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"github.com/pcap-analyzer/internal/dns"
)

type HTTPStream struct {
	net, transport gopacket.Flow
	r              tcpReader
	reversed       bool
}

type tcpReader struct {
	bytes.Buffer
	ident    string
	isClient bool
	parent   *HTTPStream
}

func (t *tcpReader) Read(p []byte) (int, error) {
	n, err := t.Buffer.Read(p)
	return n, err
}

type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

type tcpStreamFactory struct {
	dnsCache *dns.Cache
}

func (h *HTTPStream) run(dnsCache *dns.Cache) {
	buf := bufio.NewReader(&h.r)
	for {
		if h.r.isClient {
			req, err := http.ReadRequest(buf)
			if err != nil {
				return
			}

			srcIP := h.net.Src().String()
			dstIP := h.net.Dst().String()
			srcPort := h.transport.Src().String()
			dstPort := h.transport.Dst().String()

			srcFQDN, _ := dnsCache.Get(srcIP)
			dstFQDN, _ := dnsCache.Get(dstIP)

			fmt.Printf("\n=== HTTP Request ===\n")
			fmt.Printf("Time: %s\n", time.Now().Format(time.RFC3339))
			fmt.Printf("Source: %s:%s", srcIP, srcPort)
			if srcFQDN != "" {
				fmt.Printf(" (%s)", srcFQDN)
			}
			fmt.Printf("\n")
			fmt.Printf("Destination: %s:%s", dstIP, dstPort)
			if dstFQDN != "" {
				fmt.Printf(" (%s)", dstFQDN)
			}
			fmt.Printf("\n")
			fmt.Printf("Method: %s\n", req.Method)
			fmt.Printf("URL: %s\n", req.URL)
			fmt.Printf("Proto: %s\n", req.Proto)
			fmt.Printf("Host: %s\n", req.Host)

			fmt.Println("\nHeaders:")
			for name, values := range req.Header {
				for _, value := range values {
					fmt.Printf("  %s: %s\n", name, value)
				}
			}

			if req.Body != nil {
				body := make([]byte, 1024*1024) // 1MB max
				n, _ := req.Body.Read(body)
				if n > 0 {
					fmt.Printf("\nRequest Body (%d bytes):\n%s\n", n, string(body[:n]))
				}
				req.Body.Close()
			}
		} else {
			resp, err := http.ReadResponse(buf, nil)
			if err != nil {
				return
			}

			srcIP := h.net.Src().String()
			dstIP := h.net.Dst().String()
			srcPort := h.transport.Src().String()
			dstPort := h.transport.Dst().String()

			srcFQDN, _ := dnsCache.Get(srcIP)
			dstFQDN, _ := dnsCache.Get(dstIP)

			fmt.Printf("\n=== HTTP Response ===\n")
			fmt.Printf("Time: %s\n", time.Now().Format(time.RFC3339))
			fmt.Printf("Source: %s:%s", srcIP, srcPort)
			if srcFQDN != "" {
				fmt.Printf(" (%s)", srcFQDN)
			}
			fmt.Printf("\n")
			fmt.Printf("Destination: %s:%s", dstIP, dstPort)
			if dstFQDN != "" {
				fmt.Printf(" (%s)", dstFQDN)
			}
			fmt.Printf("\n")
			fmt.Printf("Status: %s\n", resp.Status)
			fmt.Printf("Proto: %s\n", resp.Proto)

			fmt.Println("\nHeaders:")
			for name, values := range resp.Header {
				for _, value := range values {
					fmt.Printf("  %s: %s\n", name, value)
				}
			}

			if resp.Body != nil {
				body := make([]byte, 1024*1024) // 1MB max
				n, _ := resp.Body.Read(body)
				if n > 0 {
					fmt.Printf("\nResponse Body (%d bytes):\n%s\n", n, string(body[:n]))
				}
				resp.Body.Close()
			}
		}
	}
}

func (h *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	hstream := &HTTPStream{
		net:       net,
		transport: transport,
		r: tcpReader{
			ident:    fmt.Sprintf("%s:%s", net, transport),
			isClient: true,
		},
	}
	hstream.r.parent = hstream

	go hstream.run(h.dnsCache)

	return &hstream.r
}

func (t *tcpReader) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	length, _ := sg.Lengths()
	data := sg.Fetch(length)
	t.Buffer.Write(data)
}

func (t *tcpReader) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	return false
}

func (t *tcpReader) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, seq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return true
}

func main() {
	var pcapFile string
	flag.StringVar(&pcapFile, "file", "", "Path to pcap file")
	flag.Parse()

	if pcapFile == "" {
		log.Fatal("Please provide a pcap file using -file flag")
	}

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	dnsCache := dns.NewCache()

	streamFactory := &tcpStreamFactory{
		dnsCache: dnsCache,
	}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Printf("Starting pcap analysis of file: %s\n", pcapFile)
	fmt.Println("Tracking DNS queries and HTTP streams...")
	fmt.Println("=" + strings.Repeat("=", 50))

	for packet := range packetSource.Packets() {
		dns.ParsePacket(packet, dnsCache)

		if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
			tcpLayer := tcp.(*layers.TCP)
			assembler.AssembleWithContext(
				packet.NetworkLayer().NetworkFlow(),
				tcpLayer,
				&Context{
					CaptureInfo: packet.Metadata().CaptureInfo,
				})
		}
	}

	assembler.FlushAll()
	fmt.Println("\nAnalysis complete.")
}
