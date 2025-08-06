package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
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

// Helper function to decompress gzip content
func decompressGzip(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()
	
	return io.ReadAll(gzipReader)
}

func (h *HTTPStream) run(dnsCache *dns.Cache) {
	// Wait for some data to be available
	for i := 0; i < 100; i++ { // Max 1 second wait
		if h.r.Buffer.Len() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	
	if h.r.Buffer.Len() == 0 {
		return
	}
	
	// Wait for buffer to fill up more to ensure we have complete headers
	// Many HTTP requests span multiple TCP packets
	prevLen := 0
	for i := 0; i < 10; i++ {
		currentLen := h.r.Buffer.Len()
		if currentLen == prevLen && currentLen > 100 {
			// Buffer stopped growing and has some data
			break
		}
		prevLen = currentLen
		time.Sleep(20 * time.Millisecond)
	}
	
	// Check if this is TLS/encrypted traffic by looking at the destination port and data
	dstPort := h.transport.Dst().String()
	srcPort := h.transport.Src().String()
	if dstPort == "443" || dstPort == "8443" || srcPort == "443" || srcPort == "8443" {
		// Peek at first few bytes to confirm TLS
		if h.r.Buffer.Len() >= 3 {
			firstBytes := h.r.Buffer.Bytes()[:3]
			if firstBytes[0] == 0x16 && firstBytes[1] == 0x03 {
				return
			}
		}
	}
	
	buf := bufio.NewReader(&h.r)
	
	for {
		// Peek at data to determine if this is HTTP request or response
		peek, err := buf.Peek(8)
		if err != nil {
			return
		}
		
		peekStr := string(peek)
		
		
		// Check if this looks like TLS handshake data
		if len(peek) >= 3 && peek[0] == 0x16 && peek[1] == 0x03 {
			return
		}
		
		// HTTP responses start with "HTTP/"
		if strings.HasPrefix(peekStr, "HTTP/") {
			// Parse as HTTP response
			dummyReq := &http.Request{Method: "GET"}
			resp, err := http.ReadResponse(buf, dummyReq)
			if err != nil {
				// Try to see if there's more data coming
				time.Sleep(10 * time.Millisecond)
				continue
			}
			h.printHTTPResponse(resp, dnsCache)
		} else {
			// Parse as HTTP request
			req, err := http.ReadRequest(buf)
			if err != nil {
				// If we get an error, wait for more data and try again
				// But only retry a few times to avoid infinite loops
				time.Sleep(50 * time.Millisecond)
				if h.r.Buffer.Len() > buf.Buffered() {
					// More data arrived, try again
					continue
				}
				// No more data coming, give up on this stream
				return
			}
			h.printHTTPRequest(req, dnsCache)
		}
	}
}

func (h *HTTPStream) printHTTPRequest(req *http.Request, dnsCache *dns.Cache) {
	srcIP := h.net.Src().String()
	dstIP := h.net.Dst().String()
	srcPort := h.transport.Src().String()
	dstPort := h.transport.Dst().String()
	

	// Use DNS cache for forward DNS, skip RDNS lookups to avoid blocking
	srcFQDN := ""
	if fqdn, ok := dnsCache.Get(srcIP); ok {
		srcFQDN = fqdn
	}
	dstFQDN := ""
	if fqdn, ok := dnsCache.Get(dstIP); ok {
		dstFQDN = fqdn
	}

	// Construct full URL with protocol and hostname
	protocol := "http"
	if dstPort == "443" || dstPort == "8443" {
		protocol = "https"
	}
	
	hostname := req.Host
	if hostname == "" {
		if dstFQDN != "" {
			hostname = dstFQDN
		} else {
			hostname = dstIP
		}
	}
	
	if (protocol == "http" && dstPort != "80") || (protocol == "https" && dstPort != "443") {
		if !strings.Contains(hostname, ":") {
			hostname = hostname + ":" + dstPort
		}
	}
	
	fullURL := fmt.Sprintf("%s://%s%s", protocol, hostname, req.URL.Path)
	if req.URL.RawQuery != "" {
		fullURL += "?" + req.URL.RawQuery
	}

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
	fmt.Printf("URL: %s\n", fullURL)
	fmt.Printf("Proto: %s\n", req.Proto)
	fmt.Printf("Host: %s\n", req.Host)

	fmt.Println("\nHeaders:")
	// Print all headers from the request
	for name, values := range req.Header {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", name, value)
		}
	}
	
	// Debug: Check if there are more headers we might be missing
	if req.ContentLength > 0 {
		fmt.Printf("  [Content-Length: %d]\n", req.ContentLength)
	}

	if req.Body != nil {
		body := make([]byte, 1024*1024) // 1MB max
		n, _ := req.Body.Read(body)
		if n > 0 {
			bodyData := body[:n]
			// Check if the request body is gzipped
			if req.Header.Get("Content-Encoding") == "gzip" {
				if decompressed, err := decompressGzip(bodyData); err == nil {
					fmt.Printf("\nRequest Body (%d bytes, decompressed from gzip):\n%s\n", len(decompressed), string(decompressed))
				} else {
					fmt.Printf("\nRequest Body (%d bytes, gzip decompression failed):\n%s\n", n, string(bodyData))
				}
			} else {
				fmt.Printf("\nRequest Body (%d bytes):\n%s\n", n, string(bodyData))
			}
		}
		req.Body.Close()
	}
}

func (h *HTTPStream) printHTTPResponse(resp *http.Response, dnsCache *dns.Cache) {
	srcIP := h.net.Src().String()
	dstIP := h.net.Dst().String()
	srcPort := h.transport.Src().String()
	dstPort := h.transport.Dst().String()
	

	// Use DNS cache for forward DNS, skip RDNS lookups to avoid blocking
	srcFQDN := ""
	if fqdn, ok := dnsCache.Get(srcIP); ok {
		srcFQDN = fqdn
	}
	dstFQDN := ""
	if fqdn, ok := dnsCache.Get(dstIP); ok {
		dstFQDN = fqdn
	}

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
			bodyData := body[:n]
			// Check if the response body is gzipped
			if resp.Header.Get("Content-Encoding") == "gzip" {
				if decompressed, err := decompressGzip(bodyData); err == nil {
					fmt.Printf("\nResponse Body (%d bytes, decompressed from gzip):\n%s\n", len(decompressed), string(decompressed))
				} else {
					fmt.Printf("\nResponse Body (%d bytes, gzip decompression failed):\n%s\n", n, string(bodyData))
				}
			} else {
				fmt.Printf("\nResponse Body (%d bytes):\n%s\n", n, string(bodyData))
			}
		}
		resp.Body.Close()
	}
}

func (h *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	srcIP := net.Src().String()
	dstIP := net.Dst().String()
	srcPort := transport.Src().String()
	dstPort := transport.Dst().String()
		
	hstream := &HTTPStream{
		net:       net,
		transport: transport,
		r: tcpReader{
			ident:    fmt.Sprintf("%s:%s->%s:%s", srcIP, dstIP, srcPort, dstPort),
			isClient: false, // Not used anymore - content-based detection
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
	// Signal that reassembly is complete
	// This allows any waiting HTTP parsers to process remaining data
	return false
}

func (t *tcpReader) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, seq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return true
}

func main() {
	var pcapFile string
	var enableDNS bool
	flag.StringVar(&pcapFile, "file", "", "Path to pcap file")
	flag.BoolVar(&enableDNS, "d", false, "Enable DNS analysis")
	flag.BoolVar(&enableDNS, "dns", false, "Enable DNS analysis")
	flag.Parse()

	if pcapFile == "" {
		log.Fatal("Please provide a pcap file using -file flag")
	}
	
	if !enableDNS {
		fmt.Println("Note: DNS packet analysis disabled. HTTP traffic will still be analyzed.")
		fmt.Println("      Use -d or --dns to enable DNS packet parsing.")
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
	if enableDNS {
		fmt.Println("Tracking DNS queries and HTTP streams...")
	} else {
		fmt.Println("Tracking HTTP streams only...")
	}
	fmt.Println("=" + strings.Repeat("=", 50))

	for packet := range packetSource.Packets() {
		if enableDNS {
			dns.ParsePacket(packet, dnsCache)
		}

		if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
			tcpLayer := tcp.(*layers.TCP)
			
			// Get port information for filtering
			srcPort := tcpLayer.SrcPort.String()
			dstPort := tcpLayer.DstPort.String()
			
			// Only process TCP streams that might contain HTTP traffic
			// Skip obvious non-HTTP ports but be more permissive
			isHTTPPort := func(port string) bool {
				switch port {
				case "80", "8080", "8000", "8888", "3000", "5000", "9000":
					return true // Common HTTP ports
				case "443", "8443":
					return true // HTTPS ports (we'll filter TLS later)
				case "22", "23", "25", "53", "110", "143", "993", "995":
					return false // Definitely not HTTP
				default:
					return true // Unknown ports - let content detection decide
				}
			}
			
			if isHTTPPort(srcPort) || isHTTPPort(dstPort) {
				assembler.AssembleWithContext(
					packet.NetworkLayer().NetworkFlow(),
					tcpLayer,
					&Context{
						CaptureInfo: packet.Metadata().CaptureInfo,
					})
			}
		}
	}

	// Flush remaining data and wait for parsers to complete
	assembler.FlushAll()
	time.Sleep(500 * time.Millisecond) // Give parsers time to process final data
	fmt.Println("\nAnalysis complete.")
}
