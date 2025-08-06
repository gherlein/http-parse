package http

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/google/gopacket"
	"github.com/pcap-analyzer/internal/dns"
)

type Stream struct {
	net, transport gopacket.Flow
	r              tcpReader
	reversed       bool
}

type tcpReader struct {
	bytes.Buffer
	ident    string
	isClient bool
	parent   *Stream
}

func (t *tcpReader) Read(p []byte) (int, error) {
	n, err := t.Buffer.Read(p)
	return n, err
}

func (s *Stream) Run(dnsCache *dns.Cache) {
	buf := bufio.NewReader(&s.r)
	for {
		if s.r.isClient {
			req, err := http.ReadRequest(buf)
			if err != nil {
				return
			}

			s.printHTTPRequest(req, dnsCache)
		} else {
			resp, err := http.ReadResponse(buf, nil)
			if err != nil {
				return
			}

			s.printHTTPResponse(resp, dnsCache)
		}
	}
}

func (s *Stream) printHTTPRequest(req *http.Request, dnsCache *dns.Cache) {
	srcIP := s.net.Src().String()
	dstIP := s.net.Dst().String()
	srcPort := s.transport.Src().String()
	dstPort := s.transport.Dst().String()

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
}

func (s *Stream) printHTTPResponse(resp *http.Response, dnsCache *dns.Cache) {
	srcIP := s.net.Src().String()
	dstIP := s.net.Dst().String()
	srcPort := s.transport.Src().String()
	dstPort := s.transport.Dst().String()

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
