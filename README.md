# PCAP Traffic Analyzer

A Go program that parses pcap files and analyzes DNS and HTTP traffic, providing detailed information about network communications.

## Features

- **DNS Analysis**: Tracks DNS queries and responses, extracting FQDNs
- **HTTP Stream Reassembly**: Reconstructs HTTP conversations from TCP streams  
- **Full Traffic Details**: Shows headers, bodies, and endpoint information
- **FQDN Resolution**: Maps IP addresses to domain names using DNS data
- **Timestamp Tracking**: Records when each communication occurred

## Project Structure

```
.
├── cmd/
│   └── pcap-analyzer/          # Main application entry point
│       └── main.go
├── internal/                   # Private application packages
│   ├── dns/                   # DNS parsing and caching
│   │   ├── cache.go
│   │   └── parser.go
│   ├── http/                  # HTTP stream processing
│   │   └── stream.go
│   └── stream/                # TCP stream factory
│       └── factory.go
├── pkg/                       # Public library packages (if needed)
├── bin/                       # Compiled binaries (generated)
├── dist/                      # Release distributions (generated)
├── go.mod
├── go.sum
├── Makefile
├── .gitignore
└── README.md
```

## Requirements

- Go 1.21+
- gopacket library
- miekg/dns library

## Installation

### Using Make (Recommended)

```bash
# Install dependencies and build
make build

# Or for development with race detection
make build-dev

# Install to GOPATH/bin
make install
```

### Manual Installation

```bash
go mod download
go build -o bin/pcap-analyzer ./cmd/pcap-analyzer
```

## Usage

### Using Make

```bash
# Run with a pcap file
make run PCAP_FILE=/path/to/capture.pcap

# Development mode with race detection
make dev PCAP_FILE=/path/to/capture.pcap
```

### Direct Execution

```bash
# Using built binary
./bin/pcap-analyzer -file /path/to/capture.pcap

# Using go run
go run ./cmd/pcap-analyzer -file /path/to/capture.pcap
```

## Development

### Available Make Commands

```bash
# Building
make build          # Build production binary
make build-dev      # Build with race detection
make install        # Install to GOPATH/bin

# Testing and Quality
make test           # Run tests
make test-coverage  # Run tests with coverage report
make bench          # Run benchmarks
make lint           # Run linter (requires golangci-lint)
make fmt            # Format code
make vet            # Run go vet
make check          # Run all checks (fmt, vet, lint, test)

# Dependencies
make deps           # Download dependencies
make deps-update    # Update dependencies

# Development Tools
make tools          # Install development tools
make security       # Run security checks (requires gosec)

# Release
make release        # Build for multiple platforms
make clean          # Clean build artifacts

# Help
make help           # Show all available commands
```

### Installing Development Tools

```bash
make tools
```

This installs:
- golangci-lint for comprehensive linting
- goimports for import management

## Output Format

The program outputs detailed information for each detected communication:

### DNS Queries
```
=== DNS Query ===
Time: 2024-01-01T12:00:00Z
Query: example.com. (Type: A)
```

### DNS Responses
```
=== DNS Response ===
Time: 2024-01-01T12:00:00Z
Query: example.com.
  A Record: example.com. -> 93.184.216.34
```

### HTTP Requests
```
=== HTTP Request ===
Time: 2024-01-01T12:00:00Z
Source: 192.168.1.100:54321 (client.local)
Destination: 93.184.216.34:80 (example.com)
Method: GET
URL: /path
Proto: HTTP/1.1
Host: example.com

Headers:
  User-Agent: Mozilla/5.0...
  Accept: text/html...

Request Body (123 bytes):
...
```

### HTTP Responses
```
=== HTTP Response ===
Time: 2024-01-01T12:00:00Z
Source: 93.184.216.34:80 (example.com)
Destination: 192.168.1.100:54321 (client.local)
Status: 200 OK
Proto: HTTP/1.1

Headers:
  Content-Type: text/html
  Content-Length: 1234

Response Body (1234 bytes):
<!DOCTYPE html>...
```

## Technical Details

- Uses TCP stream reassembly to reconstruct HTTP conversations
- Maintains a DNS cache to resolve IP addresses to FQDNs
- Handles both IPv4 and IPv6 addresses
- Limits body output to 1MB per request/response
- Thread-safe DNS cache with concurrent access support