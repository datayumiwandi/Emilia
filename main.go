package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// Import package useragent kamu
	"emilia/useragent"
)

// === KONFIGURASI ===
const (
	Debug         = false // Set true jika ingin melihat log detail per IP
	TimeoutSec    = 4     // Timeout per socket connection
	MaxConcurrent = 240   // Sesuaikan dengan batas Open Files (ulimit) OS kamu
)

// Jenis cara akses proxy
const (
	ProxyKindHTTPConnect = "http_connect" // HTTP/HTTPS proxy (CONNECT method)
	ProxyKindDirectTLS   = "direct_tls"   // Server TLS langsung (SNI/Reverse Proxy)
)

// === PILIH MODE ===
// Gunakan ProxyKindHTTPConnect untuk list proxy umum
const ProxyMode = ProxyKindHTTPConnect

var workerURLs = []string{
	"https://api-check4.checkv4.workers.dev",
	"https://api-check1.api-check1.workers.dev",
	"https://api-check2.shirokoyumi.workers.dev",
	"https://api-check3.sokove5110.workers.dev",
}

const (
	TraceURL     = "https://1.1.1.1/cdn-cgi/trace"
	AwsURL       = "https://checkip.amazonaws.com"
	FileInput    = "Data/IPProxy45Kbaru.txt"
	FileAlive    = "Data/alive.txt"
	FilePriority = "Data/Country-ALIVE.txt"
)

var regexOrg = regexp.MustCompile(`[^a-zA-Z0-9\s]`)

// === STRUKTUR DATA ===
type WorkerResponse struct {
	IP  string `json:"ip"`
	Org string `json:"as_organization"`
}

type ProxyInput struct {
	IP       string
	Port     string
	Country  string
	OrgInput string
}

type ValidProxy struct {
	IP      string
	Port    string
	Country string
	Org     string
	Source  string
}

type CheckResult struct {
	Valid bool
	Data  *ValidProxy
}

type Stats struct {
	Total   int32
	Live    int32
	Checked int32
}

// === FUNGSI UTAMA ===
func main() {
	// Setup direktori data
	_ = os.MkdirAll("Data", os.ModePerm)

	fmt.Println("==========================================")
	fmt.Println("   GOLANG SOCKET SCANNER (FINAL FIX)    ")
	fmt.Printf("   Mode: %s | Debug: %v\n", ProxyMode, Debug)
	fmt.Println("==========================================")

	// 1. DAPATKAN IP ASLI
	fmt.Print("🔍 Mendapatkan IP Asli... ")
	realIP := getPublicIPDirect()
	if realIP == "" {
		fmt.Println("\n❌ Gagal mendapatkan IP Asli. Cek koneksi internet.")
		return
	}
	fmt.Printf("%s\n\n", realIP)

	// 2. BACA FILE INPUT
	proxies, err := readInputFile(FileInput)
	if err != nil {
		fmt.Printf("❌ Error membaca file '%s': %v\n", FileInput, err)
		return
	}
	fmt.Printf("📂 Total Proxy Loaded: %d\n", len(proxies))
	fmt.Println("🚀 Memulai scan socket parallel...\n")

	// 3. SCANNING
	stats := &Stats{Total: int32(len(proxies))}
	resultsChan := make(chan CheckResult, len(proxies))

	var wg sync.WaitGroup
	// Semaphore pattern untuk membatasi concurrency
	sem := make(chan struct{}, MaxConcurrent)

	// Progress Monitor (Ticker)
	ticker := time.NewTicker(2 * time.Second)
	done := make(chan bool)
	go progressMonitor(ticker, done, stats)

	for _, p := range proxies {
		wg.Add(1)
		sem <- struct{}{} // Ambil token antrian

		go func(proxy ProxyInput) {
			defer wg.Done()
			defer func() { <-sem }() // Lepas token antrian

			res := checkProxyManualSocket(proxy, realIP)
			atomic.AddInt32(&stats.Checked, 1)

			if res.Valid {
				atomic.AddInt32(&stats.Live, 1)
				if Debug {
					fmt.Printf("\n✅ LIVE: %s:%s | %s\n", res.Data.IP, res.Data.Port, res.Data.Org)
				}
			}

			resultsChan <- res
		}(p)
	}

	wg.Wait()
	
	// Bersihkan Ticker agar tidak leak
	ticker.Stop()
	done <- true
	
	close(resultsChan)

	// 4. SORTING & SAVING
	fmt.Println("\n\n🏁 Scanning selesai. Menyimpan hasil...")
	saveValidResults(resultsChan)
}

// === LOGIKA PENGECEKAN (CORE) ===
func checkProxyManualSocket(input ProxyInput, realIP string) CheckResult {
	// Layer 1: Worker URLs (Load Balanced)
	// Pilih 1 worker acak agar tidak membebani server worker pertama terus menerus
	randomWorker := workerURLs[rand.Intn(len(workerURLs))]
	
	body, code := rawSocketRequest(randomWorker, input.IP, input.Port)
	if code == 200 {
		var resp WorkerResponse
		if err := json.Unmarshal(body, &resp); err == nil {
			if isValidIP(resp.IP) && resp.IP != realIP {
				finalOrg := input.OrgInput
				// Gunakan org dari worker jika tersedia, karena biasanya lebih akurat
				if resp.Org != "" {
					finalOrg = cleanOrgName(resp.Org)
				}
				return CheckResult{
					Valid: true,
					Data: &ValidProxy{
						IP:      input.IP,
						Port:    input.Port,
						Country: input.Country,
						Org:     finalOrg,
						Source:  "Worker",
					},
				}
			}
		}
	}

	// Layer 2: Cloudflare Trace (Fallback)
	body, code = rawSocketRequest(TraceURL, input.IP, input.Port)
	if code == 200 {
		ip := parseTraceIP(string(body))
		if isValidIP(ip) && ip != realIP {
			return CheckResult{
				Valid: true,
				Data: &ValidProxy{
					IP:      input.IP,
					Port:    input.Port,
					Country: input.Country,
					Org:     cleanOrgName(input.OrgInput),
					Source:  "CF Trace",
				},
			}
		}
	}

	// Layer 3: AWS CheckIP (Last Resort)
	body, code = rawSocketRequest(AwsURL, input.IP, input.Port)
	if code == 200 {
		ip := strings.TrimSpace(string(body))
		if isValidIP(ip) && ip != realIP {
			return CheckResult{
				Valid: true,
				Data: &ValidProxy{
					IP:      input.IP,
					Port:    input.Port,
					Country: input.Country,
					Org:     cleanOrgName(input.OrgInput),
					Source:  "AWS",
				},
			}
		}
	}

	return CheckResult{Valid: false}
}

// Dispatcher: Memilih fungsi request berdasarkan mode
func rawSocketRequest(targetURL, proxyIP, proxyPort string) ([]byte, int) {
	switch ProxyMode {
	case ProxyKindHTTPConnect:
		return rawSocketRequestHTTPProxy(targetURL, proxyIP, proxyPort)
	case ProxyKindDirectTLS:
		return rawSocketRequestDirectTLS(targetURL, proxyIP, proxyPort)
	default:
		return nil, 0
	}
}

// === IMPLEMENTASI RAW SOCKET ===

func rawSocketRequestHTTPProxy(targetURL, proxyIP, proxyPort string) ([]byte, int) {
	parsedURL, _ := url.Parse(targetURL)
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" { port = "443" } else { port = "80" }
	}
	path := parsedURL.RequestURI()
	if path == "" { path = "/" }

	// 1. TCP ke Proxy
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(proxyIP, proxyPort), time.Duration(TimeoutSec)*time.Second)
	if err != nil { return nil, 0 }
	defer conn.Close() // Pastikan koneksi ditutup di akhir fungsi

	// Set Deadline Global untuk koneksi ini
	conn.SetDeadline(time.Now().Add(time.Duration(TimeoutSec) * time.Second))

	// HTTPS via CONNECT (Tunneling)
	if parsedURL.Scheme == "https" {
		connectReq := fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)
		if _, err := conn.Write([]byte(connectReq)); err != nil { return nil, 0 }

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil { return nil, 0 }
		
		// PENTING: Kuras body response CONNECT agar buffer bersih
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 { return nil, resp.StatusCode }

		// Handshake TLS di atas koneksi TCP yang sudah ada
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		if err := tlsConn.Handshake(); err != nil { return nil, 0 }
		
		// Reset deadline untuk request selanjutnya
		tlsConn.SetDeadline(time.Now().Add(time.Duration(TimeoutSec) * time.Second))

		// Kirim GET Request terenkripsi
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", 
			path, host, useragent.GetRandom())
		
		if _, err := tlsConn.Write([]byte(req)); err != nil { return nil, 0 }

		reader := bufio.NewReader(tlsConn)
		httpResp, err := http.ReadResponse(reader, nil)
		if err != nil { return nil, 0 }
		defer httpResp.Body.Close()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil { return nil, httpResp.StatusCode }
		return body, httpResp.StatusCode
	}

	// HTTP Plain Proxy (Tanpa CONNECT)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", 
		parsedURL.String(), parsedURL.Host, useragent.GetRandom())

	if _, err := conn.Write([]byte(req)); err != nil { return nil, 0 }

	reader := bufio.NewReader(conn)
	httpResp, err := http.ReadResponse(reader, nil)
	if err != nil { return nil, 0 }
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil { return nil, httpResp.StatusCode }
	return body, httpResp.StatusCode
}

func rawSocketRequestDirectTLS(targetURL, proxyIP, proxyPort string) ([]byte, int) {
	parsedURL, _ := url.Parse(targetURL)
	host := parsedURL.Hostname()
	path := parsedURL.Path
	if path == "" { path = "/" }

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(proxyIP, proxyPort), time.Duration(TimeoutSec)*time.Second)
	if err != nil { return nil, 0 }
	defer conn.Close()

	// Langsung TLS Handshake ke IP Proxy
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil { return nil, 0 }
	
	tlsConn.SetDeadline(time.Now().Add(time.Duration(TimeoutSec) * time.Second))

	rawRequest := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", 
		path, host, useragent.GetRandom())

	if _, err := tlsConn.Write([]byte(rawRequest)); err != nil { return nil, 0 }

	reader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil { return nil, 0 }
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil { return nil, resp.StatusCode }
	return body, resp.StatusCode
}

// === UTILITIES ===

func getPublicIPDirect() string {
	client := &http.Client{Timeout: 10 * time.Second}
	
	// Coba akses ke salah satu worker secara acak
	randURL := workerURLs[rand.Intn(len(workerURLs))]
	resp, err := client.Get(randURL)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var w WorkerResponse
		if json.Unmarshal(body, &w) == nil && isValidIP(w.IP) {
			return w.IP
		}
	}
	
	// Fallback ke AWS jika worker gagal
	resp, err = client.Get(AwsURL)
	if err != nil { return "" }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	ip := strings.TrimSpace(string(body))
	if isValidIP(ip) { return ip }
	return ""
}

func parseTraceIP(text string) string {
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ip=") {
			return strings.TrimPrefix(line, "ip=")
		}
	}
	return ""
}

func cleanOrgName(org string) string {
	cleaned := regexOrg.ReplaceAllString(org, "")
	return strings.TrimSpace(cleaned)
}

// readInputFile menggunakan CSV Reader agar robust terhadap koma di dalam nama Org
func readInputFile(path string) ([]ProxyInput, error) {
	file, err := os.Open(path)
	if err != nil { return nil, err }
	defer file.Close()

	var proxies []ProxyInput
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // Mengizinkan jumlah kolom yang bervariasi

	rawLines, err := reader.ReadAll()
	if err != nil { return nil, err }

	for _, parts := range rawLines {
		if len(parts) >= 2 { // Minimal IP dan Port
			p := ProxyInput{
				IP:   strings.TrimSpace(parts[0]),
				Port: strings.TrimSpace(parts[1]),
			}
			if len(parts) > 2 { p.Country = strings.TrimSpace(parts[2]) }
			if len(parts) > 3 { p.OrgInput = strings.TrimSpace(parts[3]) }
			proxies = append(proxies, p)
		}
	}
	return proxies, nil
}

func isValidIP(ip string) bool {
	return ip != "" && net.ParseIP(ip) != nil
}

func progressMonitor(ticker *time.Ticker, done chan bool, stats *Stats) {
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			current := atomic.LoadInt32(&stats.Checked)
			live := atomic.LoadInt32(&stats.Live)
			fmt.Printf("\r⏳ Progress: %d/%d | ✅ Live: %d   ", current, stats.Total, live)
		}
	}
}

func saveValidResults(resultsChan chan CheckResult) {
	var validProxies []ValidProxy
	for res := range resultsChan {
		if res.Valid && res.Data != nil {
			validProxies = append(validProxies, *res.Data)
		}
	}

	if len(validProxies) == 0 {
		fmt.Println("⚠️ Tidak ada proxy yang valid.")
		return
	}

	// 1. Urutkan A-Z berdasarkan negara
	sort.Slice(validProxies, func(i, j int) bool {
		return validProxies[i].Country < validProxies[j].Country
	})
	if err := writeProxyFile(FileAlive, validProxies); err != nil {
		fmt.Printf("❌ Gagal menyimpan %s: %v\n", FileAlive, err)
	}

	// 2. Urutkan berdasarkan Prioritas (ID -> MY -> SG -> HK)
	prioList := make([]ValidProxy, len(validProxies))
	copy(prioList, validProxies)
	priorityOrder := map[string]int{"ID": 1, "MY": 2, "SG": 3, "HK": 4}

	sort.SliceStable(prioList, func(i, j int) bool {
		c1, c2 := prioList[i].Country, prioList[j].Country
		p1, ok1 := priorityOrder[c1]
		p2, ok2 := priorityOrder[c2]
		
		if ok1 && ok2 { return p1 < p2 }
		if ok1 { return true }
		if ok2 { return false }
		return c1 < c2
	})
	if err := writeProxyFile(FilePriority, prioList); err != nil {
		fmt.Printf("❌ Gagal menyimpan %s: %v\n", FilePriority, err)
	}

	// Report Akhir
	fmt.Printf("\n\n📁 Report Output:\n")
	fmt.Printf("   ✓ %s (Total: %d)\n", FileAlive, len(validProxies))
	fmt.Printf("   ✓ %s (Sorted Priority)\n", FilePriority)
}

func writeProxyFile(filename string, proxies []ValidProxy) error {
	f, err := os.Create(filename)
	if err != nil { return err }
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	for _, p := range proxies {
		// Format output: IP,Port,Country,Org
		// Cek error saat penulisan baris
		if _, err := w.WriteString(fmt.Sprintf("%s,%s,%s,%s\n", p.IP, p.Port, p.Country, p.Org)); err != nil {
			return err
		}
	}
	return nil
}
