package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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
	"emilia/useragent"
)

// === KONFIGURASI ===
const (
	Debug         = false
	TimeoutSec    = 5
	MaxConcurrent = 200
)

var workerURLs = []string{
	"https://api-check4.checkv4.workers.dev",
	"https://api-check1.api-check1.workers.dev",
	"https://api-check2.shirokoyumi.workers.dev",
	"https://api-check3.sokove5110.workers.dev",
}

const (
	TraceURL     = "https://1.1.1.1/cdn-cgi/trace"
	AwsURL       = "https://checkip.amazonaws.com"
	FileInput    = "Data/IPPROXY23K.txt"
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
	if err := os.MkdirAll("Data", os.ModePerm); err != nil {
		fmt.Printf("❌ Gagal membuat folder Data: %v\n", err)
		return
	}

	fmt.Println("==========================================")
	fmt.Println("   GOLANG SOCKET SCANNER (SORTING PRO)  ")
	fmt.Printf("   Debug Mode: %v\n", Debug)
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
		fmt.Printf("❌ Error membaca file: %v\n", err)
		return
	}
	fmt.Printf("📂 Total Proxy Loaded: %d\n", len(proxies))
	if len(proxies) == 0 {
		fmt.Println("❌ Tidak ada proxy untuk di-scan.")
		return
	}
	fmt.Println("🚀 Memulai scan socket parallel, Mohon tunggu.\n")

	// 3. SCANNING
	stats := &Stats{Total: int32(len(proxies))}
	resultsChan := make(chan CheckResult, len(proxies))

	var wg sync.WaitGroup
	sem := make(chan struct{}, MaxConcurrent)

	// Progress monitor
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	done := make(chan bool)
	go progressMonitor(ticker, done, stats)

	for _, p := range proxies {
		wg.Add(1)
		sem <- struct{}{}

		go func(proxy ProxyInput) {
			defer wg.Done()
			defer func() { <-sem }()

			res := checkProxyManualSocket(proxy, realIP)
			atomic.AddInt32(&stats.Checked, 1)

			if res.Valid {
				atomic.AddInt32(&stats.Live, 1)
				if Debug {
					fmt.Printf("\n✅ LIVE: %s:%s | Org: %s",
						res.Data.IP, res.Data.Port, res.Data.Org)
				}
			}

			resultsChan <- res
		}(p)
	}

	wg.Wait()
	close(done)
	close(resultsChan)

	// 4. SORTING & SAVING
	fmt.Println("\n\n🏁 Scanning selesai. Menyimpan hasil.")

	var validProxies []ValidProxy
	for res := range resultsChan {
		if res.Valid && res.Data != nil {
			validProxies = append(validProxies, *res.Data)
		}
	}

	saveResults(validProxies)
}

// === FUNGSI BANTU UTAMA ===
func checkProxyManualSocket(input ProxyInput, realIP string) CheckResult {
	// Layer 1: Worker URLs
	for i, target := range workerURLs {
		body, code := rawSocketRequest(target, input.IP, input.Port)
		if code == 200 {
			var resp WorkerResponse
			if err := json.Unmarshal(body, &resp); err == nil {
				if isValidIP(resp.IP) && resp.IP != realIP {
					finalOrg := input.OrgInput
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
							Source:  fmt.Sprintf("Worker-%d", i+1),
						},
					}
				}
			}
		}
	}

	// Layer 2: Cloudflare Trace
	body, code := rawSocketRequest(TraceURL, input.IP, input.Port)
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

	// Layer 3: AWS CheckIP
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

func rawSocketRequest(targetURL, proxyIP, proxyPort string) ([]byte, int) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, 0
	}

	host := parsedURL.Hostname()
	if host == "" {
		return nil, 0
	}

	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	// Validasi port
	if proxyPort == "" {
		return nil, 0
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(proxyIP, proxyPort),
		time.Duration(TimeoutSec)*time.Second)
	if err != nil {
		return nil, 0
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12, // TLS minimal 1.2 untuk keamanan
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if tlsConn == nil {
		return nil, 0
	}

	deadline := time.Now().Add(time.Duration(TimeoutSec) * time.Second)
	tlsConn.SetDeadline(deadline)

	if err := tlsConn.Handshake(); err != nil {
		return nil, 0
	}
	defer tlsConn.Close()

	rawRequest := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Accept: */*\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		path, host, useragent.GetRandom(),
	)

	if _, err := tlsConn.Write([]byte(rawRequest)); err != nil {
		return nil, 0
	}

	reader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode
	}

	return body, resp.StatusCode
}

// === FUNGSI UTILITAS ===
func getPublicIPDirect() string {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	for _, u := range workerURLs {
		resp, err := client.Get(u)
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				var w WorkerResponse
				if json.Unmarshal(body, &w) == nil && isValidIP(w.IP) {
					return w.IP
				}
			}
		}
	}

	resp, err := client.Get(AwsURL)
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			ip := strings.TrimSpace(string(body))
			if isValidIP(ip) {
				return ip
			}
		}
	}

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
	if org == "" {
		return ""
	}
	cleaned := regexOrg.ReplaceAllString(org, "")
	return strings.TrimSpace(cleaned)
}

func readInputFile(path string) ([]ProxyInput, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var proxies []ProxyInput
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) >= 4 {
			ip := strings.TrimSpace(parts[0])
			port := strings.TrimSpace(parts[1])
			country := strings.TrimSpace(parts[2])
			org := strings.TrimSpace(parts[3])

			if ip != "" && port != "" && country != "" {
				proxies = append(proxies, ProxyInput{
					IP:       ip,
					Port:     port,
					Country:  country,
					OrgInput: org,
				})
			} else if Debug {
				fmt.Printf("⚠️  Baris %d diabaikan: format tidak lengkap\n", lineNum)
			}
		} else if Debug {
			fmt.Printf("⚠️  Baris %d diabaikan: hanya %d bagian\n", lineNum, len(parts))
		}
	}

	if err := scanner.Err(); err != nil {
		return proxies, fmt.Errorf("error membaca file: %v", err)
	}
	return proxies, nil
}

func isValidIP(ip string) bool {
	if ip == "" {
		return false
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	// Tolok IP pribadi dan loopback
	if parsedIP.IsPrivate() || parsedIP.IsLoopback() || parsedIP.IsUnspecified() {
		return false
	}
	return true
}

func progressMonitor(ticker *time.Ticker, done chan bool, stats *Stats) {
	for {
		select {
		case <-done:
			fmt.Printf("\r⏳ Progress: %d/%d | ✅ Live: %d   \n",
				atomic.LoadInt32(&stats.Checked),
				stats.Total,
				atomic.LoadInt32(&stats.Live))
			return
		case <-ticker.C:
			current := atomic.LoadInt32(&stats.Checked)
			live := atomic.LoadInt32(&stats.Live)
			fmt.Printf("\r⏳ Progress: %d/%d | ✅ Live: %d   ",
				current, stats.Total, live)
		}
	}
}

func saveResults(proxies []ValidProxy) {
	if len(proxies) == 0 {
		fmt.Println("❌ Tidak ada proxy yang valid untuk disimpan.")
		return
	}

	// 1. SAVE ALIVE (sorted A-Z by country)
	sort.Slice(proxies, func(i, j int) bool {
		if proxies[i].Country == proxies[j].Country {
			return proxies[i].IP < proxies[j].IP
		}
		return proxies[i].Country < proxies[j].Country
	})

	fAlive, err := os.Create(FileAlive)
	if err != nil {
		fmt.Printf("❌ Gagal membuat file %s: %v\n", FileAlive, err)
		return
	}
	defer fAlive.Close()

	wAlive := bufio.NewWriter(fAlive)
	for _, p := range proxies {
		line := fmt.Sprintf("%s,%s,%s,%s\n", p.IP, p.Port, p.Country, p.Org)
		if _, err := wAlive.WriteString(line); err != nil {
			fmt.Printf("⚠️  Gagal menulis ke %s: %v\n", FileAlive, err)
			break
		}
	}
	if err := wAlive.Flush(); err != nil {
		fmt.Printf("⚠️  Gagal flush %s: %v\n", FileAlive, err)
	}

	// 2. SAVE PRIORITY (special sorting)
	prioList := make([]ValidProxy, len(proxies))
	copy(prioList, proxies)

	priorityOrder := map[string]int{
		"ID": 1,
		"MY": 2,
		"SG": 3,
		"HK": 4,
	}

	sort.SliceStable(prioList, func(i, j int) bool {
		c1 := prioList[i].Country
		c2 := prioList[j].Country

		prio1, hasPrio1 := priorityOrder[c1]
		prio2, hasPrio2 := priorityOrder[c2]

		if hasPrio1 && hasPrio2 {
			if prio1 == prio2 {
				return prioList[i].IP < prioList[j].IP
			}
			return prio1 < prio2
		}
		if hasPrio1 {
			return true
		}
		if hasPrio2 {
			return false
		}
		if c1 == c2 {
			return prioList[i].IP < prioList[j].IP
		}
		return c1 < c2
	})

	fPrio, err := os.Create(FilePriority)
	if err != nil {
		fmt.Printf("❌ Gagal membuat file %s: %v\n", FilePriority, err)
		return
	}
	defer fPrio.Close()

	wPrio := bufio.NewWriter(fPrio)
	for _, p := range prioList {
		line := fmt.Sprintf("%s,%s,%s,%s\n", p.IP, p.Port, p.Country, p.Org)
		if _, err := wPrio.WriteString(line); err != nil {
			fmt.Printf("⚠️  Gagal menulis ke %s: %v\n", FilePriority, err)
			break
		}
	}
	if err := wPrio.Flush(); err != nil {
		fmt.Printf("⚠️  Gagal flush %s: %v\n", FilePriority, err)
	}

	// 3. REPORT
	countryCount := make(map[string]int)
	for _, p := range prioList {
		countryCount[p.Country]++
	}

	fmt.Printf("\n\n📁 Output Report:\n")
	fmt.Printf("   ✓ Alive.txt    : %d proxies (Urut A-Z)\n", len(proxies))
	fmt.Printf("   ✓ Priority.txt : %d proxies (ID → MY → SG → HK → A-Z)\n", len(prioList))

	fmt.Println("\n📊 Jumlah per negara prioritas:")
	for _, code := range []string{"ID", "MY", "SG", "HK"} {
		if count, ok := countryCount[code]; ok {
			fmt.Printf("   - %s: %d proxies\n", code, count)
		} else {
			fmt.Printf("   - %s: 0 proxies\n", code)
		}
	}
}
