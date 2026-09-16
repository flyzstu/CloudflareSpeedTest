package task

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	EnableECH      bool
	ECHConfigB64   string
	ForceH2        bool
	H2Multiplex    int
	TargetHostname string
	ECHConfigBytes []byte
	baseTLSConfig  *tls.Config
	tlsInitMu      sync.RWMutex
	reECHParam     = regexp.MustCompile(`ech=([A-Za-z0-9+/=]+)`)
)

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// InitTLS initializes TLS and ECH parameters based on target URL.
func InitTLS(rawURL string) error {
	tlsInitMu.Lock()
	defer tlsInitMu.Unlock()

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	TargetHostname = u.Hostname()

	if !strings.EqualFold(u.Scheme, "https") {
		if EnableECH || ForceH2 {
			return errors.New("ECH and HTTP/2 testing requires an HTTPS URL (scheme https://)")
		}
		baseTLSConfig = nil
		return nil
	}

	cfg := &tls.Config{
		ServerName: TargetHostname,
	}

	if ForceH2 {
		cfg.NextProtos = []string{"h2"}
	} else {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}

	if EnableECH {
		cfg.MinVersion = tls.VersionTLS13
		if ECHConfigB64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(ECHConfigB64)
			if err != nil {
				return fmt.Errorf("invalid base64 in -ech-config: %w", err)
			}
			ECHConfigBytes = decoded
		} else {
			echBytes, err := fetchECHConfig(TargetHostname)
			if err != nil {
				return fmt.Errorf("failed to fetch ECH config for %s: %w", TargetHostname, err)
			}
			ECHConfigBytes = echBytes
		}
		cfg.EncryptedClientHelloConfigList = ECHConfigBytes
	}

	baseTLSConfig = cfg
	return nil
}

func fetchECHConfig(domain string) ([]byte, error) {
	dohServers := []string{
		fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=HTTPS", url.QueryEscape(domain)),
		fmt.Sprintf("https://dns.google/resolve?name=%s&type=HTTPS", url.QueryEscape(domain)),
	}

	client := &http.Client{Timeout: 5 * time.Second}
	var lastErr error

	for _, endpoint := range dohServers {
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		var doh dohResponse
		if err := json.Unmarshal(body, &doh); err != nil {
			lastErr = err
			continue
		}

		for _, ans := range doh.Answer {
			if ans.Type == 65 { // HTTPS record
				m := reECHParam.FindStringSubmatch(ans.Data)
				if len(m) > 1 {
					decoded, err := base64.StdEncoding.DecodeString(m[1])
					if err == nil && len(decoded) > 0 {
						return decoded, nil
					}
				}
			}
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no ECH config found in HTTPS DNS records for %s", domain)
}

func getTLSConfig() *tls.Config {
	tlsInitMu.RLock()
	defer tlsInitMu.RUnlock()
	if baseTLSConfig == nil {
		return nil
	}
	return baseTLSConfig.Clone()
}

func newHTTPTransport(ip *net.IPAddr) *http.Transport {
	tr := &http.Transport{
		DialContext:       getDialContext(ip),
		TLSClientConfig:   getTLSConfig(),
		ForceAttemptHTTP2: ForceH2,
		DisableKeepAlives: false,
	}
	return tr
}

func NewHTTPClient(ip *net.IPAddr, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: newHTTPTransport(ip),
		Timeout:   timeout,
	}
}

// CheckH2Multiplex tests concurrent stream capabilities on the existing connection.
func CheckH2Multiplex(client *http.Client, testURL string, concurrency int) error {
	if concurrency <= 1 {
		return nil
	}

	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest("HEAD", testURL, nil)
			if err != nil {
				errCh <- err
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			resp, err := client.Do(req)
			if err != nil {
				errCh <- err
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}
