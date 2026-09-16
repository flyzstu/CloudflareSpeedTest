package task

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInitTLS_NonHTTPS(t *testing.T) {
	// Case 1: HTTP with ECH enabled should fail
	EnableECH = true
	ForceH2 = false
	err := InitTLS("http://example.com/test")
	if err == nil {
		t.Fatalf("expected error when ECH is enabled on non-HTTPS URL, got nil")
	}

	// Case 2: HTTP with ForceH2 enabled should fail
	EnableECH = false
	ForceH2 = true
	err = InitTLS("http://example.com/test")
	if err == nil {
		t.Fatalf("expected error when ForceH2 is enabled on non-HTTPS URL, got nil")
	}

	// Case 3: HTTP without ECH or ForceH2 should succeed
	EnableECH = false
	ForceH2 = false
	err = InitTLS("http://example.com/test")
	if err != nil {
		t.Fatalf("expected success on HTTP without ECH/H2, got: %v", err)
	}
	if baseTLSConfig != nil {
		t.Fatalf("expected baseTLSConfig to be nil for HTTP URL")
	}
}

func TestInitTLS_StandardHTTPS(t *testing.T) {
	EnableECH = false
	ForceH2 = true
	err := InitTLS("https://my-domain.org:8443/test/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if TargetHostname != "my-domain.org" {
		t.Fatalf("expected hostname 'my-domain.org', got %q", TargetHostname)
	}
	cfg := getTLSConfig()
	if cfg == nil {
		t.Fatalf("expected non-nil tls.Config")
	}
	if cfg.ServerName != "my-domain.org" {
		t.Fatalf("expected ServerName 'my-domain.org', got %q", cfg.ServerName)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "h2" {
		t.Fatalf("expected NextProtos ['h2'], got %v", cfg.NextProtos)
	}

	// When ForceH2 is false, should include h2 and http/1.1
	ForceH2 = false
	err = InitTLS("https://my-domain.org/test/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg = getTLSConfig()
	if len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != "h2" || cfg.NextProtos[1] != "http/1.1" {
		t.Fatalf("expected NextProtos ['h2', 'http/1.1'], got %v", cfg.NextProtos)
	}
}

func TestInitTLS_ECH_ExplicitConfig(t *testing.T) {
	rawECH := []byte("fake-serialized-ech-config-list-bytes")
	b64ECH := base64.StdEncoding.EncodeToString(rawECH)

	EnableECH = true
	ECHConfigB64 = b64ECH
	defer func() {
		EnableECH = false
		ECHConfigB64 = ""
	}()

	err := InitTLS("https://ech-domain.com/__down")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := getTLSConfig()
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected MinVersion TLS 1.3, got 0x%04x", cfg.MinVersion)
	}
	if string(cfg.EncryptedClientHelloConfigList) != string(rawECH) {
		t.Fatalf("expected ECH config bytes to match input, got %q", cfg.EncryptedClientHelloConfigList)
	}
}

func TestInitTLS_ECH_InvalidBase64(t *testing.T) {
	EnableECH = true
	ECHConfigB64 = "!!!invalid-base64-content!!!"
	defer func() {
		EnableECH = false
		ECHConfigB64 = ""
	}()

	err := InitTLS("https://ech-domain.com/__down")
	if err == nil {
		t.Fatalf("expected error on invalid base64 ECH config, got nil")
	}
	if !strings.Contains(err.Error(), "invalid base64") {
		t.Fatalf("expected 'invalid base64' in error message, got: %v", err)
	}
}

func TestFetchECHConfig_DoH_Live(t *testing.T) {
	// Test querying live domain known to have ECH HTTPS record
	echBytes, err := fetchECHConfig("sin.piccdn.click")
	if err != nil {
		// Fallback to cloudflare.com if custom domain DNS fails
		echBytes, err = fetchECHConfig("cloudflare.com")
	}
	if err != nil {
		t.Skipf("skipping live DoH test due to network/DNS: %v", err)
	}
	if len(echBytes) == 0 {
		t.Fatalf("expected non-empty ECH config bytes")
	}
	t.Logf("Successfully fetched ECH config from DoH, length=%d bytes", len(echBytes))
}

func TestFetchECHConfig_DoH_NoECH(t *testing.T) {
	// example.com does not have an ECH HTTPS record
	_, err := fetchECHConfig("example.com")
	if err == nil {
		t.Fatalf("expected error querying ECH on domain without ECH record, got nil")
	}
	if !strings.Contains(err.Error(), "no ECH config found") {
		t.Logf("got error: %v", err)
	}
}

func TestCheckH2Multiplex_ZeroOrOne(t *testing.T) {
	// Concurrency <= 1 should return nil immediately without making requests
	client := &http.Client{}
	if err := CheckH2Multiplex(client, "https://invalid-url-that-would-fail", 0); err != nil {
		t.Fatalf("expected nil for concurrency 0, got: %v", err)
	}
	if err := CheckH2Multiplex(client, "https://invalid-url-that-would-fail", 1); err != nil {
		t.Fatalf("expected nil for concurrency 1, got: %v", err)
	}
}

func TestCheckH2Multiplex_Success(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := server.Client()
	concurrency := 5
	err := CheckH2Multiplex(client, server.URL, concurrency)
	if err != nil {
		t.Fatalf("expected multiplexing check to succeed, got: %v", err)
	}
	if atomic.LoadInt32(&requestCount) != int32(concurrency) {
		t.Fatalf("expected %d requests received by mock server, got %d", concurrency, requestCount)
	}
}

func TestCheckH2Multiplex_ErrorHandling(t *testing.T) {
	// Point to closed server port
	client := &http.Client{Timeout: 1 * time.Second}
	err := CheckH2Multiplex(client, "http://127.0.0.1:1", 3)
	if err == nil {
		t.Fatalf("expected error when connecting to non-existent endpoint, got nil")
	}
}
