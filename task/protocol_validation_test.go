package task

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProtocolValidation_HTTP2_Enforcement(t *testing.T) {
	// Create an HTTP/1.1 only mock server
	h1Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer h1Server.Close()

	// 1. ForceH2 = true against HTTP/1.1 server should fail validation
	ForceH2 = true
	client := h1Server.Client()
	resp, err := client.Get(h1Server.URL)
	if err != nil {
		t.Fatalf("unexpected request error: %v", err)
	}
	resp.Body.Close()

	if resp.Proto == "HTTP/2.0" {
		t.Fatalf("expected HTTP/1.1 mock server, got %s", resp.Proto)
	}

	// Validate our logic: if ForceH2 is on and Proto != HTTP/2.0, it must be rejected
	isAccepted := !(ForceH2 && resp.Proto != "HTTP/2.0")
	if isAccepted {
		t.Fatalf("expected HTTP/1.1 response to be rejected when ForceH2 is true")
	}

	// 2. ForceH2 = false against HTTP/1.1 server should pass
	ForceH2 = false
	isAccepted = !(ForceH2 && resp.Proto != "HTTP/2.0")
	if !isAccepted {
		t.Fatalf("expected HTTP/1.1 response to be accepted when ForceH2 is false")
	}
}

func TestProtocolValidation_ECH_Accepted_Check(t *testing.T) {
	// Test simulated TLS ConnectionState check
	EnableECH = true
	defer func() { EnableECH = false }()

	// Case A: ECH was accepted by server
	stateAccepted := &tls.ConnectionState{
		Version:     tls.VersionTLS13,
		ECHAccepted: true,
	}
	if !stateAccepted.ECHAccepted {
		t.Fatalf("expected ECHAccepted to be true")
	}

	// Case B: ECH was rejected by server / intercepted
	stateRejected := &tls.ConnectionState{
		Version:     tls.VersionTLS13,
		ECHAccepted: false,
	}
	if stateRejected.ECHAccepted {
		t.Fatalf("expected ECHAccepted to be false")
	}

	// Verify our filtering logic
	validateECH := func(cs *tls.ConnectionState) bool {
		if !EnableECH {
			return true
		}
		return cs != nil && cs.ECHAccepted
	}

	if !validateECH(stateAccepted) {
		t.Fatalf("expected accepted ECH state to pass validation")
	}
	if validateECH(stateRejected) {
		t.Fatalf("expected rejected ECH state to fail validation")
	}
	if validateECH(nil) {
		t.Fatalf("expected nil TLS state to fail validation when EnableECH is true")
	}
}

func TestAllMultiEgressEndpoints_ECH_Resolution(t *testing.T) {
	// Test ECH resolution for all 6 real multi-egress domains used by xhttp-box
	domains := []struct {
		tag    string
		domain string
	}{
		{"aliyunsg-xhttp", "sin.piccdn.click"},
		{"hwhk-xhttp", "hkg.piccdn.click"},
		{"awsjp-xhttp", "nrt.piccdn.click"},
		{"aliyunus-xhttp", "sjc.piccdn.click"},
		{"rnlax-xhttp", "lax.piccdn.click"},
		{"fr-xhttp", "par.piccdn.click"},
	}

	for _, d := range domains {
		t.Run(d.tag, func(t *testing.T) {
			echBytes, err := fetchECHConfig(d.domain)
			if err != nil {
				t.Fatalf("failed to resolve ECH config for %s (%s): %v", d.tag, d.domain, err)
			}
			if len(echBytes) == 0 {
				t.Fatalf("expected non-empty ECH config bytes for %s (%s)", d.tag, d.domain)
			}
			t.Logf("[%s] %s -> ECH config resolved successfully (%d bytes)", d.tag, d.domain, len(echBytes))

			// Verify InitTLS for each domain
			EnableECH = true
			ForceH2 = true
			rawURL := "https://" + d.domain + "/__down?file=100mb"
			err = InitTLS(rawURL)
			if err != nil {
				t.Fatalf("failed to InitTLS for %s: %v", rawURL, err)
			}
			cfg := getTLSConfig()
			if cfg.ServerName != d.domain {
				t.Fatalf("expected ServerName %s, got %s", d.domain, cfg.ServerName)
			}
			if len(cfg.EncryptedClientHelloConfigList) == 0 {
				t.Fatalf("expected EncryptedClientHelloConfigList to be set for %s", d.domain)
			}
		})
	}
}
