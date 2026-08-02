package utils

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewJSONDocument(t *testing.T) {
	generatedAt := time.Date(2026, time.August, 2, 10, 20, 30, 0, time.UTC)
	data := []CloudflareIPData{{
		PingData: &PingData{
			IP:       &net.IPAddr{IP: net.ParseIP("104.16.1.2")},
			Sended:   4,
			Received: 3,
			Delay:    123*time.Millisecond + 500*time.Microsecond,
			Colo:     "HKG",
		},
		DownloadSpeed: 8 * 1024 * 1024,
	}}

	document := newJSONDocument(data, generatedAt)
	if document.SchemaVersion != 1 {
		t.Fatalf("unexpected schema version: %d", document.SchemaVersion)
	}
	if document.Best == nil || document.Best.IP != "104.16.1.2" {
		t.Fatalf("unexpected best result: %#v", document.Best)
	}
	if document.Best.LossRate != 0.25 {
		t.Fatalf("unexpected loss rate: %v", document.Best.LossRate)
	}
	if document.Best.LatencyMilliseconds != 123.5 {
		t.Fatalf("unexpected latency: %v", document.Best.LatencyMilliseconds)
	}
	if document.Best.DownloadSpeedMBPerSecond != 8 {
		t.Fatalf("unexpected download speed: %v", document.Best.DownloadSpeedMBPerSecond)
	}
}

func TestEmptyJSONDocumentHasNullBestAndEmptyResults(t *testing.T) {
	document := newJSONDocument(nil, time.Unix(0, 0).UTC())
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err = json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["best"] != nil {
		t.Fatalf("best should be null: %s", encoded)
	}
	results, ok := decoded["results"].([]any)
	if !ok || len(results) != 0 {
		t.Fatalf("results should be an empty array: %s", encoded)
	}
}

func TestAtomicWriteFileReplacesContentAndPreservesMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(path, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new" {
		t.Fatalf("unexpected content: %q", content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("unexpected mode: %o", info.Mode().Perm())
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".result.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", matches)
	}
}
