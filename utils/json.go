package utils

import (
	"encoding/json"
	"log"
	"time"
)

const jsonSchemaVersion = 1

var JSONOutput string

type JSONResult struct {
	IP                       string  `json:"ip"`
	Sent                     int     `json:"sent"`
	Received                 int     `json:"received"`
	LossRate                 float32 `json:"loss_rate"`
	LatencyMilliseconds      float64 `json:"latency_ms"`
	DownloadSpeedMBPerSecond float64 `json:"download_speed_mb_per_second"`
	Colo                     string  `json:"colo"`
}

type JSONDocument struct {
	SchemaVersion int          `json:"schema_version"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Best          *JSONResult  `json:"best"`
	Results       []JSONResult `json:"results"`
}

// ExportJSON writes a versioned, machine-readable result document. Publishing
// is atomic, so a watcher cannot observe a partially written JSON document.
func ExportJSON(data []CloudflareIPData) {
	if JSONOutput == "" || JSONOutput == " " {
		return
	}
	document := newJSONDocument(data, time.Now().UTC())
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		log.Fatalf("生成 JSON 结果失败：%v", err)
	}
	encoded = append(encoded, '\n')
	if err = atomicWriteFile(JSONOutput, encoded, 0o644); err != nil {
		log.Fatalf("写入 JSON 结果[%s]失败：%v", JSONOutput, err)
	}
}

func newJSONDocument(data []CloudflareIPData, generatedAt time.Time) JSONDocument {
	results := make([]JSONResult, 0, len(data))
	for index := range data {
		item := &data[index]
		results = append(results, JSONResult{
			IP:                       item.IP.String(),
			Sent:                     item.Sended,
			Received:                 item.Received,
			LossRate:                 item.getLossRate(),
			LatencyMilliseconds:      float64(item.Delay) / float64(time.Millisecond),
			DownloadSpeedMBPerSecond: item.DownloadSpeed / 1024 / 1024,
			Colo:                     item.Colo,
		})
	}

	document := JSONDocument{
		SchemaVersion: jsonSchemaVersion,
		GeneratedAt:   generatedAt,
		Results:       results,
	}
	if len(results) > 0 {
		document.Best = &document.Results[0]
	}
	return document
}
