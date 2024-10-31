package reporter

import (
	"context"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

var _ Reporter = (*InstanaReporter)(nil)

type InstanaReporter struct {
	agentId string

	url string

	instanaKey string
}

func (r *InstanaReporter) Stop() {
	close(r.stopSignal)
}

func (r *InstanaReporter) ReportMetrics(timestamp uint32, ids []uint32, values []int64) {}

func (r *InstanaReporter) GetMetrics() Metrics {
	return Metrics{}
}

func (r *InstanaReporter) ReportCountForTrace(_ libpf.TraceHash, _ libpf.UnixTime64,
	_ uint16, _, _, _, _ string, _ int64) {
}

func (r *InstanaReporter) SupportsReportTraceEvent() bool { return true }

func (r *InstanaReporter) ReportFramesForTrace(_ *libpf.Trace) {}

func (r *InstanaReporter) ReportHostMetadata(metadataMap map[string]string) {}

// ReportHostMetadataBlocking sends host metadata to the collection agent.
func (r *InstanaReporter) ReportHostMetadataBlocking(ctx context.Context, metadataMap map[string]string,
	maxRetries int, waitRetry time.Duration) error {
	return nil
}

type CallSite struct {
	File_line   int64      `json:"file_line"`
	File_name   string     `json:"file_name"`
	Method_name string     `json:"method_name"`
	Measurement int64      `json:"measurement"`
	Num_samples int64      `json:"num_samples"`
	Children    []CallSite `json:"children"`
}

func (r *InstanaReporter) ReportFallbackSymbol(frameID libpf.FrameID, symbol string) {
	if _, exists := r.fallbackSymbols.Peek(frameID); exists {
		return
	}
	r.fallbackSymbols.Add(frameID, symbol)
}

func (r *InstanaReporter) ExecutableMetadata(_ context.Context,
	fileID libpf.FileID, fileName, buildID string) {
	r.executables.Add(fileID, execInfo{
		fileName: fileName,
		buildID:  buildID,
	})
}
