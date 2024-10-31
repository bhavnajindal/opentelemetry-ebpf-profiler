package reporter

import "go.opentelemetry.io/ebpf-profiler/libpf"

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
