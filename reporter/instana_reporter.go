package reporter

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
