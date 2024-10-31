package reporter

var _ Reporter = (*InstanaReporter)(nil)

type InstanaReporter struct {
	agentId string

	url string

	instanaKey string
}
