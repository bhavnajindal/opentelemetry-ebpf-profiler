package reporter

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
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

func (r *InstanaReporter) ReportTraceEvent(trace *libpf.Trace,
	timestamp libpf.UnixTime64, comm, podName,
	containerName, apmServiceName string, pid int64) {
	traceEvents := r.traceEvents.WLock()
	defer r.traceEvents.WUnlock(&traceEvents)

	if tr, exists := (*traceEvents)[trace.Hash]; exists {
		tr.timestamps = append(tr.timestamps, uint64(timestamp))
		(*traceEvents)[trace.Hash] = tr
		return
	}

	(*traceEvents)[trace.Hash] = traceFramesCounts{
		files:          trace.Files,
		linenos:        trace.Linenos,
		frameTypes:     trace.FrameTypes,
		comm:           comm,
		podName:        podName,
		containerName:  containerName,
		apmServiceName: apmServiceName,
		timestamps:     []uint64{uint64(timestamp)},
		pid:            strconv.FormatInt(pid, 10),
	}

}

func getPHPMasterPid(pid string) string {
	cmd := exec.Command("ps", "-p", strings.TrimSpace(pid), "-o", "ppid=")
	ppid, err := cmd.Output()

	if err == nil {
		cmd = exec.Command("ps", "-p", strings.TrimSpace(string(ppid)), "-o", "args=")
		pname, err := cmd.Output()
		if err == nil {
			if strings.Contains(string(pname), "php-fpm: master process") {
				fmt.Println("put correct pid")
				return strings.TrimSpace(string(ppid))
			}
		} else {
			log.Warnf("Unable to get PHP-FPM Master process", err.Error()) //improve log msg
		}
	} else {
		log.Warnf("Unable to get parent of PHP-FPM process", err.Error()) ////improve log msg
	}
	return pid
}

func getInstanaAgentId() (string, error) {

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	method := "GET"
	url := "http://localhost:42699/info"

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		log.Errorf(err.Error())
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Warnf(err.Error())
		return "", err
	}
	defer resp.Body.Close()

	var agentData interface{}
	err = json.NewDecoder(resp.Body).Decode(&agentData)
	if err != nil {
		log.Errorf(err.Error())
		return "", err
	}

	if agentInfo, ok := agentData.(map[string]interface{}); ok {
		if id, ok := agentInfo["agent-id"].(string); ok {
			return id, nil
		}
	}

	return "", errors.New("couldn't get Instana agent id")

}

func getInstanaUrl() (string, string, error) {
	cfg, err := ini.Load("/opt/instana/agent/etc/instana/com.instana.agent.main.sender.Backend.cfg")
	if err != nil {
		return "", "", err //Add more log here
	}

	host := cfg.Section("").Key("host")
	if host == nil {
		return "", "", errors.New("couldn't get Instana host")
	}
	port := cfg.Section("").Key("port")
	if port == nil {
		return "", "", errors.New("couldn't get Instana Port")
	}
	instaKey := cfg.Section("").Key("key")
	if instaKey == nil {
		return "", "", errors.New("couldn't get Instana Key")
	}

	url := "https://" + host.String() + ":" + port.String() + "/profiles"

	//fmt.Println("url and key", url, instaKey)

	return url, instaKey.String(), nil
}
