package observability

import (
	"fmt"
	"sort"
	"strings"
)

type Snapshot struct {
	Service  string
	Ready    bool
	Counters map[string]int64
}

func PrometheusText(snapshot Snapshot) string {
	var b strings.Builder
	ready := 0
	if snapshot.Ready {
		ready = 1
	}
	fmt.Fprintf(&b, "agentnexus_service_ready{service=%q} %d\n", snapshot.Service, ready)

	keys := make([]string, 0, len(snapshot.Counters))
	for key := range snapshot.Counters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&b, "agentnexus_%s %d\n", sanitizeMetricName(key), snapshot.Counters[key])
	}
	return b.String()
}

func sanitizeMetricName(name string) string {
	replacer := strings.NewReplacer("-", "_", ".", "_", " ", "_")
	return replacer.Replace(name)
}
