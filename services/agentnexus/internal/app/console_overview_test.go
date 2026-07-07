package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConsoleOverviewHandlerReturnsLocalizedAPIOverview(t *testing.T) {
	server := httptest.NewServer(NewGatewayAPIRouter("gateway-api", "0.1.0-test"))
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/console/overview?locale=zh")
	if err != nil {
		t.Fatalf("GET console overview: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got, want := resp.Header.Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("Content-Type = %q, want %q", got, want)
	}

	var overview ConsoleOverview
	if err := json.NewDecoder(resp.Body).Decode(&overview); err != nil {
		t.Fatalf("decode overview: %v", err)
	}

	if overview.Source.Kind != "api" {
		t.Fatalf("Source.Kind = %q, want api", overview.Source.Kind)
	}
	if overview.Source.Label != "Gateway API" {
		t.Fatalf("Source.Label = %q, want Gateway API", overview.Source.Label)
	}
	if overview.Enterprise != "示例企业（Gateway API）" {
		t.Fatalf("Enterprise = %q, want API sample enterprise", overview.Enterprise)
	}
	if overview.Topbar.Search == "" || len(overview.Metrics) != 4 || len(overview.Tickets.Rows) == 0 {
		t.Fatalf("overview missing required console sections: %+v", overview)
	}
}

func TestConsoleOverviewHandlerFallsBackToEnglish(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/console/overview?locale=fr", nil)
	rec := httptest.NewRecorder()

	NewGatewayAPIRouter("gateway-api", "0.1.0-test").ServeHTTP(rec, req)

	var overview ConsoleOverview
	if err := json.NewDecoder(rec.Body).Decode(&overview); err != nil {
		t.Fatalf("decode overview: %v", err)
	}

	if overview.Title != "Enterprise Agent Command Center" {
		t.Fatalf("Title = %q, want English fallback", overview.Title)
	}
}
