package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/iam"
)

func TestConsoleOverviewHandlerReturnsDemoOverviewWhenRequested(t *testing.T) {
	server := httptest.NewServer(NewGatewayAPIRouter("gateway-api", "0.1.0-test"))
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/console/overview?locale=zh&demo=true")
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

	if overview.Source.Kind != "development_fixture" {
		t.Fatalf("Source.Kind = %q, want development_fixture", overview.Source.Kind)
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
	req := httptest.NewRequest(http.MethodGet, "/api/console/overview?locale=fr&demo=true", nil)
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

func TestConsoleOverviewLiveRequiresEnterpriseID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/console/overview", nil)
	rec := httptest.NewRecorder()

	NewGatewayAPIRouter("gateway-api", "0.1.0-test").ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
	}
}

func TestLiveConsoleOverviewUsesChineseCopy(t *testing.T) {
	overview := NewLiveConsoleOverview("zh", setupEnterpriseContext{
		EnterpriseName:   "顺视智能制造集团",
		EnvironmentLabel: "私有化环境",
	}, iam.OrgGraph{
		Users: []iam.EnterpriseUser{{ID: "user_ada"}},
		Departments: []iam.OrgUnit{{
			ID: "dept_rd",
		}},
		Memberships: []iam.OrgMembership{{EnterpriseUserID: "user_ada", OrgUnitID: "dept_rd"}},
		Versions:    []iam.OrgVersion{{VersionNumber: 1}},
	})

	if overview.Title != "企业智能行政中枢" {
		t.Fatalf("Title = %q, want Chinese live title", overview.Title)
	}
	if overview.Source.Label != "Gateway API 实时数据" {
		t.Fatalf("Source.Label = %q, want Chinese live source label", overview.Source.Label)
	}
	if overview.Topbar.Search != "搜索员工、系统、策略、审计号" {
		t.Fatalf("Topbar.Search = %q, want Chinese search placeholder", overview.Topbar.Search)
	}
	if overview.Metrics[0][0] != "已同步员工" || overview.ResourceMap.Tabs[0] != "组织" || overview.Connectors.Title != "连接器健康" {
		t.Fatalf("overview is not localized: metrics=%#v tabs=%#v connectors=%q", overview.Metrics, overview.ResourceMap.Tabs, overview.Connectors.Title)
	}
}
