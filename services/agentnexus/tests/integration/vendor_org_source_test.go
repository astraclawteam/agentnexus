package integration

import (
	"context"
	"os"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/orgsource"
)

func TestWeComOrgSource(t *testing.T) {
	testVendorOrgSource(t, "AGENTNEXUS_TEST_WECOM", orgsource.NewWeComHTTPProvider)
}

func TestFeishuOrgSource(t *testing.T) {
	testVendorOrgSource(t, "AGENTNEXUS_TEST_FEISHU", orgsource.NewFeishuHTTPProvider)
}

func TestDingTalkOrgSource(t *testing.T) {
	testVendorOrgSource(t, "AGENTNEXUS_TEST_DINGTALK", orgsource.NewDingTalkHTTPProvider)
}

func testVendorOrgSource(t *testing.T, prefix string, newProvider func(orgsource.VendorHTTPConfig) orgsource.Provider) {
	t.Helper()
	baseURL := os.Getenv(prefix + "_BASE_URL")
	token := os.Getenv(prefix + "_TOKEN")
	departmentsPath := os.Getenv(prefix + "_DEPARTMENTS_PATH")
	employeesPath := os.Getenv(prefix + "_EMPLOYEES_PATH")
	if baseURL == "" || token == "" || departmentsPath == "" || employeesPath == "" {
		t.Skip("set " + prefix + "_BASE_URL, " + prefix + "_TOKEN, " + prefix + "_DEPARTMENTS_PATH, and " + prefix + "_EMPLOYEES_PATH to run vendor org source integration")
	}

	provider := newProvider(orgsource.VendorHTTPConfig{
		BaseURL:         baseURL,
		DepartmentsPath: departmentsPath,
		EmployeesPath:   employeesPath,
		CredentialRef:   "secret://agentnexus/test/" + providerName(prefix),
		TokenResolver: orgsource.TokenResolverFunc(func(context.Context, string) (string, error) {
			return token, nil
		}),
	})
	snapshot, err := provider.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	if len(snapshot.Departments) == 0 {
		t.Fatal("expected at least one department from vendor source")
	}
	if len(snapshot.Employees) == 0 {
		t.Fatal("expected at least one employee from vendor source")
	}
}

func providerName(prefix string) string {
	switch prefix {
	case "AGENTNEXUS_TEST_WECOM":
		return "wecom"
	case "AGENTNEXUS_TEST_FEISHU":
		return "feishu"
	case "AGENTNEXUS_TEST_DINGTALK":
		return "dingtalk"
	default:
		return "vendor"
	}
}
