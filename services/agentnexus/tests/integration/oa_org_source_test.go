package integration

import (
	"context"
	"os"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/orgsource"
)

func TestOAOrgSource(t *testing.T) {
	baseURL := os.Getenv("AGENTNEXUS_TEST_OA_BASE_URL")
	token := os.Getenv("AGENTNEXUS_TEST_OA_TOKEN")
	departmentsPath := os.Getenv("AGENTNEXUS_TEST_OA_DEPARTMENTS_PATH")
	employeesPath := os.Getenv("AGENTNEXUS_TEST_OA_EMPLOYEES_PATH")
	if baseURL == "" || token == "" || departmentsPath == "" || employeesPath == "" {
		t.Skip("set AGENTNEXUS_TEST_OA_BASE_URL, AGENTNEXUS_TEST_OA_TOKEN, AGENTNEXUS_TEST_OA_DEPARTMENTS_PATH, and AGENTNEXUS_TEST_OA_EMPLOYEES_PATH to run real OA org source integration")
	}

	provider := orgsource.NewOAHTTPProvider(orgsource.OAHTTPConfig{
		BaseURL:         baseURL,
		DepartmentsPath: departmentsPath,
		EmployeesPath:   employeesPath,
		Token:           token,
	})

	snapshot, err := provider.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(snapshot.Departments) == 0 {
		t.Fatal("expected at least one department from OA source")
	}
	if len(snapshot.Employees) == 0 {
		t.Fatal("expected at least one employee from OA source")
	}
}
