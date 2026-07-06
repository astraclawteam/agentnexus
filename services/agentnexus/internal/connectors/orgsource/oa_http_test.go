package orgsource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOAHTTPProviderFetchesAndNormalizesSnapshot(t *testing.T) {
	var authHeaders []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/departments":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"departments": []map[string]string{
					{"id": "dept_rd", "parent_id": "", "name": "R&D", "manager_employee_id": "user_ada"},
				},
			})
		case "/employees":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"employees": []map[string]any{
					{
						"id":                  "user_ada",
						"display_name":        "Ada",
						"email":               "ada@example.test",
						"phone":               "",
						"manager_employee_id": "",
						"department_ids":      []string{"dept_rd", "dept_rd"},
					},
				},
				"memberships": []map[string]string{
					{"employee_id": "user_ada", "department_id": "dept_rd", "role": "manager"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewOAHTTPProvider(OAHTTPConfig{
		BaseURL:         server.URL,
		DepartmentsPath: "/departments",
		EmployeesPath:   "/employees",
		Token:           "test-token",
	})

	snapshot, err := provider.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if provider.Name() != "oa_http" {
		t.Fatalf("Name() = %q, want oa_http", provider.Name())
	}
	if len(authHeaders) != 2 {
		t.Fatalf("auth header count = %d, want 2", len(authHeaders))
	}
	for _, header := range authHeaders {
		if header != "Bearer test-token" {
			t.Fatalf("Authorization header = %q, want Bearer test-token", header)
		}
	}
	if got := len(snapshot.Departments); got != 1 {
		t.Fatalf("department count = %d, want 1", got)
	}
	if got := len(snapshot.Employees); got != 1 {
		t.Fatalf("employee count = %d, want 1", got)
	}
	if got := snapshot.Employees[0].DepartmentIDs; len(got) != 1 || got[0] != "dept_rd" {
		t.Fatalf("normalized department ids = %#v, want [dept_rd]", got)
	}
	if got := len(snapshot.Memberships); got != 1 {
		t.Fatalf("membership count = %d, want 1", got)
	}
	if snapshot.Memberships[0].Role != RoleManager {
		t.Fatalf("membership role = %q, want %q", snapshot.Memberships[0].Role, RoleManager)
	}
}
