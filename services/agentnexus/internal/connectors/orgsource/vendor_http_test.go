package orgsource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVendorHTTPProvidersFetchNormalizedSnapshotWithCredentialRef(t *testing.T) {
	providers := []struct {
		name string
		new  func(VendorHTTPConfig) Provider
	}{
		{name: "wecom", new: NewWeComHTTPProvider},
		{name: "feishu", new: NewFeishuHTTPProvider},
		{name: "dingtalk", new: NewDingTalkHTTPProvider},
	}
	for _, tc := range providers {
		t.Run(tc.name, func(t *testing.T) {
			var sawAuth bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "Bearer resolved-token" {
					sawAuth = true
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"departments": []map[string]any{{"id": "dept_rd", "name": "R&D"}},
					"employees":   []map[string]any{{"id": "user_ada", "display_name": "Ada", "email": "ada@example.test", "department_ids": []string{"dept_rd", "dept_rd"}}},
					"memberships": []map[string]any{{"employee_id": "user_ada", "department_id": "dept_rd", "role": "manager"}},
				})
			}))
			defer server.Close()

			provider := tc.new(VendorHTTPConfig{
				BaseURL:         server.URL,
				DepartmentsPath: "/org",
				EmployeesPath:   "/org",
				CredentialRef:   "secret://agentnexus/dev/" + tc.name,
				TokenResolver: TokenResolverFunc(func(_ context.Context, ref string) (string, error) {
					if ref == "" {
						t.Fatal("credential ref is empty")
					}
					return "resolved-token", nil
				}),
			})

			snapshot, err := provider.Fetch(context.Background())
			if err != nil {
				t.Fatalf("Fetch returned error: %v", err)
			}
			if provider.Name() != tc.name {
				t.Fatalf("Name = %q, want %q", provider.Name(), tc.name)
			}
			if !sawAuth {
				t.Fatal("expected Authorization header from credential ref resolver")
			}
			if len(snapshot.Departments) != 1 || len(snapshot.Employees) != 1 || len(snapshot.Employees[0].DepartmentIDs) != 1 {
				t.Fatalf("snapshot = %+v", snapshot)
			}
		})
	}
}
