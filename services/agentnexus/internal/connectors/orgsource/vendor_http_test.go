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

func TestVendorHTTPProviderFollowsNormalizedNextPagePath(t *testing.T) {
	var requestedPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer resolved-token" {
			t.Fatalf("Authorization header = %q, want Bearer resolved-token", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.RequestURI() {
		case "/org?page=1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"departments":    []map[string]any{{"id": "dept_rd", "name": "R&D"}},
				"next_page_path": "/org?page=2",
			})
		case "/org?page=2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"employees":   []map[string]any{{"id": "user_ada", "display_name": "Ada", "email": "ada@example.test", "department_ids": []string{"dept_rd"}}},
				"memberships": []map[string]any{{"employee_id": "user_ada", "department_id": "dept_rd"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewWeComHTTPProvider(VendorHTTPConfig{
		BaseURL:         server.URL,
		DepartmentsPath: "/org?page=1",
		EmployeesPath:   "/org?page=1",
		CredentialRef:   "secret://agentnexus/dev/wecom",
		TokenResolver: TokenResolverFunc(func(context.Context, string) (string, error) {
			return "resolved-token", nil
		}),
	})

	snapshot, err := provider.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	if len(requestedPaths) != 2 {
		t.Fatalf("requested paths = %#v, want first and next page only", requestedPaths)
	}
	if len(snapshot.Departments) != 1 || len(snapshot.Employees) != 1 || len(snapshot.Memberships) != 1 {
		t.Fatalf("snapshot = %+v, want paged departments, employees, memberships", snapshot)
	}
	if snapshot.Memberships[0].Role != RoleMember {
		t.Fatalf("membership role = %q, want default member", snapshot.Memberships[0].Role)
	}
}
