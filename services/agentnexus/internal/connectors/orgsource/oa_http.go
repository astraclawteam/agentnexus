package orgsource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const oaHTTPProviderName = "oa_http"
const oaHTTPMaxPages = 100

type OAHTTPConfig struct {
	BaseURL         string
	DepartmentsPath string
	EmployeesPath   string
	Token           string
	HTTPClient      *http.Client
}

type oaHTTPProvider struct {
	config OAHTTPConfig
	client *http.Client
}

func NewOAHTTPProvider(config OAHTTPConfig) Provider {
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return oaHTTPProvider{
		config: config,
		client: client,
	}
}

func (p oaHTTPProvider) Name() string {
	return oaHTTPProviderName
}

func (p oaHTTPProvider) Fetch(ctx context.Context) (Snapshot, error) {
	if p.config.BaseURL == "" {
		return Snapshot{}, fmt.Errorf("oa_http base_url is required")
	}
	if p.config.DepartmentsPath == "" {
		return Snapshot{}, fmt.Errorf("oa_http departments path is required")
	}
	if p.config.EmployeesPath == "" {
		return Snapshot{}, fmt.Errorf("oa_http employees path is required")
	}

	var snapshot Snapshot
	departmentsPayload, err := p.fetchSnapshotPayload(ctx, p.config.DepartmentsPath)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Departments = append(snapshot.Departments, departmentsPayload.Departments...)
	snapshot.Employees = append(snapshot.Employees, departmentsPayload.Employees...)
	snapshot.Memberships = append(snapshot.Memberships, departmentsPayload.Memberships...)

	if p.config.EmployeesPath != p.config.DepartmentsPath {
		employeesPayload, err := p.fetchSnapshotPayload(ctx, p.config.EmployeesPath)
		if err != nil {
			return Snapshot{}, err
		}
		snapshot.Departments = append(snapshot.Departments, employeesPayload.Departments...)
		snapshot.Employees = append(snapshot.Employees, employeesPayload.Employees...)
		snapshot.Memberships = append(snapshot.Memberships, employeesPayload.Memberships...)
	}

	return NormalizeSnapshot(snapshot), nil
}

func (p oaHTTPProvider) fetchSnapshotPayload(ctx context.Context, endpointPath string) (Snapshot, error) {
	var snapshot Snapshot
	nextPath := endpointPath
	visited := map[string]struct{}{}
	for page := 0; nextPath != ""; page++ {
		if page >= oaHTTPMaxPages {
			return Snapshot{}, fmt.Errorf("oa_http %s exceeded max page count %d", endpointPath, oaHTTPMaxPages)
		}
		if _, ok := visited[nextPath]; ok {
			return Snapshot{}, fmt.Errorf("oa_http %s returned repeated next_page_path %q", endpointPath, nextPath)
		}
		visited[nextPath] = struct{}{}
		payload, err := p.fetchOneSnapshotPayload(ctx, nextPath)
		if err != nil {
			return Snapshot{}, err
		}
		pageSnapshot := payload.toSnapshot()
		snapshot.Departments = append(snapshot.Departments, pageSnapshot.Departments...)
		snapshot.Employees = append(snapshot.Employees, pageSnapshot.Employees...)
		snapshot.Memberships = append(snapshot.Memberships, pageSnapshot.Memberships...)
		nextPath = payload.NextPagePath
	}
	return snapshot, nil
}

func (p oaHTTPProvider) fetchOneSnapshotPayload(ctx context.Context, endpointPath string) (oaHTTPSnapshotPayload, error) {
	endpoint, err := p.endpointURL(endpointPath)
	if err != nil {
		return oaHTTPSnapshotPayload{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return oaHTTPSnapshotPayload{}, err
	}
	if p.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.config.Token)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return oaHTTPSnapshotPayload{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return oaHTTPSnapshotPayload{}, fmt.Errorf("oa_http %s returned status %d", endpointPath, resp.StatusCode)
	}

	var payload oaHTTPSnapshotPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return oaHTTPSnapshotPayload{}, err
	}
	return payload, nil
}

func (p oaHTTPProvider) endpointURL(endpointPath string) (string, error) {
	if _, err := url.ParseRequestURI(endpointPath); err == nil && strings.HasPrefix(endpointPath, "http") {
		return endpointPath, nil
	}
	baseURL := strings.TrimRight(p.config.BaseURL, "/")
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return "", fmt.Errorf("invalid oa_http base_url: %w", err)
	}
	return baseURL + "/" + strings.TrimLeft(endpointPath, "/"), nil
}

type oaHTTPSnapshotPayload struct {
	Departments  []oaHTTPDepartment `json:"departments"`
	Employees    []oaHTTPEmployee   `json:"employees"`
	Memberships  []oaHTTPMembership `json:"memberships"`
	NextPagePath string             `json:"next_page_path"`
}

type oaHTTPDepartment struct {
	ID                string `json:"id"`
	ParentID          string `json:"parent_id"`
	Name              string `json:"name"`
	ManagerEmployeeID string `json:"manager_employee_id"`
}

type oaHTTPEmployee struct {
	ID                string   `json:"id"`
	DisplayName       string   `json:"display_name"`
	Email             string   `json:"email"`
	Phone             string   `json:"phone"`
	ManagerEmployeeID string   `json:"manager_employee_id"`
	DepartmentIDs     []string `json:"department_ids"`
}

type oaHTTPMembership struct {
	EmployeeID   string `json:"employee_id"`
	DepartmentID string `json:"department_id"`
	Role         Role   `json:"role"`
}

func (p oaHTTPSnapshotPayload) toSnapshot() Snapshot {
	snapshot := Snapshot{
		Departments: make([]Department, 0, len(p.Departments)),
		Employees:   make([]Employee, 0, len(p.Employees)),
		Memberships: make([]Membership, 0, len(p.Memberships)),
	}
	for _, department := range p.Departments {
		snapshot.Departments = append(snapshot.Departments, Department{
			ID:                department.ID,
			ParentID:          department.ParentID,
			Name:              department.Name,
			ManagerEmployeeID: department.ManagerEmployeeID,
		})
	}
	for _, employee := range p.Employees {
		snapshot.Employees = append(snapshot.Employees, Employee{
			ID:                employee.ID,
			DisplayName:       employee.DisplayName,
			Email:             employee.Email,
			Phone:             employee.Phone,
			ManagerEmployeeID: employee.ManagerEmployeeID,
			DepartmentIDs:     append([]string(nil), employee.DepartmentIDs...),
		})
	}
	for _, membership := range p.Memberships {
		snapshot.Memberships = append(snapshot.Memberships, Membership{
			EmployeeID:   membership.EmployeeID,
			DepartmentID: membership.DepartmentID,
			Role:         membership.Role,
		})
	}
	return snapshot
}
