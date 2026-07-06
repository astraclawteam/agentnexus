package orgsource

import "fmt"

type ConflictCode string

const (
	ConflictDuplicateEmail ConflictCode = "duplicate_email"
	ConflictDuplicatePhone ConflictCode = "duplicate_phone"
	ConflictMissingManager ConflictCode = "missing_manager"
	ConflictCyclicManager  ConflictCode = "cyclic_manager"
)

type Conflict struct {
	Code        ConflictCode `json:"code"`
	EmployeeID  string       `json:"employee_id"`
	RelatedID   string       `json:"related_id,omitempty"`
	Description string       `json:"description"`
}

type PreviewRow struct {
	EmployeeID  string
	Confidence  float64
	AutoImport  bool
	ConflictIDs []ConflictCode
}

type ImportPreview struct {
	Rows                      []PreviewRow
	Conflicts                 []Conflict
	AutoImportableEmployeeIDs []string
	RequiresConfirmation      bool
	ConfirmationReason        string
}

func PreviewImport(snapshot Snapshot) ImportPreview {
	snapshot = NormalizeSnapshot(snapshot)
	conflicts := detectConflicts(snapshot)
	conflictsByEmployee := map[string][]ConflictCode{}
	for _, conflict := range conflicts {
		conflictsByEmployee[conflict.EmployeeID] = append(conflictsByEmployee[conflict.EmployeeID], conflict.Code)
		if conflict.RelatedID != "" {
			conflictsByEmployee[conflict.RelatedID] = append(conflictsByEmployee[conflict.RelatedID], conflict.Code)
		}
	}

	preview := ImportPreview{
		Conflicts:            conflicts,
		RequiresConfirmation: len(conflicts) > 0,
	}
	for _, employee := range snapshot.Employees {
		row := PreviewRow{
			EmployeeID:  employee.ID,
			Confidence:  0.99,
			AutoImport:  true,
			ConflictIDs: conflictsByEmployee[employee.ID],
		}
		if len(row.ConflictIDs) > 0 {
			row.Confidence = 0.25
			row.AutoImport = false
		}
		preview.Rows = append(preview.Rows, row)
		if row.AutoImport {
			preview.AutoImportableEmployeeIDs = append(preview.AutoImportableEmployeeIDs, employee.ID)
		}
	}
	if preview.RequiresConfirmation {
		preview.ConfirmationReason = fmt.Sprintf("%d organization import conflicts require review", len(conflicts))
	}
	return preview
}

func detectConflicts(snapshot Snapshot) []Conflict {
	var conflicts []Conflict
	employeesByID := map[string]Employee{}
	emailOwner := map[string]string{}
	phoneOwner := map[string]string{}

	for _, employee := range snapshot.Employees {
		employeesByID[employee.ID] = employee
		if employee.Email != "" {
			if existing, ok := emailOwner[employee.Email]; ok && existing != employee.ID {
				conflicts = append(conflicts, Conflict{Code: ConflictDuplicateEmail, EmployeeID: employee.ID, RelatedID: existing, Description: "email is used by multiple employees"})
			} else {
				emailOwner[employee.Email] = employee.ID
			}
		}
		if employee.Phone != "" {
			if existing, ok := phoneOwner[employee.Phone]; ok && existing != employee.ID {
				conflicts = append(conflicts, Conflict{Code: ConflictDuplicatePhone, EmployeeID: employee.ID, RelatedID: existing, Description: "phone is used by multiple employees"})
			} else {
				phoneOwner[employee.Phone] = employee.ID
			}
		}
	}

	for _, employee := range snapshot.Employees {
		if employee.ManagerEmployeeID != "" {
			if _, ok := employeesByID[employee.ManagerEmployeeID]; !ok {
				conflicts = append(conflicts, Conflict{Code: ConflictMissingManager, EmployeeID: employee.ID, RelatedID: employee.ManagerEmployeeID, Description: "manager is missing from import"})
			}
		}
	}

	for _, employee := range snapshot.Employees {
		if hasManagerCycle(employee.ID, employeesByID) {
			conflicts = append(conflicts, Conflict{Code: ConflictCyclicManager, EmployeeID: employee.ID, Description: "manager chain contains a cycle"})
			break
		}
	}

	return conflicts
}

func hasManagerCycle(employeeID string, employeesByID map[string]Employee) bool {
	seen := map[string]struct{}{}
	current := employeeID
	for current != "" {
		if _, ok := seen[current]; ok {
			return true
		}
		seen[current] = struct{}{}
		employee, ok := employeesByID[current]
		if !ok {
			return false
		}
		current = employee.ManagerEmployeeID
	}
	return false
}
