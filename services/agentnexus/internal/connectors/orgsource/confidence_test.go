package orgsource

import "testing"

func TestPreviewAutoImportsHighConfidenceRows(t *testing.T) {
	preview := PreviewImport(Snapshot{
		Departments: []Department{{ID: "dept_legal", Name: "Legal"}},
		Employees: []Employee{{
			ID:            "user_1",
			DisplayName:   "Ada",
			Email:         "ada@example.com",
			Phone:         "+8613800000000",
			DepartmentIDs: []string{"dept_legal"},
		}},
	})

	if preview.RequiresConfirmation {
		t.Fatalf("RequiresConfirmation = true, conflicts = %+v", preview.Conflicts)
	}
	if len(preview.AutoImportableEmployeeIDs) != 1 || preview.AutoImportableEmployeeIDs[0] != "user_1" {
		t.Fatalf("AutoImportableEmployeeIDs = %+v, want user_1", preview.AutoImportableEmployeeIDs)
	}
}

func TestPreviewDetectsConflictsAndRequiresConfirmation(t *testing.T) {
	preview := PreviewImport(Snapshot{
		Departments: []Department{{ID: "dept_legal", Name: "Legal"}},
		Employees: []Employee{
			{ID: "user_1", DisplayName: "Ada", Email: "same@example.com", Phone: "+8613800000000", ManagerEmployeeID: "user_2", DepartmentIDs: []string{"dept_legal"}},
			{ID: "user_2", DisplayName: "Ben", Email: "same@example.com", Phone: "+8613800000000", ManagerEmployeeID: "user_1", DepartmentIDs: []string{"dept_legal"}},
			{ID: "user_3", DisplayName: "Cy", Email: "cy@example.com", ManagerEmployeeID: "missing_manager", DepartmentIDs: []string{"dept_legal"}},
		},
	})

	if !preview.RequiresConfirmation {
		t.Fatal("RequiresConfirmation = false, want true")
	}
	assertConflictCode(t, preview, ConflictDuplicateEmail)
	assertConflictCode(t, preview, ConflictDuplicatePhone)
	assertConflictCode(t, preview, ConflictMissingManager)
	assertConflictCode(t, preview, ConflictCyclicManager)
	if preview.ConfirmationReason == "" {
		t.Fatal("ConfirmationReason is empty")
	}
}

func assertConflictCode(t *testing.T, preview ImportPreview, code ConflictCode) {
	t.Helper()
	for _, conflict := range preview.Conflicts {
		if conflict.Code == code {
			return
		}
	}
	t.Fatalf("conflicts = %+v, want code %q", preview.Conflicts, code)
}
