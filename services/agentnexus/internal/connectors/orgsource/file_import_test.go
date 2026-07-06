package orgsource

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"
)

func TestParseCSVOrgSnapshot(t *testing.T) {
	csvData := `record_type,id,parent_id,name,display_name,email,phone,manager_id,department_id,role
department,dept_legal,,Legal,,,,,,
employee,user_1,,,Ada,ada@example.com,+8613800000000,,dept_legal,
membership,user_1,,,,,,,dept_legal,manager
`

	snapshot, err := ParseCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("ParseCSV returned error: %v", err)
	}
	if len(snapshot.Departments) != 1 || snapshot.Departments[0].Name != "Legal" {
		t.Fatalf("departments = %+v, want Legal", snapshot.Departments)
	}
	if len(snapshot.Employees) != 1 || snapshot.Employees[0].Email != "ada@example.com" {
		t.Fatalf("employees = %+v, want ada@example.com", snapshot.Employees)
	}
	if len(snapshot.Memberships) != 1 || snapshot.Memberships[0].DepartmentID != "dept_legal" {
		t.Fatalf("memberships = %+v, want dept_legal", snapshot.Memberships)
	}
}

func TestParseXLSXOrgSnapshot(t *testing.T) {
	file := excelize.NewFile()
	sheet := file.GetSheetName(0)
	rows := [][]any{
		{"record_type", "id", "parent_id", "name", "display_name", "email", "phone", "manager_id", "department_id", "role"},
		{"department", "dept_legal", "", "Legal", "", "", "", "", "", ""},
		{"employee", "user_1", "", "", "Ada", "ada@example.com", "+8613800000000", "", "dept_legal", ""},
		{"membership", "user_1", "", "", "", "", "", "", "dept_legal", "manager"},
	}
	for index, row := range rows {
		cell, err := excelize.CoordinatesToCellName(1, index+1)
		if err != nil {
			t.Fatalf("CoordinatesToCellName returned error: %v", err)
		}
		if err := file.SetSheetRow(sheet, cell, &row); err != nil {
			t.Fatalf("SetSheetRow returned error: %v", err)
		}
	}
	buffer, err := file.WriteToBuffer()
	if err != nil {
		t.Fatalf("WriteToBuffer returned error: %v", err)
	}

	snapshot, err := ParseXLSX(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		t.Fatalf("ParseXLSX returned error: %v", err)
	}
	if len(snapshot.Departments) != 1 || len(snapshot.Employees) != 1 || len(snapshot.Memberships) != 1 {
		t.Fatalf("snapshot = %+v, want one department, employee, and membership", snapshot)
	}
}
