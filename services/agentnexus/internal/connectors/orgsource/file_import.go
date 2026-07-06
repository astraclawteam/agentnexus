package orgsource

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/xuri/excelize/v2"
)

func ParseCSV(reader io.Reader) (Snapshot, error) {
	csvReader := csv.NewReader(reader)
	csvReader.TrimLeadingSpace = true

	rows, err := csvReader.ReadAll()
	if err != nil {
		return Snapshot{}, err
	}
	return parseRows(rows)
}

func ParseXLSX(reader io.Reader) (Snapshot, error) {
	file, err := excelize.OpenReader(reader)
	if err != nil {
		return Snapshot{}, err
	}
	defer file.Close()

	sheets := file.GetSheetList()
	if len(sheets) == 0 {
		return Snapshot{}, fmt.Errorf("xlsx has no sheets")
	}
	rows, err := file.GetRows(sheets[0])
	if err != nil {
		return Snapshot{}, err
	}
	return parseRows(rows)
}

func parseRows(rows [][]string) (Snapshot, error) {
	if len(rows) == 0 {
		return Snapshot{}, nil
	}

	header := map[string]int{}
	for index, column := range rows[0] {
		header[strings.TrimSpace(column)] = index
	}

	var snapshot Snapshot
	for _, row := range rows[1:] {
		recordType := field(row, header, "record_type")
		switch recordType {
		case "":
			continue
		case "department":
			snapshot.Departments = append(snapshot.Departments, Department{
				ID:                field(row, header, "id"),
				ParentID:          field(row, header, "parent_id"),
				Name:              field(row, header, "name"),
				ManagerEmployeeID: field(row, header, "manager_id"),
			})
		case "employee":
			employee := Employee{
				ID:                field(row, header, "id"),
				DisplayName:       field(row, header, "display_name"),
				Email:             field(row, header, "email"),
				Phone:             field(row, header, "phone"),
				ManagerEmployeeID: field(row, header, "manager_id"),
			}
			if departmentID := field(row, header, "department_id"); departmentID != "" {
				employee.DepartmentIDs = []string{departmentID}
			}
			snapshot.Employees = append(snapshot.Employees, employee)
		case "membership":
			role := Role(field(row, header, "role"))
			if role == "" {
				role = RoleMember
			}
			snapshot.Memberships = append(snapshot.Memberships, Membership{
				EmployeeID:   field(row, header, "id"),
				DepartmentID: field(row, header, "department_id"),
				Role:         role,
			})
		default:
			return Snapshot{}, fmt.Errorf("unsupported org import record_type %q", recordType)
		}
	}

	return NormalizeSnapshot(snapshot), nil
}

func field(row []string, header map[string]int, name string) string {
	index, ok := header[name]
	if !ok || index >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[index])
}
