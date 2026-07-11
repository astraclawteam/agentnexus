package deploypreflight

import "testing"

func TestValidateProductionPostgresDSNRequiresOneStrongExplicitTLSMode(t *testing.T) {
	valid := []string{
		"postgres://runtime:secret@db.example:5432/agentnexus?sslmode=require",
		"postgres://runtime:secret@db.example:5432/agentnexus?connect_timeout=5&sslmode=verify-ca",
		"postgres://runtime:p%40ss@db.example:5432/agentnexus?sslmode=verify-full",
	}
	for _, dsn := range valid {
		if err := ValidateProductionPostgresDSN(dsn); err != nil {
			t.Fatalf("valid DSN rejected: %v", err)
		}
	}
	invalid := map[string]string{
		"empty":                 "",
		"keyword format":        "host=db.example dbname=agentnexus sslmode=require",
		"http":                  "https://db.example/agentnexus?sslmode=verify-full",
		"postgresql alias":      "postgresql://db.example/agentnexus?sslmode=verify-full",
		"missing host":          "postgres:///agentnexus?sslmode=verify-full",
		"missing database":      "postgres://db.example?sslmode=verify-full",
		"missing mode":          "postgres://db.example/agentnexus",
		"disable":               "postgres://db.example/agentnexus?sslmode=disable",
		"allow":                 "postgres://db.example/agentnexus?sslmode=allow",
		"prefer":                "postgres://db.example/agentnexus?sslmode=prefer",
		"duplicate same":        "postgres://db.example/agentnexus?sslmode=require&sslmode=require",
		"duplicate conflict":    "postgres://db.example/agentnexus?sslmode=require&sslmode=disable",
		"encoded key duplicate": "postgres://db.example/agentnexus?sslmode=require&%73slmode=verify-full",
		"encoded strong key":    "postgres://db.example/agentnexus?%73slmode=verify-full",
		"encoded strong value":  "postgres://db.example/agentnexus?sslmode=verify%2Dfull",
		"encoded weak value":    "postgres://db.example/agentnexus?sslmode=%64isable",
		"case bypass":           "postgres://db.example/agentnexus?SSLMODE=verify-full&sslmode=require",
		"malformed percent":     "postgres://db.example/agentnexus?sslmode=verify-full%ZZ",
		"fragment":              "postgres://db.example/agentnexus?sslmode=verify-full#ignored",
	}
	for name, dsn := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := ValidateProductionPostgresDSN(dsn); err == nil {
				t.Fatal("unsafe DSN accepted")
			}
		})
	}
}
