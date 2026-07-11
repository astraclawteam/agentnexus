package main

import (
	"fmt"
	"os"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/deploypreflight"
)

func main() {
	if err := deploypreflight.ValidateProductionPostgresDSN(os.Getenv("AGENTNEXUS_POSTGRES_DSN")); err != nil {
		fmt.Fprintln(os.Stderr, "release-preflight:", err)
		os.Exit(1)
	}
}
