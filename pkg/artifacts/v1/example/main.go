package main

import (
	"os"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts/v1"
)

func main() {
	f, err := os.Open("grype-report.json")
	if err != nil {
		panic(err)
	}
	artifacts.ListGrypeReport(os.Stdout, f)
}
