// Package harness provides shared utilities for the certdx e2e test suite.
//
// It builds the certdx_server, certdx_client and certdx_tools binaries once
// per test run and provides helpers to drive them as subprocesses against
// per-test temporary working directories.
//
// All test files in this module use the //go:build e2e build tag so that a
// plain `go test ./...` is a no-op; run the suite with:
//
//	go test -tags=e2e ./...
package harness
