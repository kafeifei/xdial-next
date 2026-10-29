//go:build !darwin

package main

// hasACL is a macOS check: the daemon installs only there. Elsewhere,
// where CI runs the tests, there is nothing to check.
func hasACL(string) (bool, error) { return false, nil }
