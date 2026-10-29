package main

import (
	"os/exec"
	"regexp"
)

// hasACL reports whether path carries an access control list; ls -le
// prints its entries as numbered lines. Without cgo there is no direct
// call, and any ACL is refused rather than interpreted. Not being able to
// tell is an error, never a no.
func hasACL(path string) (bool, error) {
	out, err := exec.Command(aclLister, "-lde", path).Output()
	if err != nil {
		return false, err
	}
	return aclEntry.Match(out), nil
}

// aclLister lists a path with its ACL; tests replace it.
var aclLister = "/bin/ls"

var aclEntry = regexp.MustCompile(`(?m)^\s*\d+: `)
