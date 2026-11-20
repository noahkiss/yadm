// Package oracle records what stock yadm produces in $HOME for a set of
// machine profiles, so a replacement can be checked against it byte for byte.
//
// The harness never touches a live home directory. It clones the source repo
// into a private sandbox, points yadm at that sandbox with its own directory
// flags, sets the profile through yadm's local.* overrides, and records every
// path the profile's home ends up holding.
package oracle

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Profile is one machine as yadm sees it.
type Profile struct {
	// Name labels the output directory. It defaults to Hostname.
	Name     string   `json:"name"`
	Hostname string   `json:"hostname"`
	Classes  []string `json:"classes"`
	OS       string   `json:"os"`
	Arch     string   `json:"arch,omitempty"`
	User     string   `json:"user"`
	// Decrypt gives the profile the repo's transcrypt key, so encrypted
	// paths check out as plaintext. Without it they stay ciphertext.
	Decrypt bool `json:"decrypt"`
}

// UserToken stands in for the login name when a profile names none.
const UserToken = "@@USER@@"

// ParseProfiles reads a tab-separated profiles file with a header line.
//
// Required columns: hostname, classes (comma-separated, in the order yadm
// adds them). Optional columns: name, os, arch, user, decrypt (yes/no).
// Other columns are ignored. A profile with no os column value takes
// defaultOS; if that is empty too, parsing fails.
func ParseProfiles(r io.Reader, defaultOS string) ([]Profile, error) {
	sc := bufio.NewScanner(r)
	var header []string
	var out []Profile
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(text) == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Split(text, "\t")
		if header == nil {
			header = fields
			if col(header, "hostname") < 0 || col(header, "classes") < 0 {
				return nil, fmt.Errorf("profiles header must name hostname and classes columns")
			}
			continue
		}
		get := func(name string) string {
			i := col(header, name)
			if i < 0 || i >= len(fields) {
				return ""
			}
			return strings.TrimSpace(fields[i])
		}
		p := Profile{
			Name:     get("name"),
			Hostname: get("hostname"),
			OS:       get("os"),
			Arch:     get("arch"),
			User:     get("user"),
		}
		if p.Hostname == "" {
			return nil, fmt.Errorf("profiles line %d: empty hostname", line)
		}
		if p.Name == "" {
			p.Name = p.Hostname
		}
		if strings.ContainsAny(p.Name, "/\\") || p.Name == "." || p.Name == ".." {
			return nil, fmt.Errorf("profiles line %d: name %q is not a plain directory name", line, p.Name)
		}
		for _, c := range strings.Split(get("classes"), ",") {
			if c = strings.TrimSpace(c); c != "" {
				p.Classes = append(p.Classes, c)
			}
		}
		if p.OS == "" {
			p.OS = defaultOS
		}
		if p.OS == "" {
			return nil, fmt.Errorf("profiles line %d: no os column value and no default os", line)
		}
		if p.User == "" {
			p.User = UserToken
		}
		switch strings.ToLower(get("decrypt")) {
		case "", "no", "false", "0":
		case "yes", "true", "1":
			p.Decrypt = true
		default:
			return nil, fmt.Errorf("profiles line %d: decrypt must be yes or no", line)
		}
		out = append(out, p)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if header == nil {
		return nil, fmt.Errorf("profiles file is empty")
	}
	seen := map[string]bool{}
	for _, p := range out {
		if seen[p.Name] {
			return nil, fmt.Errorf("duplicate profile name %q", p.Name)
		}
		seen[p.Name] = true
	}
	return out, nil
}

func col(header []string, name string) int {
	for i, h := range header {
		if strings.EqualFold(strings.TrimSpace(h), name) {
			return i
		}
	}
	return -1
}
