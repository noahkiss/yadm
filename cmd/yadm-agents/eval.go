package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Evaluator answers condition questions. yadm owns the condition language,
// the fleet and every machine's facts, so the real one asks `yadm eval`
// rather than reimplementing them. Tests use a fake.
type Evaluator interface {
	// Eval evaluates a condition for a machine; "" is this machine.
	Eval(expr, machine string) (bool, error)
	// This names this machine.
	This() (string, error)
	// Machines lists every fleet machine by name.
	Machines() ([]string, error)
}

// expandLocal inlines every `cond:NAME` whose NAME the units file defines,
// so the matrix works before yadm loads the file through
// conditions.include. A name the file does not define is left for yadm.
func expandLocal(expr string, defs map[string]string) (string, error) {
	return expandDepth(expr, defs, map[string]bool{})
}

func expandDepth(expr string, defs map[string]string, stack map[string]bool) (string, error) {
	var b strings.Builder
	for {
		i := strings.Index(expr, "cond:")
		if i < 0 {
			b.WriteString(expr)
			return b.String(), nil
		}
		// cond: must start a term
		if i > 0 && !strings.ContainsRune(" \t\n!&|(", rune(expr[i-1])) {
			b.WriteString(expr[:i+5])
			expr = expr[i+5:]
			continue
		}
		j := i + 5
		for j < len(expr) && isNameByte(expr[j]) {
			j++
		}
		name := expr[i+5 : j]
		b.WriteString(expr[:i])
		def, ok := defs[name]
		switch {
		case !ok:
			b.WriteString(expr[i:j])
		case stack[name]:
			return "", fmt.Errorf("condition %q refers to itself", name)
		default:
			stack[name] = true
			inner, err := expandDepth(def, defs, stack)
			delete(stack, name)
			if err != nil {
				return "", err
			}
			b.WriteString("(" + inner + ")")
		}
		expr = expr[j:]
	}
}

func isNameByte(c byte) bool {
	return c == '.' || c == '_' || c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// yadmEval runs the yadm binary. Results are cached per run.
type yadmEval struct {
	bin       string
	cache     map[string]bool
	this      string
	delivered map[string]map[string]bool
}

func newYadmEval() *yadmEval {
	bin := os.Getenv("YADM_AGENTS_YADM")
	if bin == "" {
		bin = "yadm"
	}
	return &yadmEval{bin: bin, cache: map[string]bool{}}
}

type envelope struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (y *yadmEval) run(args ...string) (json.RawMessage, error) {
	cmd := exec.Command(y.bin, append(args, "--json")...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()
	var env envelope
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		if runErr != nil {
			return nil, fmt.Errorf("%s %s: %v: %s", y.bin, strings.Join(args, " "), runErr, strings.TrimSpace(errb.String()))
		}
		return nil, fmt.Errorf("%s %s: bad JSON: %v", y.bin, strings.Join(args, " "), err)
	}
	if !env.OK {
		msg := "failed"
		if env.Error != nil {
			msg = env.Error.Message
		}
		return nil, fmt.Errorf("%s %s: %s", y.bin, strings.Join(args, " "), msg)
	}
	return env.Data, nil
}

func (y *yadmEval) Eval(expr, machine string) (bool, error) {
	switch strings.TrimSpace(expr) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	k := machine + "\x00" + expr
	if v, ok := y.cache[k]; ok {
		return v, nil
	}
	args := []string{"eval", expr}
	if machine != "" {
		args = append(args, "--as", machine)
	}
	data, err := y.run(args...)
	if err != nil {
		return false, err
	}
	var r struct {
		Result      bool     `json:"result"`
		Unavailable []string `json:"unavailable"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return false, err
	}
	if len(r.Unavailable) > 0 {
		return false, fmt.Errorf("condition %q on %s reads collectors this machine cannot see: %s", expr, machine, strings.Join(r.Unavailable, ", "))
	}
	y.cache[k] = r.Result
	return r.Result, nil
}

func (y *yadmEval) This() (string, error) {
	if y.this != "" {
		return y.this, nil
	}
	if n := os.Getenv("YADM_MACHINE_NAME"); n != "" {
		y.this = n
		return n, nil
	}
	data, err := y.run("machine")
	if err != nil {
		return "", err
	}
	var m struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return "", err
	}
	if m.Name == "" {
		return "", errors.New("yadm machine: no name")
	}
	y.this = m.Name
	return m.Name, nil
}

func (y *yadmEval) Machines() ([]string, error) {
	data, err := y.run("fleet", "list")
	if err != nil {
		return nil, err
	}
	var r struct {
		Machines []struct {
			Machine struct {
				Name string `json:"name"`
			} `json:"machine"`
		} `json:"machines"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	var out []string
	for _, m := range r.Machines {
		out = append(out, m.Machine.Name)
	}
	return out, nil
}

// cellOn evaluates the unit × harness cell for a machine. A unit with no
// cell for the harness is off.
func cellOn(f *File, ev Evaluator, unit, harness, machine string) (on bool, has bool, err error) {
	c, ok := f.Cell(unit, harness)
	if !ok {
		return false, false, nil
	}
	x, err := expandLocal(c, f.Conditions)
	if err != nil {
		return false, true, err
	}
	on, err = ev.Eval(x, machine)
	if err != nil {
		return false, true, fmt.Errorf("cell %s.%s: %w", unit, harness, err)
	}
	return on, true, nil
}

// Delivered lists the targets the manifest gives a machine. One fleet
// query serves every machine.
func (y *yadmEval) Delivered(machine string) (map[string]bool, error) {
	if y.delivered == nil {
		data, err := y.run("manifest", "--fleet")
		if err != nil {
			return nil, err
		}
		var r struct {
			Machines []struct {
				Name    string `json:"name"`
				Error   string `json:"error"`
				Entries []struct {
					Target string `json:"target"`
				} `json:"entries"`
			} `json:"machines"`
		}
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, err
		}
		y.delivered = map[string]map[string]bool{}
		for _, m := range r.Machines {
			if m.Error != "" {
				continue
			}
			s := map[string]bool{}
			for _, e := range m.Entries {
				s[e.Target] = true
			}
			y.delivered[m.Name] = s
		}
	}
	s, ok := y.delivered[machine]
	if !ok {
		return nil, fmt.Errorf("manifest: no entries for %s", machine)
	}
	return s, nil
}
