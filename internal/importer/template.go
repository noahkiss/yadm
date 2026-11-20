package importer

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/noahkiss/yadm/internal/render"
)

// Upstream's built-in template processor recognises only these whole-line
// directives and inline variables; every other byte is literal text.
const legacyVar = `(?:env|yadm)\.[a-zA-Z0-9_]+`

var (
	reIf      = regexp.MustCompile(`^[ \t]*\{%[ \t]*if[ \t]+(` + legacyVar + `)[ \t]*([!=]=)[ \t]*"(.*)"[ \t]*%\}$`)
	reElse    = regexp.MustCompile(`^[ \t]*\{%[ \t]*else[ \t]*%\}$`)
	reEndif   = regexp.MustCompile(`^[ \t]*\{%[ \t]*endif[ \t]*%\}$`)
	reInclude = regexp.MustCompile(`^[ \t]*\{%[ \t]*include[ \t]+("[^"]+"|[^"]+)[ \t]*%\}$`)
	reVar     = regexp.MustCompile(`\{\{[ \t]*(` + legacyVar + `)[ \t]*\}\}`)
)

// tmplResult is a converted template.
type tmplResult struct {
	Out   []byte
	Facts map[string]bool // declared facts the template reads
	Atoms []atom          // condition terms the template tests
}

// includeFunc returns the content of a repository file named by its path
// relative to $HOME. ok is false when the repository has no such file.
type includeFunc func(home string) (content []byte, ok bool, err error)

type tmplConv struct {
	res      tmplResult
	problems []Problem
	out      strings.Builder
	depth    []bool // per open if: whether an else was seen
	include  includeFunc
	nest     int
}

// maxInclude bounds include nesting, which also stops include cycles.
const maxInclude = 8

// convertTemplate converts a template for upstream's built-in processor into
// the section 5.2 syntax. name is the legacy path, for problems; homePath is
// the template's path below $HOME, which anchors relative includes.
func convertTemplate(name, homePath string, src []byte, include includeFunc) (tmplResult, []Problem) {
	c := &tmplConv{res: tmplResult{Facts: map[string]bool{}}, include: include}
	c.file(name, homePath, src)
	if len(c.depth) > 0 {
		c.problem(name, 0, "unterminated if")
	}
	// Upstream writes the processor output through a shell substitution and
	// a here-string: trailing newlines collapse to exactly one.
	c.res.Out = []byte(strings.TrimRight(c.out.String(), "\n") + "\n")
	return c.res, c.problems
}

func (c *tmplConv) problem(name string, line int, msg string) {
	c.problems = append(c.problems, Problem{Path: name, Line: line, Reason: msg})
}

func (c *tmplConv) file(name, homePath string, src []byte) {
	if len(src) == 0 {
		return
	}
	lines := strings.Split(strings.TrimSuffix(string(src), "\n"), "\n")
	for i, line := range lines {
		n := i + 1
		switch {
		case reIf.MatchString(line):
			m := reIf.FindStringSubmatch(line)
			cond, ok := c.condition(name, n, m[1], m[2], m[3])
			if !ok {
				cond = "false"
			}
			c.depth = append(c.depth, false)
			c.out.WriteString("{% if " + cond + " %}\n")
		case reElse.MatchString(line):
			if len(c.depth) == 0 {
				c.problem(name, n, "else without matching if")
				continue
			}
			if c.depth[len(c.depth)-1] {
				c.problem(name, n, "second else in one if")
			}
			c.depth[len(c.depth)-1] = true
			c.out.WriteString("{% else %}\n")
		case reEndif.MatchString(line):
			if len(c.depth) == 0 {
				c.problem(name, n, "endif without matching if")
				continue
			}
			c.depth = c.depth[:len(c.depth)-1]
			c.out.WriteString("{% endif %}\n")
		case reInclude.MatchString(line):
			c.includeLine(name, homePath, n, line)
		default:
			c.line(name, n, line)
		}
	}
}

// includeLine inlines an included repository file, converting it the same way.
func (c *tmplConv) includeLine(name, homePath string, n int, line string) {
	arg := reInclude.FindStringSubmatch(line)[1]
	if strings.Contains(arg, "{{") {
		c.problem(name, n, "include path uses a variable")
		return
	}
	p, ok := includePath(homePath, arg)
	if !ok {
		c.problem(name, n, fmt.Sprintf("include %s is outside the repository", arg))
		return
	}
	if c.nest >= maxInclude {
		c.problem(name, n, "includes nest too deep")
		return
	}
	if c.include == nil {
		c.problem(name, n, fmt.Sprintf("include %s: file not in the repository", p))
		return
	}
	b, found, err := c.include(p)
	if err != nil {
		c.problem(name, n, fmt.Sprintf("include %s: %v", p, err))
		return
	}
	if !found {
		c.problem(name, n, fmt.Sprintf("include %s: file not in the repository", p))
		return
	}
	c.nest++
	c.file(p, p, b)
	c.nest--
}

// line converts one text line: inline variables become references.
func (c *tmplConv) line(name string, n int, line string) {
	var b strings.Builder
	last := 0
	for _, loc := range reVar.FindAllStringSubmatchIndex(line, -1) {
		ref, ok := c.reference(name, n, line[loc[2]:loc[3]])
		literal(line[last:loc[0]], ok, &b)
		if ok {
			b.WriteString(ref)
		}
		last = loc[1]
	}
	literal(line[last:], false, &b)
	c.out.WriteString(b.String() + "\n")
}

// literal copies text that upstream prints as is, escaping every tag opener
// with render.Escape. When a tag follows, a trailing "{" is escaped too, or
// it would join the tag's own "{{".
func literal(s string, tagFollows bool, b *strings.Builder) {
	e := render.Escape(s)
	if tagFollows && strings.HasSuffix(e, "{") {
		e = e[:len(e)-1] + `{{ "{" }}`
	}
	b.WriteString(e)
}

// reference maps one upstream variable to a section 5.2 reference.
func (c *tmplConv) reference(name string, n int, v string) (string, bool) {
	switch v {
	case "env.HOME":
		return "{{ home }}", true
	case "yadm.user":
		return "{{ user }}", true
	case "yadm.os":
		return "{{ machine.os }}", true
	case "yadm.arch":
		return "{{ machine.arch }}", true
	case "yadm.hostname", "yadm.class", "yadm.classes", "yadm.distro", "yadm.distro_family":
		k := strings.TrimPrefix(v, "yadm.")
		c.res.Facts[k] = true
		return "{{ machine.facts." + k + " }}", true
	}
	if strings.HasPrefix(v, "env.") {
		c.problem(name, n, fmt.Sprintf("environment variable %s has no equivalent; only env.HOME converts", v))
	} else {
		c.problem(name, n, fmt.Sprintf("variable %s has no equivalent", v))
	}
	return "", false
}

// condition maps `if VAR == "value"` to a condition.
func (c *tmplConv) condition(name string, n int, v, op, rhs string) (string, bool) {
	if strings.Contains(rhs, "{{") {
		c.problem(name, n, "if compares against a variable")
		return "", false
	}
	var a atom
	switch v {
	case "yadm.class":
		a = atom{"type", strings.ToLower(rhs)}
	case "yadm.os":
		a = atom{"os", strings.ToLower(rhs)}
	case "yadm.arch":
		a = atom{"arch", strings.ToLower(rhs)}
	case "yadm.hostname", "yadm.user", "yadm.distro", "yadm.distro_family":
		a = atom{"fact:" + strings.TrimPrefix(v, "yadm."), rhs}
	default:
		c.problem(name, n, fmt.Sprintf("if on %s has no equivalent condition", v))
		return "", false
	}
	if a.Value == "" {
		c.problem(name, n, fmt.Sprintf("if on %s compares against an empty value", v))
		return "", false
	}
	c.res.Atoms = append(c.res.Atoms, a)
	if op == "!=" {
		return "!" + a.String(), true
	}
	return a.String(), true
}

// includePath resolves an include argument against the template's directory below $HOME.
func includePath(homePath, arg string) (string, bool) {
	arg = strings.Trim(arg, "\" \t")
	if strings.HasPrefix(arg, "/") {
		return "", false
	}
	p := path.Clean(path.Join(path.Dir(homePath), arg))
	if p == ".." || strings.HasPrefix(p, "../") {
		return "", false
	}
	return p, true
}
