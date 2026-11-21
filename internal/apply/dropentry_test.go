package apply

import "testing"

// removeEntries drops whole [[file]] tables, their [file.*] sub-tables and
// the comments directly above them, and leaves every other line alone.
func TestRemoveEntries(t *testing.T) {
	src := `schema = 1

[[file]]
target = "a"

# b's comment
[[file]]
target = "b"
when = "type:work"

[file.seal]
"token" = "personal"

# c's comment
[[file]]
target = "c"

[[root]]
path = "r"

[[file]]
target = "d"
`
	cases := []struct {
		idxs []int
		want string
	}{
		{[]int{1}, `schema = 1

[[file]]
target = "a"

# c's comment
[[file]]
target = "c"

[[root]]
path = "r"

[[file]]
target = "d"
`},
		{[]int{0, 3}, `schema = 1

# b's comment
[[file]]
target = "b"
when = "type:work"

[file.seal]
"token" = "personal"

# c's comment
[[file]]
target = "c"

[[root]]
path = "r"
`},
	}
	for _, c := range cases {
		got, err := removeEntries([]byte(src), c.idxs)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != c.want {
			t.Fatalf("remove %v:\n%s\nwant:\n%s", c.idxs, got, c.want)
		}
	}
	if _, err := removeEntries([]byte(src), []int{4}); err == nil {
		t.Fatal("a missing table must fail")
	}
}
