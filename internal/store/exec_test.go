package store

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestHashBlobConfigKeysAndGit(t *testing.T) {
	ctx := context.Background()
	_, a, _ := seeded(t)

	id, err := a.HashBlob(ctx, []byte("hello\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := a.ReadBlob(ctx, id); err != nil || string(got) != "hello\n" {
		t.Fatalf("ReadBlob(%s) = %q, %v", id, got, err)
	}

	keys, err := a.ConfigKeys(ctx, `^filter\..+$`, true)
	if err != nil || len(keys) != 0 {
		t.Fatalf("no filters: %v %v", keys, err)
	}
	rawGit(t, a.Dir(), "config", "filter.x.clean", "cat")
	rawGit(t, a.Dir(), "config", "merge.y.driver", "true")
	keys, err = a.ConfigKeys(ctx, `^(merge\..+\.driver|filter\..+)$`, false)
	if err != nil || strings.Join(keys, ",") != "filter.x.clean,merge.y.driver" {
		t.Fatalf("ConfigKeys = %v, %v", keys, err)
	}

	var out, errb bytes.Buffer
	code, err := a.Git(ctx, nil, &out, &errb, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil || code != 0 || strings.TrimSpace(out.String()) != "main" {
		t.Fatalf("Git rev-parse: %d %v %q %q", code, err, out.String(), errb.String())
	}
	if code, err := a.Git(ctx, nil, &out, &errb, "rev-parse", "--verify", "refs/heads/absent"); err != nil || code == 0 {
		t.Fatalf("Git on a missing ref: exit %d %v", code, err)
	}
	if _, err := Output(ctx, a.Dir(), "cat-file", "-e", "deadbeef"); err == nil || GitExitCode(err) <= 0 {
		t.Fatalf("Output on a missing object: %v", err)
	}
}

func TestRemoteHeads(t *testing.T) {
	ctx := context.Background()
	_, a, b := seeded(t)
	heads, err := b.RemoteHeads(ctx)
	if err != nil {
		t.Fatal(err)
	}
	main, _ := a.ResolveRef(ctx, RefMain)
	if heads[RefMain] != main {
		t.Fatalf("RemoteHeads main = %s, want %s (%v)", heads[RefMain], main, heads)
	}
	next := commitMain(t, a, "more", change("files/.more", "more\n"))
	if err := a.Push(ctx, []string{RefMain + ":" + RefMain}); err != nil {
		t.Fatal(err)
	}
	heads, err = b.RemoteHeads(ctx)
	if err != nil || heads[RefMain] != next {
		t.Fatalf("after push: %v %v", heads, err)
	}
	if local, _ := b.ResolveRef(ctx, RemoteMain); local == next {
		t.Fatal("RemoteHeads must not fetch")
	}
}
