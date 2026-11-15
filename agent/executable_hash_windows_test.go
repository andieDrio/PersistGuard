package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestHashesOnlyEligibleLocalExecutables(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	first := filepath.Join(dir, "fixture one.exe")
	second := filepath.Join(dir, "fixture-two.exe")
	if err := os.WriteFile(first, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	hasher := newExecutableHasher()
	if digest := hasher.hashCommand(ctx, `"`+first+`" --example`); digest != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("unexpected first fixture SHA-256: %q", digest)
	}
	if digest := hasher.hashExecutable(ctx, second); digest != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("unexpected second fixture SHA-256: %q", digest)
	}
	for _, path := range []string{`\\example.invalid\share\fixture.exe`, `\\?\C:\fixture.exe`,
		`C:\dir\..\fixture.exe`, `C:\fixture.exe:other.exe`, `fixture.exe`, `C:\NUL.exe`, filepath.Join(dir, "missing.exe")} {
		if digest := hasher.hashExecutable(ctx, path); digest != "" {
			t.Errorf("ineligible path %q produced a digest", path)
		}
	}
	limited := newExecutableHasher()
	limited.remaining = 2
	if digest := limited.hashExecutable(ctx, first); digest != "" {
		t.Fatalf("fixture larger than the remaining byte budget was hashed: %s", digest)
	}
}

func TestHashSkipsExecutableThroughDirectoryJunction(t *testing.T) {
	dir := t.TempDir()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "fixture.exe"), []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked")
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/j", link, target).CombinedOutput(); err != nil {
		t.Fatalf("create fixture junction: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if err := os.Remove(link); err != nil {
			t.Errorf("remove fixture junction: %v", err)
		}
	})
	if digest := newExecutableHasher().hashExecutable(context.Background(), filepath.Join(link, "fixture.exe")); digest != "" {
		t.Fatalf("file reached through a directory link was hashed: %s", digest)
	}
}
