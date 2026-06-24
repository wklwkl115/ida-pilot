package server

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// newGuardedServer builds a Server whose allowlist is normalized the same way
// SetSecurity does it, so tests exercise the real comparison path.
func newGuardedServer(roots ...string) *Server {
	return &Server{allowedRoots: normalizeRoots(roots)}
}

func TestValidatePathNoRootsIsPassthrough(t *testing.T) {
	t.Parallel()
	s := &Server{} // no roots configured
	in := filepath.Join("some", "..", "weird", "path.bin")
	got, err := s.validatePath("path", in)
	if err != nil {
		t.Fatalf("unrestricted validatePath errored: %v", err)
	}
	if got != in {
		t.Errorf("unrestricted validatePath altered the path: got %q want %q", got, in)
	}
}

func TestValidatePathAcceptsInsideRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	bin := filepath.Join(root, "target.bin")
	if err := os.WriteFile(bin, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newGuardedServer(root)
	got, err := s.validatePath("path", bin)
	if err != nil {
		t.Fatalf("path inside root rejected: %v", err)
	}
	if !pathWithinRoots(got, s.allowedRoots) {
		t.Errorf("returned path %q is not within the allowed roots", got)
	}
}

func TestValidatePathRejectsOutsideRoot(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	allowed := filepath.Join(base, "allowed")
	other := filepath.Join(base, "other")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(other, "secret.bin")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newGuardedServer(allowed)
	if _, err := s.validatePath("path", outside); err == nil {
		t.Errorf("path outside the allowed root was accepted")
	}
}

func TestValidatePathRejectsTraversal(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	allowed := filepath.Join(base, "allowed")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	// Lexically climbs out of the root via "..".
	escape := filepath.Join(allowed, "..", "other", "secret.bin")
	s := newGuardedServer(allowed)
	if _, err := s.validatePath("path", escape); err == nil {
		t.Errorf("traversal path %q was accepted", escape)
	}
}

func TestValidatePathRejectsSiblingPrefix(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	data := filepath.Join(base, "data")
	sibling := filepath.Join(base, "data-evil")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	// "data-evil" shares the "data" string prefix but is not under it.
	target := filepath.Join(sibling, "x.bin")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newGuardedServer(data)
	if _, err := s.validatePath("path", target); err == nil {
		t.Errorf("sibling-prefix path %q was accepted", target)
	}
}

func TestValidatePathRejectsSymlinkEscape(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevation on Windows")
	}
	base := t.TempDir()
	allowed := filepath.Join(base, "allowed")
	secret := filepath.Join(base, "secret")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	realTarget := filepath.Join(secret, "passwd")
	if err := os.WriteFile(realTarget, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(allowed, "link.bin")
	if err := os.Symlink(realTarget, link); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}
	s := newGuardedServer(allowed)
	// Lexically the link is inside the root; resolution must catch the escape.
	if _, err := s.validatePath("path", link); err == nil {
		t.Errorf("symlink escaping the allowed root was accepted")
	}
}

func TestValidatePathEmptyWithRootsErrors(t *testing.T) {
	t.Parallel()
	s := newGuardedServer(t.TempDir())
	if _, err := s.validatePath("path", ""); err == nil {
		t.Errorf("empty path with roots configured must error")
	}
}
