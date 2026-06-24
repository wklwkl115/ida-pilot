package server

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// Filesystem allowlist for agent-supplied paths.
//
// open_binary and import_metadata take paths chosen by the MCP client. With the
// default single-trusted-local-client posture that's fine, but when the operator
// exposes the port (or just wants defense in depth) they can set AllowedRoots to
// confine those paths to specific directories. The check resolves symlinks so a
// link planted inside an allowed root that points outside it is still rejected.

// normalizeRoots cleans configured allow-roots into absolute, symlink-resolved
// forms for cheap prefix comparison, dropping blanks.
func normalizeRoots(roots []string) []string {
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		out = append(out, normalizeRoot(r))
	}
	return out
}

// normalizeRoot resolves a single root to an absolute, symlink-resolved path.
// A root that doesn't exist yet still works lexically — EvalSymlinks failure is
// non-fatal and falls back to the cleaned absolute form.
func normalizeRoot(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	abs = filepath.Clean(abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

// foldPath lowercases on case-insensitive filesystems (Windows) so the allowlist
// can't be sidestepped by case variation; identity elsewhere.
func foldPath(p string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(p)
	}
	return p
}

// pathWithin reports whether target is root itself or nested under it. It uses
// filepath.Rel rather than string prefixing so "/data" does not match the
// sibling "/data-evil".
func pathWithin(target, root string) bool {
	rel, err := filepath.Rel(foldPath(root), foldPath(target))
	if err != nil {
		return false
	}
	rel = filepath.Clean(rel)
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func pathWithinRoots(target string, roots []string) bool {
	for _, root := range roots {
		if pathWithin(target, root) {
			return true
		}
	}
	return false
}

// validatePath enforces the agent-supplied filesystem allowlist for a single
// path. With no roots configured it is a no-op returning the path unchanged
// (default posture). With roots configured, the path — both lexically and after
// symlink resolution — must resolve inside one of them, defeating ../ traversal
// and symlink escapes alike; it returns the symlink-resolved absolute path so
// callers hand the worker a canonical location. label names the field in errors.
func (s *Server) validatePath(label, p string) (string, error) {
	if len(s.allowedRoots) == 0 {
		return p, nil
	}
	if p == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("invalid %s %q: %w", label, p, err)
	}
	abs = filepath.Clean(abs)
	// Resolve to the file's real location before comparing — this follows
	// symlinks (defeating a link inside a root that points outside it) and, on
	// Windows, canonicalizes 8.3 short names, so both sides are compared in the
	// same form the roots were normalized to. When the file doesn't exist yet,
	// fall back to the lexical path; Clean() already collapsed any ".." so
	// traversal is still caught against the resolved roots.
	resolved := abs
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		resolved = r
	}
	if !pathWithinRoots(resolved, s.allowedRoots) {
		return "", fmt.Errorf("%s %q is outside the allowed roots", label, p)
	}
	return resolved, nil
}
