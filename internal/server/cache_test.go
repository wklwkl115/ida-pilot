package server

import "testing"

func TestDecompCacheLRUEviction(t *testing.T) {
	t.Parallel()

	c := newDecompCache(3)
	c.set(1, "a")
	c.set(2, "b")
	c.set(3, "c")

	// Touch 1 — moves it to front; eviction order is now 2, 3, 1.
	if code, ok := c.get(1); !ok || code != "a" {
		t.Fatalf("get(1) = (%q, %v), want (a, true)", code, ok)
	}

	// Insert a 4th entry — capacity 3, so the least-recently-used (2) must go.
	c.set(4, "d")

	if _, ok := c.get(2); ok {
		t.Errorf("expected 2 evicted as LRU, still present")
	}
	for _, addr := range []uint64{1, 3, 4} {
		if _, ok := c.get(addr); !ok {
			t.Errorf("expected %d to remain after eviction", addr)
		}
	}
}

func TestDecompCacheSetOverwriteKeepsOrder(t *testing.T) {
	t.Parallel()

	c := newDecompCache(2)
	c.set(1, "first")
	c.set(2, "second")
	c.set(1, "first updated") // refresh front

	if code, ok := c.get(1); !ok || code != "first updated" {
		t.Fatalf("get(1) = (%q, %v), want (first updated, true)", code, ok)
	}

	// Adding a third entry must evict 2 (now the LRU), not 1.
	c.set(3, "third")
	if _, ok := c.get(2); ok {
		t.Errorf("expected 2 evicted after refresh of 1")
	}
	if _, ok := c.get(1); !ok {
		t.Errorf("expected 1 to remain — it was just refreshed")
	}
}

func TestDecompCacheDeleteWhere(t *testing.T) {
	t.Parallel()

	c := newDecompCache(4)
	c.set(1, "alpha calls old_name();")
	c.set(2, "beta unrelated;")
	c.set(3, "gamma also old_name();")
	c.set(4, "delta clean;")

	removed := c.deleteWhere(func(code string) bool {
		return contains(code, "old_name")
	})
	if removed != 2 {
		t.Errorf("deleteWhere returned %d, want 2", removed)
	}
	if _, ok := c.get(1); ok {
		t.Errorf("expected 1 removed")
	}
	if _, ok := c.get(3); ok {
		t.Errorf("expected 3 removed")
	}
	if _, ok := c.get(2); !ok {
		t.Errorf("expected 2 to remain")
	}
	if _, ok := c.get(4); !ok {
		t.Errorf("expected 4 to remain")
	}
}

// contains avoids the strings import for a single test-local substring check.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
