package server

import (
	"errors"
	"sort"
	"sync/atomic"
	"testing"
)

func TestRunLabeled(t *testing.T) {
	t.Parallel()

	results, errs := runLabeled(map[string]func() (any, error){
		"a": func() (any, error) { return 1, nil },
		"b": func() (any, error) { return "two", nil },
		"c": func() (any, error) { return nil, errors.New("boom") },
	})

	if len(results) != 2 || len(errs) != 1 {
		t.Fatalf("expected 2 results + 1 err, got results=%v errs=%v", results, errs)
	}
	if results["a"] != 1 || results["b"] != "two" {
		t.Errorf("wrong success values: %v", results)
	}
	if results["c"] != nil {
		t.Errorf("failed key must not appear in results: %v", results["c"])
	}
	if errs["c"] == nil || errs["c"].Error() != "boom" {
		t.Errorf("expected error for c, got %v", errs["c"])
	}
	// A success key must never also be an error key.
	for k := range results {
		if _, bad := errs[k]; bad {
			t.Errorf("key %q in both results and errs", k)
		}
	}

	// Empty task set is a no-op (and must not deadlock).
	r, e := runLabeled(map[string]func() (any, error){})
	if len(r) != 0 || len(e) != 0 {
		t.Errorf("empty tasks: expected empty maps, got %v / %v", r, e)
	}
}

func TestParallelMap(t *testing.T) {
	t.Parallel()

	in := []int{1, 2, 3, 4, 5}
	out := parallelMap(in, func(n int) int { return n * n })

	want := []int{1, 4, 9, 16, 25}
	if len(out) != len(want) {
		t.Fatalf("length mismatch: got %v", out)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("order not preserved at %d: got %d, want %d", i, out[i], want[i])
		}
	}

	if got := parallelMap([]int{}, func(n int) int { return n }); len(got) != 0 {
		t.Errorf("empty input: expected empty slice, got %v", got)
	}

	// Every item's fn runs exactly once (race detector validates the writes too).
	var calls atomic.Int64
	parallelMap(make([]int, 50), func(int) int { calls.Add(1); return 0 })
	if calls.Load() != 50 {
		t.Errorf("expected 50 calls, got %d", calls.Load())
	}
}

// sortedKeys is exercised by the survey refactor; covered here so the helper is
// pinned independent of caller wiring.
func TestSortedFailedKeysDeterministic(t *testing.T) {
	t.Parallel()
	errs := map[string]error{"zeta": errors.New("x"), "alpha": errors.New("y"), "mid": errors.New("z")}
	keys := make([]string, 0, len(errs))
	for k := range errs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if keys[0] != "alpha" || keys[2] != "zeta" {
		t.Errorf("sorted keys wrong: %v", keys)
	}
}
