package server

import "sync"

// runLabeled runs each named task concurrently and returns the successful
// results and the per-task errors, both keyed by task name. A task's key
// appears in exactly one of the two maps: results on success, errs on failure.
// Callers apply their own failure policy (e.g. list failed keys, embed an
// error field, or fail when every task errored).
//
// The channel is buffered to len(tasks) so no worker blocks on send, and the
// drain reads exactly len(tasks) values, so no WaitGroup or close is needed.
func runLabeled(tasks map[string]func() (any, error)) (results map[string]any, errs map[string]error) {
	type labeled struct {
		key string
		val any
		err error
	}
	ch := make(chan labeled, len(tasks))
	for key, fn := range tasks {
		go func(key string, fn func() (any, error)) {
			v, e := fn()
			ch <- labeled{key, v, e}
		}(key, fn)
	}

	results = make(map[string]any)
	errs = make(map[string]error)
	for range tasks {
		r := <-ch
		if r.err != nil {
			errs[r.key] = r.err
		} else {
			results[r.key] = r.val
		}
	}
	return results, errs
}

// parallelMap applies fn to every item concurrently and returns the results in
// input order. Each goroutine writes a distinct slice index, so no locking is
// needed. fn must fold any per-item error into its return value (R), since the
// whole point is per-item degradation rather than aborting the batch.
func parallelMap[T, R any](items []T, fn func(T) R) []R {
	results := make([]R, len(items))
	var wg sync.WaitGroup
	for i, item := range items {
		wg.Add(1)
		go func(i int, item T) {
			defer wg.Done()
			results[i] = fn(item)
		}(i, item)
	}
	wg.Wait()
	return results
}
