package server

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
	"github.com/wklwkl115/ida-pilot/internal/worker"
)

const maxDecompCacheEntries = 200

// decompEntry is the value stored in the LRU list. We keep addr alongside the
// code so eviction can delete the entries-map row without walking it.
type decompEntry struct {
	addr uint64
	code string
}

// decompCache is a bounded LRU keyed by address. Hot entries (recently
// fetched) live at the front of order; eviction removes the back. The
// container/list element pointer in entries lets every operation stay O(1).
//
// Not goroutine-safe — sessionCache.mu serializes all access.
type decompCache struct {
	cap     int
	entries map[uint64]*list.Element
	order   *list.List
}

func newDecompCache(cap int) *decompCache {
	return &decompCache{
		cap:     cap,
		entries: make(map[uint64]*list.Element),
		order:   list.New(),
	}
}

func (c *decompCache) get(addr uint64) (string, bool) {
	el, ok := c.entries[addr]
	if !ok {
		return "", false
	}
	c.order.MoveToFront(el)
	return el.Value.(*decompEntry).code, true
}

func (c *decompCache) set(addr uint64, code string) {
	if el, ok := c.entries[addr]; ok {
		el.Value.(*decompEntry).code = code
		c.order.MoveToFront(el)
		return
	}
	if c.order.Len() >= c.cap {
		oldest := c.order.Back()
		if oldest != nil {
			delete(c.entries, oldest.Value.(*decompEntry).addr)
			c.order.Remove(oldest)
		}
	}
	c.entries[addr] = c.order.PushFront(&decompEntry{addr: addr, code: code})
}

func (c *decompCache) delete(addr uint64) {
	if el, ok := c.entries[addr]; ok {
		c.order.Remove(el)
		delete(c.entries, addr)
	}
}

func (c *decompCache) has(addr uint64) bool {
	_, ok := c.entries[addr]
	return ok
}

// deleteWhere removes every entry whose code satisfies predicate, returning
// the number deleted. Order traversal is back-to-front so the iteration is
// over the same snapshot even as we mutate.
func (c *decompCache) deleteWhere(predicate func(code string) bool) int {
	count := 0
	for el := c.order.Front(); el != nil; {
		next := el.Next()
		entry := el.Value.(*decompEntry)
		if predicate(entry.code) {
			c.order.Remove(el)
			delete(c.entries, entry.addr)
			count++
		}
		el = next
	}
	return count
}

type xrefsEntry struct {
	to   [][]any
	from [][]any
}

type analysisNote struct {
	Timestamp int64  `json:"t"`
	Note      string `json:"note,omitempty"`
}

type sessionCache struct {
	mu        sync.RWMutex
	strings   []*pb.StringItem
	functions []*pb.Function
	imports   []*pb.Import
	exports   []*pb.Export
	segments  []*pb.Segment
	decomp    *decompCache
	xrefs     map[uint64]*xrefsEntry
	visited   map[uint64]*analysisNote
}

func (s *Server) fetchAllStrings(ctx context.Context, client *worker.WorkerClient, progress *progressReporter) ([]*pb.StringItem, error) {
	const chunkSize = defaultPageLimit
	chunkLimit := int32(chunkSize)
	var all []*pb.StringItem
	offset := 0
	var total float64
	for {
		req := &pb.GetStringsRequest{Offset: int32(offset), Limit: chunkLimit}
		resp, err := (*client.Analysis).GetStrings(ctx, connect.NewRequest(req))
		if err != nil {
			if progress != nil {
				progress.Emit("get_strings", fmt.Sprintf("Failed to enumerate strings: %v", err), float64(len(all)), total)
			}
			return nil, err
		}
		if resp.Msg.Error != "" {
			if progress != nil {
				progress.Emit("get_strings", fmt.Sprintf("IDA error enumerating strings: %s", resp.Msg.Error), float64(len(all)), total)
			}
			return nil, errors.New(resp.Msg.Error)
		}
		chunk := resp.Msg.GetStrings()
		all = append(all, chunk...)
		if total == 0 && resp.Msg.Total > 0 {
			total = float64(resp.Msg.Total)
		}
		if progress != nil {
			progress.Emit("get_strings", fmt.Sprintf("Enumerated %d strings", len(all)), float64(len(all)), total)
		}
		if len(chunk) < chunkSize {
			break
		}
		offset += len(chunk)
	}
	if progress != nil {
		progress.Emit("get_strings", "String enumeration complete", float64(len(all)), total)
	}
	return all, nil
}

// fetchWithProgress is the shared scaffold for non-paginated worker enumerations
// (functions, imports, exports). It folds the start/error/done progress
// emissions around a typed RPC closure so each enumerator stays a one-liner.
// Paginated enumerations (fetchAllStrings) need their own scaffold because the
// progress cadence is per-page.
func fetchWithProgress[T any](progress *progressReporter, eventName, noun string, call func() ([]T, error)) ([]T, error) {
	if progress != nil {
		progress.Emit(eventName, fmt.Sprintf("Fetching %s from IDA", noun), 0, 0)
	}
	items, err := call()
	if err != nil {
		if progress != nil {
			progress.Emit(eventName, fmt.Sprintf("Failed to fetch %s: %v", noun, err), 0, 0)
		}
		return nil, err
	}
	if progress != nil {
		progress.Emit(eventName, fmt.Sprintf("Fetched %d %s", len(items), noun), float64(len(items)), float64(len(items)))
	}
	return items, nil
}

func (s *Server) fetchAllFunctions(ctx context.Context, client *worker.WorkerClient, progress *progressReporter) ([]*pb.Function, error) {
	return fetchWithProgress(progress, "get_functions", "functions", func() ([]*pb.Function, error) {
		resp, err := (*client.Analysis).GetFunctions(ctx, connect.NewRequest(&pb.GetFunctionsRequest{}))
		if err != nil {
			return nil, err
		}
		if resp.Msg.Error != "" {
			return nil, errors.New(resp.Msg.Error)
		}
		return resp.Msg.GetFunctions(), nil
	})
}

func (s *Server) fetchAllImports(ctx context.Context, client *worker.WorkerClient, progress *progressReporter) ([]*pb.Import, error) {
	return fetchWithProgress(progress, "get_imports", "imports", func() ([]*pb.Import, error) {
		resp, err := (*client.Analysis).GetImports(ctx, connect.NewRequest(&pb.GetImportsRequest{}))
		if err != nil {
			return nil, err
		}
		if resp.Msg.Error != "" {
			return nil, errors.New(resp.Msg.Error)
		}
		return resp.Msg.GetImports(), nil
	})
}

func (s *Server) fetchAllExports(ctx context.Context, client *worker.WorkerClient, progress *progressReporter) ([]*pb.Export, error) {
	return fetchWithProgress(progress, "get_exports", "exports", func() ([]*pb.Export, error) {
		resp, err := (*client.Analysis).GetExports(ctx, connect.NewRequest(&pb.GetExportsRequest{}))
		if err != nil {
			return nil, err
		}
		if resp.Msg.Error != "" {
			return nil, errors.New(resp.Msg.Error)
		}
		return resp.Msg.GetExports(), nil
	})
}

// loadCached is the double-checked-locking helper shared by every per-session
// list cache. slot points at the cache field (e.g. &c.strings). On a hit it
// returns the stored slice; on a miss it calls loader under the write lock and
// stores the result. Go has no generic methods, so this lives as a free
// function and the typed loadX methods below are thin shims.
func loadCached[T any](mu *sync.RWMutex, slot *[]T, sessionID, name string, logger *log.Logger, loader func() ([]T, error)) ([]T, bool, error) {
	mu.RLock()
	if *slot != nil {
		data := *slot
		mu.RUnlock()
		logger.Printf("[Cache] %s HIT session=%s", name, sessionID)
		return data, true, nil
	}
	mu.RUnlock()

	mu.Lock()
	defer mu.Unlock()
	if *slot == nil {
		logger.Printf("[Cache] %s MISS session=%s", name, sessionID)
		data, err := loader()
		if err != nil {
			return nil, false, err
		}
		*slot = data
	}
	return *slot, false, nil
}

func (c *sessionCache) loadStrings(sessionID string, logger *log.Logger, loader func() ([]*pb.StringItem, error)) ([]*pb.StringItem, bool, error) {
	return loadCached(&c.mu, &c.strings, sessionID, "strings", logger, loader)
}

func (c *sessionCache) loadFunctions(sessionID string, logger *log.Logger, loader func() ([]*pb.Function, error)) ([]*pb.Function, bool, error) {
	return loadCached(&c.mu, &c.functions, sessionID, "functions", logger, loader)
}

func (c *sessionCache) loadImports(sessionID string, logger *log.Logger, loader func() ([]*pb.Import, error)) ([]*pb.Import, bool, error) {
	return loadCached(&c.mu, &c.imports, sessionID, "imports", logger, loader)
}

func (c *sessionCache) loadExports(sessionID string, logger *log.Logger, loader func() ([]*pb.Export, error)) ([]*pb.Export, bool, error) {
	return loadCached(&c.mu, &c.exports, sessionID, "exports", logger, loader)
}

func (s *Server) getSessionCache(sessionID string) *sessionCache {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if s.cache == nil {
		s.cache = make(map[string]*sessionCache)
	}
	cache := s.cache[sessionID]
	if cache == nil {
		cache = &sessionCache{}
		s.cache[sessionID] = cache
	}
	return cache
}

func (s *Server) deleteSessionCache(sessionID string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if s.cache != nil {
		if _, ok := s.cache[sessionID]; ok {
			s.logger.Printf("[Cache] clear session=%s", sessionID)
		}
		delete(s.cache, sessionID)
	}
}

func (c *sessionCache) invalidateFunctions() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.functions = nil
}

// ── Decompilation cache ──

// getDecomp takes a write lock because the LRU updates ordering on every hit.
// The workload (analyze_function on a small set of hot functions during an
// agent session) doesn't see meaningful parallel reads of the same cache, so
// the upgrade from RLock costs nothing in practice.
func (c *sessionCache) getDecomp(addr uint64) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.decomp == nil {
		return "", false
	}
	return c.decomp.get(addr)
}

func (c *sessionCache) setDecomp(addr uint64, code string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.decomp == nil {
		c.decomp = newDecompCache(maxDecompCacheEntries)
	}
	c.decomp.set(addr, code)
}

func (c *sessionCache) invalidateDecomp(addr uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.decomp != nil {
		c.decomp.delete(addr)
	}
}

// invalidateDecompByOldName removes all cached decomp entries whose text
// contains oldName, which typically appears as the old symbol name in
// pseudocode output. Returns the number of invalidated entries.
func (c *sessionCache) invalidateDecompByOldName(oldName string) int {
	if oldName == "" {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.decomp == nil {
		return 0
	}
	return c.decomp.deleteWhere(func(code string) bool {
		return strings.Contains(code, oldName)
	})
}

// isCachedFunction returns true when addr is among the cached function list.
func (c *sessionCache) isCachedFunction(addr uint64) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, f := range c.functions {
		if f.GetAddress() == addr {
			return true
		}
	}
	return false
}

func (c *sessionCache) invalidateAllDecomp() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decomp = nil
}

// ── Xrefs cache ──

func (c *sessionCache) getXRefs(addr uint64) (*xrefsEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.xrefs == nil {
		return nil, false
	}
	e, ok := c.xrefs[addr]
	return e, ok
}

func (c *sessionCache) setXRefs(addr uint64, entry *xrefsEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.xrefs == nil {
		c.xrefs = make(map[uint64]*xrefsEntry)
	}
	c.xrefs[addr] = entry
}

func (c *sessionCache) invalidateAllXRefs() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.xrefs = nil
}

// ── Segments cache ──

func (c *sessionCache) loadSegments(sessionID string, logger *log.Logger, loader func() ([]*pb.Segment, error)) ([]*pb.Segment, bool, error) {
	return loadCached(&c.mu, &c.segments, sessionID, "segments", logger, loader)
}

// ── Analysis context ──

func (c *sessionCache) markVisited(addr uint64, ts int64, note string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.visited == nil {
		c.visited = make(map[uint64]*analysisNote)
	}
	existing, ok := c.visited[addr]
	if ok && note == "" {
		existing.Timestamp = ts
		return
	}
	c.visited[addr] = &analysisNote{Timestamp: ts, Note: note}
}

func (c *sessionCache) setNote(addr uint64, ts int64, note string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.visited == nil {
		c.visited = make(map[uint64]*analysisNote)
	}
	c.visited[addr] = &analysisNote{Timestamp: ts, Note: note}
}

func (c *sessionCache) getVisited() map[uint64]*analysisNote {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.visited == nil {
		return nil
	}
	cp := make(map[uint64]*analysisNote, len(c.visited))
	for k, v := range c.visited {
		cp[k] = &analysisNote{Timestamp: v.Timestamp, Note: v.Note}
	}
	return cp
}

func (c *sessionCache) pruneNotedFunctions() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for addr, note := range c.visited {
		if note.Note == "" {
			continue
		}
		if c.decomp != nil && c.decomp.has(addr) {
			c.decomp.delete(addr)
			count++
		}
		if c.xrefs != nil {
			if _, ok := c.xrefs[addr]; ok {
				delete(c.xrefs, addr)
				count++
			}
		}
	}
	return count
}

func (s *Server) warmSessionCache(sessionID string, progress *progressReporter) {
	client, err := s.workers.GetClient(sessionID)
	if err != nil {
		return
	}
	cache := s.getSessionCache(sessionID)
	// Generous budget: warming enumerates all functions/imports/exports/strings,
	// which is slow on large binaries. This runs in the background and failures
	// are non-fatal (survey_binary just fetches on demand instead).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	const totalSteps = 4
	s.emitProgress(progress, sessionID, "warming", "Warming caches (functions, imports, exports, strings)", 3, 4)

	var mu sync.Mutex
	completed := 0
	emitWarmProgress := func(name string) {
		if progress == nil {
			return
		}
		mu.Lock()
		completed++
		c := completed
		mu.Unlock()
		progress.Emit("warming", fmt.Sprintf("Cache warming: %s (%d/%d)", name, c, totalSteps), 3+float64(c)/float64(totalSteps), 4)
	}

	// runLabeled handles the goroutine fan-in. Each task's return value is
	// unused — warming is best-effort and the typed loadX helpers already cache
	// on success — so we discard results and just record completion.
	warm := func(name string, load func() error) func() (any, error) {
		return func() (any, error) {
			_ = load()
			emitWarmProgress(name)
			s.debugf("[Cache] warm %s done session=%s", name, sessionID)
			return nil, nil
		}
	}
	runLabeled(map[string]func() (any, error){
		"functions": warm("functions", func() error {
			_, _, err := cache.loadFunctions(sessionID, s.logger, func() ([]*pb.Function, error) {
				return s.fetchAllFunctions(ctx, client, nil)
			})
			return err
		}),
		"imports": warm("imports", func() error {
			_, _, err := cache.loadImports(sessionID, s.logger, func() ([]*pb.Import, error) {
				return s.fetchAllImports(ctx, client, nil)
			})
			return err
		}),
		"exports": warm("exports", func() error {
			_, _, err := cache.loadExports(sessionID, s.logger, func() ([]*pb.Export, error) {
				return s.fetchAllExports(ctx, client, nil)
			})
			return err
		}),
		"strings": warm("strings", func() error {
			_, _, err := cache.loadStrings(sessionID, s.logger, func() ([]*pb.StringItem, error) {
				return s.fetchAllStrings(ctx, client, nil)
			})
			return err
		}),
	})

	s.logger.Printf("[Cache] warm complete session=%s", sessionID)
	// The caller (backgroundOpen) emits the terminal "ready" after this returns,
	// so readiness transitions monotonically (… → warming → ready) and never
	// regresses from ready back to warming.
}
