package server

import (
	"fmt"
	"strings"

	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
)

func textResult(text string) string {
	return strings.TrimRight(text, "\n")
}

// formatListHeader renders the first line of paginated list output. When the
// page is capped (more items exist beyond it) it says so explicitly and gives
// the next offset, so the agent never mistakes a truncated page for the full
// set. Complete pages keep the original "Total: N (offset O)" form.
func formatListHeader(total, offset, shown int) string {
	if next := offset + shown; next < total {
		return fmt.Sprintf("Total: %d  (showing %d from offset %d; %d more, use offset=%d)", total, shown, offset, total-next, next)
	}
	return fmt.Sprintf("Total: %d (offset %d)", total, offset)
}

func formatFunctionsText(items []*pb.Function, total, offset int) string {
	var b strings.Builder
	b.WriteString(formatListHeader(total, offset, len(items)) + "\n")
	for _, fn := range items {
		fmt.Fprintf(&b, "0x%x\t%s\n", fn.Address, fn.Name)
	}
	return textResult(b.String())
}

func formatImportsText(items []*pb.Import, total, offset int) string {
	var b strings.Builder
	b.WriteString(formatListHeader(total, offset, len(items)) + "\n")
	for _, imp := range items {
		if imp.Ordinal != 0 {
			fmt.Fprintf(&b, "%s!%s\t0x%x\t[ord %d]\n", imp.Module, imp.Name, imp.Address, imp.Ordinal)
		} else {
			fmt.Fprintf(&b, "%s!%s\t0x%x\n", imp.Module, imp.Name, imp.Address)
		}
	}
	return textResult(b.String())
}

func formatExportsText(items []*pb.Export, total, offset int) string {
	var b strings.Builder
	b.WriteString(formatListHeader(total, offset, len(items)) + "\n")
	for _, exp := range items {
		if exp.Ordinal != 0 {
			fmt.Fprintf(&b, "%s\t0x%x\t[ord %d]\n", exp.Name, exp.Address, exp.Ordinal)
		} else {
			fmt.Fprintf(&b, "%s\t0x%x\n", exp.Name, exp.Address)
		}
	}
	return textResult(b.String())
}

func formatStringsText(items []*pb.StringItem, total, offset int) string {
	var b strings.Builder
	b.WriteString(formatListHeader(total, offset, len(items)) + "\n")
	for _, s := range items {
		val := s.Value
		if len(val) > 80 {
			val = val[:80] + "..."
		}
		fmt.Fprintf(&b, "0x%x\t%q\n", s.Address, val)
	}
	return textResult(b.String())
}

func formatXRefsText(address uint64, xrefsTo, xrefsFrom [][]any) string {
	var b strings.Builder
	if len(xrefsTo) > 0 {
		fmt.Fprintf(&b, "xrefs_to 0x%x (%d):\n", address, len(xrefsTo))
		for _, x := range xrefsTo {
			fmt.Fprintf(&b, "  0x%x %v\n", anyToUint64(x[0]), x[1])
		}
	}
	if len(xrefsFrom) > 0 {
		fmt.Fprintf(&b, "xrefs_from 0x%x (%d):\n", address, len(xrefsFrom))
		for _, x := range xrefsFrom {
			fmt.Fprintf(&b, "  0x%x %v\n", anyToUint64(x[0]), x[1])
		}
	}
	if b.Len() == 0 {
		return "no xrefs"
	}
	return textResult(b.String())
}

func anyToUint64(v any) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		return uint64(n)
	case float64:
		return uint64(n)
	case uint32:
		return uint64(n)
	case int:
		return uint64(n)
	default:
		return 0
	}
}

func formatSegmentsText(segs []*pb.Segment) string {
	var b strings.Builder
	for _, seg := range segs {
		fmt.Fprintf(&b, "%-12s 0x%x..0x%x  %s  %s  %dbit\n",
			seg.GetName(), seg.GetStart(), seg.GetEnd(),
			formatPermissions(seg.GetPermissions()), seg.GetSegClass(), seg.GetBitness())
	}
	return textResult(b.String())
}

func formatPermissions(perm uint32) string {
	var buf [3]byte
	if perm&4 != 0 {
		buf[0] = 'r'
	} else {
		buf[0] = '-'
	}
	if perm&2 != 0 {
		buf[1] = 'w'
	} else {
		buf[1] = '-'
	}
	if perm&1 != 0 {
		buf[2] = 'x'
	} else {
		buf[2] = '-'
	}
	return string(buf[:])
}

// crossMatch is the compact-text row shape shared by cross_reference and
// cross_search results.
type crossMatch struct {
	Category string // empty when not in cross_reference's mixed result
	Address  uint64
	Name     string
	Module   string
	Value    string // strings mode only
}

func formatCrossReference(symbol, srcSessID, tgtSessID string, srcAddr uint64, matches []crossMatch) string {
	if len(matches) == 0 {
		return fmt.Sprintf("0x%x %q in %s: no matches in %s", srcAddr, symbol, srcSessID, tgtSessID)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "0x%x %q in %s → %s (%d):\n", srcAddr, symbol, srcSessID, tgtSessID, len(matches))
	for _, m := range matches {
		switch {
		case m.Module != "":
			fmt.Fprintf(&b, "  %-8s 0x%x  %s!%s\n", m.Category, m.Address, m.Module, m.Name)
		default:
			fmt.Fprintf(&b, "  %-8s 0x%x  %s\n", m.Category, m.Address, m.Name)
		}
	}
	return textResult(b.String())
}

// crossSearchResult collects the per-session items the cross_search handler
// gathered. Items use the same row shape as crossMatch (Category is unused).
type crossSearchResult struct {
	SessionID  string
	BinaryPath string
	Items      []crossMatch
	Error      string
}

func formatCrossSearch(mode string, totalMatches int, results []crossSearchResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "mode=%s, %d matches across %d sessions\n", mode, totalMatches, len(results))
	for _, r := range results {
		b.WriteByte('\n')
		if r.Error != "" {
			fmt.Fprintf(&b, "%s (error): %s\n", r.SessionID, r.Error)
			continue
		}
		fmt.Fprintf(&b, "%s %s (%d):\n", r.SessionID, r.BinaryPath, len(r.Items))
		for _, item := range r.Items {
			switch mode {
			case "strings":
				val := item.Value
				if len(val) > 80 {
					val = val[:80] + "..."
				}
				fmt.Fprintf(&b, "  0x%x\t%q\n", item.Address, val)
			case "imports":
				if item.Module != "" {
					fmt.Fprintf(&b, "  0x%x\t%s!%s\n", item.Address, item.Module, item.Name)
				} else {
					fmt.Fprintf(&b, "  0x%x\t%s\n", item.Address, item.Name)
				}
			default:
				fmt.Fprintf(&b, "  0x%x\t%s\n", item.Address, item.Name)
			}
		}
	}
	return textResult(b.String())
}

func typeKindStr(resp *pb.GetTypeAtResponse) string {
	if !resp.GetHasType() {
		return "unknown"
	}
	switch {
	case resp.GetIsFunc():
		return "func"
	case resp.GetIsStruct():
		return "struct"
	case resp.GetIsUnion():
		return "union"
	case resp.GetIsEnum():
		return "enum"
	case resp.GetIsArray():
		return "array"
	case resp.GetIsPtr():
		return "ptr"
	default:
		return "scalar"
	}
}
