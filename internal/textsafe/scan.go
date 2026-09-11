package textsafe

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	reErrorWord = regexp.MustCompile(`(?i)\b(error|fatal|crit|critical|emerg|emergency|alert)\b`)
	rePanicWord = regexp.MustCompile(`(?i)\bpanic(?:ked|king)?\b`)
	reOOM       = regexp.MustCompile(`(?i)out of memory|oom-killer|cannot allocate memory|java\.lang\.outofmemoryerror|killed process \d+`)
	reHTTP5xx   = regexp.MustCompile(`(?i)(?:HTTP/\d(?:\.\d)?[" ]\s*5\d\d\b|status[=: ]5\d\d\b|" 5\d\d \d)`)
	rePyStart   = regexp.MustCompile(`^Traceback \(most recent call last\):`)
	rePyFrame   = regexp.MustCompile(`^  File `)
	rePyCont    = regexp.MustCompile(`^    `)
	rePyExc     = regexp.MustCompile(`^[A-Za-z_][\w.]*((Error|Exception|Exit|Interrupt|Failure)|Panic)\b`)
	reJavaExc   = regexp.MustCompile(`^(?:Caused by:\s+)?(?:[A-Za-z_][\w.$]*\.)*[A-Za-z_][\w$]*(Exception|Error|Throwable|Failure)(?::|$)`)
	reJavaFrame = regexp.MustCompile(`^\tat `)
	reGoPanic   = regexp.MustCompile(`^panic: |^fatal error: |^runtime error:`)
	reGoGoro    = regexp.MustCompile(`^goroutine \d+ \[`)
	reGoFrame   = regexp.MustCompile(`^\t`)
	reGoFunc    = regexp.MustCompile(`^(?:created by )?[\w./+\-*\[\]]+\(.*`)
	reNodeErr   = regexp.MustCompile(`^(?:[A-Za-z]*Error|AssertionError|TypeError|ReferenceError|RangeError|SyntaxError|URIError): `)
	reNodeFrame = regexp.MustCompile(`^\s+at `)
	reRustPanic = regexp.MustCompile(`^thread '.+' panicked at`)
	reRustFrame = regexp.MustCompile(`^(?:stack backtrace:|\s+\d+:)`)
)

type lineRec struct {
	n    int
	text string
}

type openBlock struct {
	kind  string
	start int
	lines []string
}

// Scan reads r once and returns bounded, classified hits.
func Scan(r io.Reader, req Request) (Result, error) {
	if err := req.Normalize(); err != nil {
		return Result{}, err
	}
	var pattern *regexp.Regexp
	if req.Pattern != "" {
		compiled, err := regexp.Compile(req.Pattern)
		if err != nil {
			return Result{}, fmt.Errorf("invalid --pattern: %w", err)
		}
		pattern = compiled
	}

	limited := &limitReader{r: r, limit: req.MaxScanBytes}
	scanner := bufio.NewScanner(limited)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, MaxLineBytes)

	var (
		lines     []lineRec
		n         int
		skipped   bool
		probe     []byte
		truncated string
	)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(probe) < 4096 {
			need := 4096 - len(probe)
			if len(raw) < need {
				need = len(raw)
			}
			probe = append(probe, raw[:need]...)
			if containsNUL(probe) {
				return Result{}, fmt.Errorf("refusing binary input")
			}
		} else if containsNUL(raw) {
			return Result{}, fmt.Errorf("refusing binary input")
		}
		if req.SkipPartialFirst && !skipped {
			skipped = true
			continue
		}
		n++
		text := string(raw)
		if !utf8.ValidString(text) {
			text = strings.ToValidUTF8(text, "\uFFFD")
		}
		if req.Offset > 0 && n < req.Offset {
			continue
		}
		if req.Offset > 0 && req.Limit > 0 && n >= req.Offset+req.Limit {
			break
		}
		lines = append(lines, lineRec{n: n, text: text})
		if req.Tail > 0 && len(lines) > req.Tail {
			copy(lines, lines[len(lines)-req.Tail:])
			lines = lines[:req.Tail]
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return Result{}, fmt.Errorf("scan input: %w", scanErr)
	}
	if limited.hit {
		truncated = "max_scan_bytes"
	}

	origin := LineOriginWindow
	if req.Kind == SourceFile && (req.Scan == ScanStart || req.WindowStartByte == 0) {
		origin = LineOriginFile
	}

	out := Result{
		Source: SourceInfo{
			Kind:            req.Kind,
			Path:            req.Path,
			JournalUnit:     req.JournalUnit,
			Since:           req.Since,
			Until:           req.Until,
			Scan:            req.Scan,
			BytesScanned:    limited.n,
			WindowStartByte: req.WindowStartByte,
			FileSize:        req.FileSize,
		},
		Filter: FilterInfo{
			Presets: append([]string(nil), req.Presets...),
			Pattern: req.Pattern,
			Context: req.Context,
		},
		Stats: Stats{
			LinesScanned:    n,
			BytesScanned:    limited.n,
			TotalHitsExact:  truncated == "",
			WindowStartByte: req.WindowStartByte,
			FileSize:        req.FileSize,
		},
		Hits:       []Hit{},
		Redacted:   req.Redact,
		LineOrigin: origin,
	}
	if truncated != "" {
		out.Truncated = true
		out.TruncatedReason = truncated
	}

	if req.AroundLine > 0 {
		return sliceWindow(out, req, lines, req.AroundLine-req.Context, req.AroundLine+req.Context)
	}
	if !req.wantsAnyFilter() && (req.Offset > 0 || req.Limit > 0 || req.Tail > 0) {
		if len(lines) == 0 {
			return out, nil
		}
		return sliceWindow(out, req, lines, lines[0].n, lines[len(lines)-1].n)
	}
	return extractHits(out, req, pattern, lines)
}

func sliceWindow(out Result, req Request, lines []lineRec, lo, hi int) (Result, error) {
	if lo < 1 {
		lo = 1
	}
	var body []string
	start, end := 0, 0
	for _, ln := range lines {
		if ln.n < lo || ln.n > hi {
			continue
		}
		if start == 0 {
			start = ln.n
		}
		end = ln.n
		body = append(body, ln.text)
	}
	if start == 0 {
		out.Stats.TotalHitsExact = true
		return out, nil
	}
	text := strings.Join(body, "\n")
	if req.Redact {
		text = Redact(text)
	}
	hit := Hit{Kind: KindSlice, StartLine: start, EndLine: end, Text: text}
	if len(text) > req.MaxBytes {
		hit.Text = clipBytes(text, req.MaxBytes)
		out.Truncated = true
		out.TruncatedReason = joinReason(out.TruncatedReason, "max_bytes")
	}
	out.Hits = []Hit{hit}
	out.Stats.TotalHits = 1
	out.Stats.Returned = 1
	return out, nil
}

func extractHits(out Result, req Request, pattern *regexp.Regexp, lines []lineRec) (Result, error) {
	var (
		block    *openBlock
		covered  = map[int]struct{}{}
		returned int
		hits     []Hit
		total    int
		blocks   int
		reason   = out.TruncatedReason
		stop     bool
	)

	appendHit := func(hit Hit) {
		total++
		if hit.Kind == KindExceptionBlock {
			blocks++
		}
		if stop || len(hits) >= req.MaxHits || returned >= req.MaxBytes {
			stop = true
			if len(hits) >= req.MaxHits {
				reason = joinReason(reason, "max_hits")
			} else if returned >= req.MaxBytes {
				reason = joinReason(reason, "max_bytes")
			}
			return
		}
		text := hit.Text
		if req.Redact {
			text = Redact(text)
		}
		if returned+len(text) > req.MaxBytes {
			text = clipBytes(text, req.MaxBytes-returned)
			reason = joinReason(reason, "max_bytes")
			stop = true
		}
		hit.Text = text
		hits = append(hits, hit)
		returned += len(text)
		if len(hits) >= req.MaxHits {
			reason = joinReason(reason, "max_hits")
			stop = true
		}
	}

	flushBlock := func() {
		if block == nil {
			return
		}
		end := block.start + len(block.lines) - 1
		for i := 0; i < len(block.lines); i++ {
			covered[block.start+i] = struct{}{}
		}
		if req.wantsPreset("exception") {
			prefix := contextBefore(lines, block.start, req.Context)
			text := strings.Join(append(prefix, block.lines...), "\n")
			start := block.start
			if req.Context > 0 && len(prefix) > 0 {
				start = block.start - len(prefix)
				if start < 1 {
					start = 1
				}
			}
			appendHit(Hit{
				Kind:      KindExceptionBlock,
				Level:     "error",
				StartLine: start,
				EndLine:   end,
				Text:      text,
			})
		}
		block = nil
	}

	extend := func(line string) {
		if block == nil {
			return
		}
		if len(block.lines) >= MaxBlockLines {
			flushBlock()
			return
		}
		block.lines = append(block.lines, line)
	}

	startBlock := func(ln lineRec) {
		flushBlock()
		block = &openBlock{kind: exceptionKind(ln.text), start: ln.n, lines: []string{ln.text}}
	}

	emitLine := func(kind, level string, idx int, ln lineRec) {
		if _, skip := covered[ln.n]; skip {
			return
		}
		lo := idx - req.Context
		if lo < 0 {
			lo = 0
		}
		hi := idx + req.Context
		if hi >= len(lines) {
			hi = len(lines) - 1
		}
		body := make([]string, 0, hi-lo+1)
		for i := lo; i <= hi; i++ {
			body = append(body, lines[i].text)
			covered[lines[i].n] = struct{}{}
		}
		appendHit(Hit{
			Kind:      kind,
			Level:     level,
			StartLine: lines[lo].n,
			EndLine:   lines[hi].n,
			Text:      strings.Join(body, "\n"),
		})
	}

	for idx, ln := range lines {
		if block != nil && continuesException(block.kind, ln.text) {
			extend(ln.text)
			continue
		}
		if isExceptionStart(ln.text) {
			startBlock(ln)
			continue
		}
		if block != nil {
			flushBlock()
		}
		kind, level := "", ""
		switch {
		case req.wantsPreset("oom") && reOOM.MatchString(ln.text):
			kind, level = KindOOMLine, "error"
		case req.wantsPreset("panic") && rePanicWord.MatchString(ln.text):
			kind, level = KindPanicLine, "error"
		case req.wantsPreset("http5xx") && reHTTP5xx.MatchString(ln.text):
			kind, level = KindHTTP5xx, "error"
		case req.wantsPreset("error") && reErrorWord.MatchString(ln.text):
			kind, level = KindErrorLine, "error"
		case pattern != nil && pattern.MatchString(ln.text):
			kind, level = KindPattern, "info"
		}
		if kind != "" {
			emitLine(kind, level, idx, ln)
		}
	}
	flushBlock()

	out.Hits = hits
	out.Stats.TotalHits = total
	out.Stats.Returned = len(hits)
	out.Stats.ExceptionBlocks = blocks
	if reason != "" {
		out.Truncated = true
		out.TruncatedReason = reason
		out.Stats.TotalHitsExact = false
	}
	return out, nil
}

func contextBefore(lines []lineRec, start, ctx int) []string {
	if ctx <= 0 {
		return nil
	}
	idx := -1
	for i, ln := range lines {
		if ln.n == start {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return nil
	}
	lo := idx - ctx
	if lo < 0 {
		lo = 0
	}
	out := make([]string, 0, idx-lo)
	for i := lo; i < idx; i++ {
		out = append(out, lines[i].text)
	}
	return out
}

func exceptionKind(line string) string {
	switch {
	case rePyStart.MatchString(line):
		return "python"
	case reGoPanic.MatchString(line):
		return "go"
	case reRustPanic.MatchString(line):
		return "rust"
	case reNodeErr.MatchString(line):
		return "node"
	default:
		return "jvm"
	}
}

func isExceptionStart(line string) bool {
	return rePyStart.MatchString(line) ||
		reGoPanic.MatchString(line) ||
		reRustPanic.MatchString(line) ||
		reNodeErr.MatchString(line) ||
		reJavaExc.MatchString(line) ||
		rePyExc.MatchString(line)
}

func continuesException(kind, line string) bool {
	if strings.TrimSpace(line) == "" {
		return true
	}
	if isFrameLine(line) || rePyExc.MatchString(line) || reJavaExc.MatchString(line) || reNodeErr.MatchString(line) {
		return true
	}
	if kind == "go" || kind == "rust" {
		return !looksLikeLogLine(line)
	}
	return false
}

func isFrameLine(line string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "at ") || strings.HasPrefix(line, "Caused by:") {
		return true
	}
	return rePyFrame.MatchString(line) ||
		rePyCont.MatchString(line) ||
		reJavaFrame.MatchString(line) ||
		reNodeFrame.MatchString(line) ||
		reGoGoro.MatchString(line) ||
		reGoFrame.MatchString(line) ||
		reGoFunc.MatchString(line) ||
		reRustFrame.MatchString(line)
}

func looksLikeLogLine(line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	switch strings.ToUpper(fields[0]) {
	case "INFO", "WARN", "WARNING", "ERROR", "DEBUG", "NOTICE", "TRACE":
		return true
	}
	if len(fields[0]) >= 4 && fields[0][0] >= '0' && fields[0][0] <= '9' && strings.Contains(fields[0], "-") {
		return true
	}
	return false
}

type limitReader struct {
	r     io.Reader
	n     int64
	limit int64
	hit   bool
	extra bool
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.n >= l.limit {
		if !l.extra {
			l.extra = true
			var one [1]byte
			n, err := l.r.Read(one[:])
			if n > 0 {
				l.hit = true
			}
			if err != nil && err != io.EOF {
				return 0, err
			}
		}
		return 0, io.EOF
	}
	if int64(len(p)) > l.limit-l.n {
		p = p[:l.limit-l.n]
	}
	n, err := l.r.Read(p)
	l.n += int64(n)
	return n, err
}

func containsNUL(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

func clipBytes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	if n <= 0 {
		return ""
	}
	return s[:n] + "…"
}

func joinReason(existing, next string) string {
	if existing == "" {
		return next
	}
	if strings.Contains(existing, next) {
		return existing
	}
	return existing + "," + next
}
