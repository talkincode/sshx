package textsafe

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const pythonTrace = `INFO starting
Traceback (most recent call last):
  File "app.py", line 10, in <module>
    main()
  File "app.py", line 4, in main
    raise ValueError("bad token=secret-value")
ValueError: bad token=secret-value
INFO recovered
`

const javaTrace = `2026-01-01 INFO boot
java.lang.IllegalStateException: exploded
	at com.example.App.run(App.java:12)
	at com.example.App.main(App.java:5)
Caused by: java.io.IOException: disk
	at com.example.Disk.read(Disk.java:9)
2026-01-01 INFO still running
`

const goPanic = `2026-01-01T00:00:00Z info ok
panic: runtime error: index out of range

goroutine 1 [running]:
main.crash()
	/app/main.go:8 +0x20
main.main()
	/app/main.go:4 +0x18
`

const nodeErr = `listening on 3000
TypeError: Cannot read property 'x' of undefined
    at Server.<anonymous> (/app/server.js:14:11)
    at process.processTicksAndRejections (node:internal/process/task_queues:95:5)
done
`

const rustPanic = `ready
thread 'main' panicked at src/main.rs:4:5:
nope
stack backtrace:
   0: rust_begin_unwind
   1: core::panicking::panic_fmt
later
`

func scanString(t *testing.T, body string, req Request) Result {
	t.Helper()
	req.Kind = SourceFile
	req.Path = "/var/log/app.log"
	req.Scan = ScanStart
	out, err := Scan(strings.NewReader(body), req)
	require.NoError(t, err)
	return out
}

func TestScanPythonExceptionBlock(t *testing.T) {
	out := scanString(t, pythonTrace, Request{Presets: []string{"exception"}, Redact: true})
	require.Equal(t, 1, out.Stats.ExceptionBlocks)
	require.Len(t, out.Hits, 1)
	require.Equal(t, KindExceptionBlock, out.Hits[0].Kind)
	require.Equal(t, 2, out.Hits[0].StartLine)
	require.Equal(t, 7, out.Hits[0].EndLine)
	require.Contains(t, out.Hits[0].Text, "Traceback")
	require.Contains(t, out.Hits[0].Text, "ValueError")
	require.NotContains(t, out.Hits[0].Text, "secret-value")
	require.Contains(t, out.Hits[0].Text, "token=***")
}

func TestScanJavaExceptionBlock(t *testing.T) {
	out := scanString(t, javaTrace, Request{Presets: []string{"exception"}})
	require.Equal(t, 1, out.Stats.ExceptionBlocks)
	require.Equal(t, KindExceptionBlock, out.Hits[0].Kind)
	require.Contains(t, out.Hits[0].Text, "Caused by:")
	require.Equal(t, 2, out.Hits[0].StartLine)
	require.Equal(t, 6, out.Hits[0].EndLine)
}

func TestScanGoPanicBlock(t *testing.T) {
	out := scanString(t, goPanic, Request{Presets: []string{"exception"}})
	require.Equal(t, 1, out.Stats.ExceptionBlocks)
	require.Contains(t, out.Hits[0].Text, "goroutine 1")
	require.Contains(t, out.Hits[0].Text, "main.go:8")
}

func TestScanNodeAndRustBlocks(t *testing.T) {
	node := scanString(t, nodeErr, Request{Presets: []string{"exception"}})
	require.Equal(t, 1, node.Stats.ExceptionBlocks)
	require.Contains(t, node.Hits[0].Text, "TypeError")
	rust := scanString(t, rustPanic, Request{Presets: []string{"exception"}})
	require.Equal(t, 1, rust.Stats.ExceptionBlocks)
	require.Contains(t, rust.Hits[0].Text, "panicked at")
}

func TestScanErrorLinesSkipExceptionInterior(t *testing.T) {
	body := "WARN ok\nERROR boom\nTraceback (most recent call last):\n  File \"a.py\", line 1, in x\nValueError: x\nERROR after\n"
	out := scanString(t, body, Request{Presets: []string{"exception", "error"}})
	require.Equal(t, 1, out.Stats.ExceptionBlocks)
	var kinds []string
	for _, h := range out.Hits {
		kinds = append(kinds, h.Kind)
	}
	require.Equal(t, []string{KindErrorLine, KindExceptionBlock, KindErrorLine}, kinds)
}

func TestScanAroundLineAndContext(t *testing.T) {
	body := "l1\nl2\nERROR here\nl4\nl5\n"
	out := scanString(t, body, Request{Presets: []string{"error"}, Context: 1})
	require.Len(t, out.Hits, 1)
	require.Equal(t, 2, out.Hits[0].StartLine)
	require.Equal(t, 4, out.Hits[0].EndLine)
	require.Equal(t, "l2\nERROR here\nl4", out.Hits[0].Text)

	sliced := scanString(t, body, Request{AroundLine: 3, Context: 1})
	require.Len(t, sliced.Hits, 1)
	require.Equal(t, KindSlice, sliced.Hits[0].Kind)
	require.Equal(t, "l2\nERROR here\nl4", sliced.Hits[0].Text)
}

func TestScanMaxHitsTruncation(t *testing.T) {
	body := "ERROR a\nERROR b\nERROR c\nERROR d\n"
	out := scanString(t, body, Request{Presets: []string{"error"}, MaxHits: 2})
	require.True(t, out.Truncated)
	require.Equal(t, "max_hits", out.TruncatedReason)
	require.Equal(t, 2, out.Stats.Returned)
	require.Greater(t, out.Stats.TotalHits, out.Stats.Returned)
}

func TestScanPatternAndHTTP5xx(t *testing.T) {
	body := `ok
GET /x HTTP/1.1" 500 12
timeout after 3s
`
	out := scanString(t, body, Request{Presets: []string{"http5xx"}, Pattern: `timeout after`})
	require.Equal(t, 2, out.Stats.Returned)
	require.Equal(t, KindHTTP5xx, out.Hits[0].Kind)
	require.Equal(t, KindPattern, out.Hits[1].Kind)
}

func TestScanRejectsBinaryAndBadPattern(t *testing.T) {
	_, err := Scan(strings.NewReader("ok\x00nope"), Request{Kind: SourceFile, Path: "/var/log/a", Scan: ScanStart})
	require.Error(t, err)
	_, err = Scan(strings.NewReader("a"), Request{Kind: SourceFile, Path: "/var/log/a", Pattern: "("})
	require.Error(t, err)
}

func TestScanRE2DoesNotHang(t *testing.T) {
	body := strings.Repeat("aaaaaaaaaaaaaaaa", 200) + "\n"
	done := make(chan struct{})
	go func() {
		_, err := Scan(strings.NewReader(body), Request{
			Kind: SourceFile, Path: "/var/log/a", Scan: ScanStart, Pattern: `(a+)+$`,
		})
		require.NoError(t, err)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RE2 pattern hung")
	}
}

func TestNormalizeDefaultsAndConflicts(t *testing.T) {
	req := Request{Kind: SourceFile, Path: "/var/log/a.log"}
	require.NoError(t, req.Normalize())
	require.Equal(t, ScanEnd, req.Scan)
	require.Equal(t, []string{"exception", "error", "panic", "oom"}, req.Presets)

	bad := Request{Kind: SourceFile, Path: "/var/log/a.log", JournalUnit: "nginx.service"}
	require.Error(t, bad.Normalize())
	conflict := Request{Kind: SourceFile, Path: "/var/log/a.log", AroundLine: 3, Tail: 2}
	require.Error(t, conflict.Normalize())
}

func TestValidateTextPathAndJournal(t *testing.T) {
	require.NoError(t, ValidateTextPath("/var/log/app.log"))
	require.Error(t, ValidateTextPath("var/log/app.log"))
	require.Error(t, ValidateTextPath("/var/log/../etc/passwd"))
	require.Error(t, ValidateTextPath("/"))
	require.NoError(t, ValidateJournalUnit("nginx.service"))
	require.Error(t, ValidateJournalUnit("nginx;rm"))
	require.Error(t, ValidateTimeBound("1h;reboot"))
	cmd := JournalCommand(Request{JournalUnit: "nginx.service", JournalLines: 10, Since: "1 hour ago"}, true)
	require.True(t, strings.HasPrefix(cmd, "sudo -S -p '' journalctl"))
	require.Contains(t, cmd, "--unit='nginx.service'")
	require.NotContains(t, cmd, ";")
}
