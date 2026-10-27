package sshclient

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// sudoExchange gates two different consumers of SSH stdin. A credential is sent
// only after sudo's nonce-bound prompt; application data only after the child
// acknowledges readiness. NOPASSWD/cache/root never receive a credential.
// No secret file, environment variable, extra remote fd or PTY is required.
type sudoExchange struct {
	prompt, ready, password string
	payload                 io.Reader
	events                  chan bool // false: prompt, true: child ready
	stop                    chan struct{}
	done                    chan struct{}
	mu                      sync.Mutex
	err                     error
	childReady              bool
	abort                   func()
}

func (c *SSHClient) executeSudo(command string, payload io.Reader, capture bool) (ExecResult, error) {
	password := c.config.SudoPassword
	if strings.ContainsAny(password, "\x00\r\n") {
		return ExecResult{ExitCode: -1}, boundaryError("auth", "prepare sudo", fmt.Errorf("sudo password must be a single line"))
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ExecResult{ExitCode: -1}, err
	}
	id := hex.EncodeToString(nonce[:])
	auth := &sudoExchange{prompt: "SSHX_SUDO_PROMPT_" + id, ready: "SSHX_SUDO_READY_" + id, password: password, payload: payload, events: make(chan bool, 2), stop: make(chan struct{}), done: make(chan struct{}), abort: func() { _ = c.Close() }} //nolint:errcheck // abort owns the transport
	wrapped, err := sudoReadyCommand(command, auth.prompt, auth.ready)
	if err != nil {
		return ExecResult{ExitCode: -1}, boundaryError("config", "prepare sudo", err)
	}
	return c.executeSession(wrapped, nil, capture, false, auth)
}

func (s *sudoExchange) failure(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	s.abort()
}
func (s *sudoExchange) result() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.childReady, s.err
}
func (s *sudoExchange) start(w io.WriteCloser) {
	go func() {
		defer close(s.done)
		defer func() { _ = w.Close() }() //nolint:errcheck // EOF is best-effort after send/abort
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		sent := false
		for {
			select {
			case <-s.stop:
				return
			case <-timer.C:
				s.failure(fmt.Errorf("sudo readiness handshake timed out"))
				return
			case ready := <-s.events:
				if !ready {
					if sent || s.password == "" {
						s.failure(fmt.Errorf("sudo authentication was rejected or no credential is available"))
						return
					}
					sent = true
					if _, err := io.WriteString(w, s.password+"\n"); err != nil {
						s.failure(fmt.Errorf("send sudo authentication: %w", err))
						return
					}
					continue
				}
				timer.Stop()
				s.mu.Lock()
				s.childReady = true
				s.mu.Unlock()
				if s.payload != nil {
					if _, err := io.Copy(w, s.payload); err != nil {
						s.failure(fmt.Errorf("send sudo payload: %w", err))
					}
				}
				return
			}
		}
	}()
}

// sudoControlWriter strips only session-owned framing, including markers split
// across SSH packets. After ready it is a transparent stderr writer.
type sudoControlWriter struct {
	dst             io.Writer
	auth            *sudoExchange
	pending         []byte
	prompted, ready bool
}

func (w *sudoControlWriter) Write(p []byte) (int, error) {
	n := len(p)
	if w.ready {
		return w.dst.Write(p)
	}
	w.pending = append(w.pending, p...)
	for len(w.pending) > 0 {
		a, b := bytes.Index(w.pending, []byte(w.auth.prompt)), bytes.Index(w.pending, []byte(w.auth.ready))
		pos, ready := a, false
		if b >= 0 && (a < 0 || b < a) {
			pos, ready = b, true
		}
		if pos >= 0 {
			if _, err := w.dst.Write(w.pending[:pos]); err != nil {
				return 0, err
			}
			marker := w.auth.prompt
			if ready {
				marker = w.auth.ready
			}
			w.pending = w.pending[pos+len(marker):]
			if !ready && w.prompted {
				w.auth.failure(fmt.Errorf("repeated sudo authentication prompt"))
				return 0, fmt.Errorf("sudo authentication rejected")
			}
			w.prompted = w.prompted || !ready
			if ready {
				w.auth.mu.Lock()
				w.auth.childReady = true
				w.auth.mu.Unlock()
			}
			w.auth.events <- ready
			if ready {
				w.ready = true
				_, err := w.dst.Write(w.pending)
				w.pending = nil
				return n, err
			}
			continue
		}
		keep := 0
		for _, marker := range []string{w.auth.prompt, w.auth.ready} {
			for k := 1; k < len(marker) && k <= len(w.pending); k++ {
				if bytes.Equal(w.pending[len(w.pending)-k:], []byte(marker[:k])) && k > keep {
					keep = k
				}
			}
		}
		if _, err := w.dst.Write(w.pending[:len(w.pending)-keep]); err != nil {
			return 0, err
		}
		w.pending = append([]byte(nil), w.pending[len(w.pending)-keep:]...)
		break
	}
	return n, nil
}
func (w *sudoControlWriter) flush() error {
	_, err := w.dst.Write(w.pending)
	w.pending = nil
	return err
}

// Preserve the original command's quoting, expansions, pipes and redirections:
// the wrapper executes argv, not a second parse of the user's command text.
// Only the leading sudo options are parsed. Ambiguous shell/login modes fail
// closed rather than accidentally changing the effective privilege boundary.
func sudoReadyCommand(command, prompt, ready string) (string, error) {
	rest, ok := leadingSudoRemainder(command)
	if !ok {
		return "", fmt.Errorf("expected leading sudo")
	}
	var options []string
	for strings.HasPrefix(strings.TrimSpace(rest), "-") {
		token, tail, err := sudoWord(rest)
		if err != nil {
			return "", err
		}
		rest = tail
		if token == "--" {
			break
		}
		switch token {
		case "-S", "--stdin":
			continue
		case "-p", "--prompt":
			_, rest, err = sudoWord(rest)
			if err != nil {
				return "", err
			}
			continue
		case "-u", "--user", "-g", "--group", "-h", "--host", "-D", "--chdir":
			value, next, e := sudoWord(rest)
			if e != nil {
				return "", e
			}
			options = append(options, token, value)
			rest = next
		case "-n", "--non-interactive", "-H", "--set-home", "-E", "--preserve-env", "-k", "--reset-timestamp":
			options = append(options, token)
		default:
			if strings.HasPrefix(token, "--prompt=") {
				continue
			}
			if strings.HasPrefix(token, "--user=") || strings.HasPrefix(token, "--group=") || strings.HasPrefix(token, "--preserve-env=") || strings.HasPrefix(token, "-u") && len(token) > 2 || strings.HasPrefix(token, "-g") && len(token) > 2 {
				options = append(options, token)
			} else {
				return "", fmt.Errorf("sudo option %q is not supported for credential injection; use an explicit sudo command without shell/login mode", token)
			}
		}
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", fmt.Errorf("sudo requires an explicit noninteractive command")
	}
	return "sudo " + strings.Join(options, " ") + " -S -p '" + prompt + "' -- sh -c 'printf %s " + ready + " >&2; exec \"$@\"' sh " + rest, nil
}

// Return one shell word verbatim, retaining quoted option values. Expansions
// and shell control operators are not accepted in the sudo option prefix.
func sudoWord(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	quote := byte(0)
	escaped := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		if strings.ContainsRune("$`;|&<>()\r\n", rune(ch)) {
			return "", "", fmt.Errorf("unsupported shell syntax in sudo option")
		}
		if ch == ' ' || ch == '\t' {
			return s[:i], s[i+1:], nil
		}
	}
	if s == "" || quote != 0 || escaped {
		return "", "", fmt.Errorf("missing or malformed sudo option value")
	}
	return s, "", nil
}
