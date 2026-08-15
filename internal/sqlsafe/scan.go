// Package sqlsafe implements the guarded SQL execution contract for sshx:
// fail-closed statement classification, policy gates, backup planning, and
// PostgreSQL remote command assembly. It never connects anywhere itself; it
// only analyzes SQL text and builds commands for the SSH execution layer.
package sqlsafe

import (
	"errors"
	"fmt"
	"strings"
)

// maskNonCode returns a byte slice with the same length and offsets as sql in
// which every byte that is not SQL "code" (comment bodies, string literal
// contents, dollar-quoted bodies, quoted-identifier contents) is replaced so
// that keyword and separator scanning cannot be confused by embedded text.
//
// Masking rules:
//   - line/block comments and their delimiters   → ' '
//   - string literals including quotes           → ' '
//   - dollar-quoted strings including delimiters → ' '
//   - quoted identifiers: quotes kept, body      → 'x'
//
// It is fail-closed: any unterminated construct returns an error.
func maskNonCode(sql string) ([]byte, error) {
	src := []byte(sql)
	masked := make([]byte, len(src))
	copy(masked, src)

	n := len(src)
	i := 0
	for i < n {
		c := src[i]
		switch {
		case c == '-' && i+1 < n && src[i+1] == '-':
			for i < n && src[i] != '\n' {
				masked[i] = ' '
				i++
			}
		case c == '/' && i+1 < n && src[i+1] == '*':
			depth := 0
			start := i
			for i < n {
				if src[i] == '/' && i+1 < n && src[i+1] == '*' {
					depth++
					masked[i], masked[i+1] = ' ', ' '
					i += 2
					continue
				}
				if src[i] == '*' && i+1 < n && src[i+1] == '/' {
					depth--
					masked[i], masked[i+1] = ' ', ' '
					i += 2
					if depth == 0 {
						break
					}
					continue
				}
				masked[i] = ' '
				i++
			}
			if depth != 0 {
				return nil, fmt.Errorf("unterminated block comment starting at offset %d", start)
			}
		case c == '\'':
			// E'' strings honor backslash escapes; standard strings only ''.
			backslashEscapes := i > 0 && (src[i-1] == 'e' || src[i-1] == 'E') &&
				(i-1 == 0 || !isIdentByte(src[i-2]))
			start := i
			masked[i] = ' '
			i++
			closed := false
			for i < n {
				if backslashEscapes && src[i] == '\\' && i+1 < n {
					masked[i], masked[i+1] = ' ', ' '
					i += 2
					continue
				}
				if src[i] == '\'' {
					if i+1 < n && src[i+1] == '\'' {
						masked[i], masked[i+1] = ' ', ' '
						i += 2
						continue
					}
					masked[i] = ' '
					i++
					closed = true
					break
				}
				masked[i] = ' '
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string literal starting at offset %d", start)
			}
		case c == '"':
			start := i
			i++
			closed := false
			for i < n {
				if src[i] == '"' {
					if i+1 < n && src[i+1] == '"' {
						masked[i], masked[i+1] = 'x', 'x'
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				masked[i] = 'x'
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated quoted identifier starting at offset %d", start)
			}
		case c == '$':
			tagEnd, ok := dollarTagEnd(src, i)
			if !ok {
				i++ // positional parameter ($1) or bare '$'
				continue
			}
			tag := string(src[i : tagEnd+1])
			closeIdx := strings.Index(sql[tagEnd+1:], tag)
			if closeIdx < 0 {
				return nil, fmt.Errorf("unterminated dollar-quoted string starting at offset %d", i)
			}
			end := tagEnd + 1 + closeIdx + len(tag)
			for j := i; j < end; j++ {
				masked[j] = ' '
			}
			i = end
		default:
			i++
		}
	}
	return masked, nil
}

// RedactForAudit removes comments and literal values while retaining enough SQL
// structure for an audit record to remain useful. Exact-statement correlation
// is provided separately by a SHA-256 digest.
func RedactForAudit(sql string) string {
	masked, err := maskNonCode(sql)
	if err != nil {
		return "<unparseable SQL redacted>"
	}
	for i := 0; i < len(masked); {
		if masked[i] < '0' || masked[i] > '9' ||
			(i > 0 && isIdentByte(masked[i-1])) {
			i++
			continue
		}
		j := i + 1
		for j < len(masked) && ((masked[j] >= '0' && masked[j] <= '9') ||
			masked[j] == '.' || masked[j] == 'e' || masked[j] == 'E' ||
			masked[j] == '+' || masked[j] == '-') {
			j++
		}
		for k := i; k < j; k++ {
			masked[k] = ' '
		}
		masked[i] = '?'
		i = j
	}
	return strings.Join(strings.Fields(string(masked)), " ")
}

// dollarTagEnd returns the index of the closing '$' of a dollar-quote tag
// beginning at src[start] ('$'), or ok=false when this is not a dollar quote.
func dollarTagEnd(src []byte, start int) (int, bool) {
	i := start + 1
	for i < len(src) {
		c := src[i]
		if c == '$' {
			return i, true
		}
		isTagByte := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(i > start+1 && c >= '0' && c <= '9')
		if !isTagByte {
			return 0, false
		}
		i++
	}
	return 0, false
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// splitStatements splits sql at top-level semicolons using the masked view and
// returns the non-empty statements as (original, masked) slices with matching
// offsets. Fail-closed lexing errors propagate from maskNonCode.
func splitStatements(sql string) ([]string, [][]byte, error) {
	masked, err := maskNonCode(sql)
	if err != nil {
		return nil, nil, err
	}
	var stmts []string
	var maskedStmts [][]byte
	begin := 0
	flush := func(end int) {
		if strings.TrimSpace(string(masked[begin:end])) == "" {
			return
		}
		// Trim using the original text: masked regions (string literals,
		// comments) read as spaces in the masked view and must not be eaten.
		lead, trail := trimOffsets([]byte(sql[begin:end]))
		stmts = append(stmts, sql[begin+lead:begin+trail])
		maskedStmts = append(maskedStmts, masked[begin+lead:begin+trail])
	}
	for i := 0; i < len(masked); i++ {
		if masked[i] == ';' {
			flush(i)
			begin = i + 1
		}
	}
	flush(len(masked))
	if len(stmts) == 0 {
		return nil, nil, errors.New("empty SQL statement")
	}
	return stmts, maskedStmts, nil
}

// trimOffsets returns the [lead, trail) window of text with surrounding
// whitespace removed.
func trimOffsets(text []byte) (int, int) {
	lead := 0
	trail := len(text)
	for lead < trail && isSpaceByte(text[lead]) {
		lead++
	}
	for trail > lead && isSpaceByte(text[trail-1]) {
		trail--
	}
	return lead, trail
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// token is one top-level (paren depth 0) lexical word of a masked statement.
type token struct {
	pos   int    // byte offset in the statement
	end   int    // exclusive end offset
	upper string // uppercased masked text of the token
}

// isTokenByte reports bytes that belong to one identifier/keyword token.
// Quoted identifiers were masked to `"xxx"` so they form a single token.
func isTokenByte(c byte) bool {
	return isIdentByte(c) || c == '.' || c == '"' || c == '*'
}

// topLevelTokens tokenizes the masked statement keeping only tokens at paren
// depth zero. Anything inside parentheses (subqueries, column lists, CTE
// bodies) is skipped, which is exactly what top-level clause detection needs.
func topLevelTokens(masked []byte) []token {
	var tokens []token
	depth := 0
	i := 0
	n := len(masked)
	for i < n {
		c := masked[i]
		switch {
		case c == '(':
			depth++
			i++
		case c == ')':
			depth--
			i++
		case depth == 0 && isTokenByte(c):
			start := i
			for i < n && isTokenByte(masked[i]) {
				i++
			}
			tokens = append(tokens, token{
				pos:   start,
				end:   i,
				upper: strings.ToUpper(string(masked[start:i])),
			})
		default:
			i++
		}
	}
	return tokens
}

// containsKeyword scans all parenthesis depths in an already masked statement.
// It is used only for fail-closed checks where hidden executable clauses matter.
func containsKeyword(masked []byte, keywords ...string) bool {
	for i := 0; i < len(masked); {
		if !isIdentByte(masked[i]) {
			i++
			continue
		}
		start := i
		for i < len(masked) && isIdentByte(masked[i]) {
			i++
		}
		word := strings.ToUpper(string(masked[start:i]))
		for _, keyword := range keywords {
			if word == keyword {
				return true
			}
		}
	}
	return false
}

// findKeyword returns the index within tokens of the first token equal to any
// of the given keywords, starting at from. Returns -1 when absent.
func findKeyword(tokens []token, from int, keywords ...string) int {
	for i := from; i < len(tokens); i++ {
		for _, kw := range keywords {
			if tokens[i].upper == kw {
				return i
			}
		}
	}
	return -1
}
