package textsafe

import "regexp"

var (
	redactQuotedAssign = regexp.MustCompile(`(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|authorization|bearer)=("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`)
	redactAssign       = regexp.MustCompile(`(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|authorization)=([^\s&;]+)`)
	redactBearer       = regexp.MustCompile(`(?i)\b(bearer)\s+([A-Za-z0-9\-._~+/]+=*)`)
	redactJWT          = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
)

// Redact replaces secret-shaped spans. It is conservative: unmatched text is kept.
func Redact(text string) string {
	if text == "" {
		return text
	}
	out := redactQuotedAssign.ReplaceAllString(text, `${1}="***"`)
	out = redactAssign.ReplaceAllString(out, `${1}=***`)
	out = redactBearer.ReplaceAllString(out, `${1} ***`)
	out = redactJWT.ReplaceAllString(out, "***jwt***")
	return out
}
