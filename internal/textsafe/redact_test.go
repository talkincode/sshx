package textsafe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedactSecretShapes(t *testing.T) {
	in := `password=hunter2 token="abc" Authorization=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaaaaaabb.cccccccccc ok`
	out := Redact(in)
	require.NotContains(t, out, "hunter2")
	require.NotContains(t, out, "abc")
	require.Contains(t, out, "password=***")
	require.Contains(t, out, "***jwt***")
	require.Contains(t, out, "ok")
}
