package textsafe

import (
	"fmt"
	"path"
	"strings"
)

// ValidateTextPath requires a clean absolute POSIX path. Remote paths never
// use the local OS separator, including when sshx itself runs on Windows.
func ValidateTextPath(remotePath string) error {
	if strings.TrimSpace(remotePath) == "" {
		return fmt.Errorf("path is required")
	}
	if strings.Contains(remotePath, "\x00") {
		return fmt.Errorf("path contains NUL")
	}
	if strings.Contains(remotePath, "\\") {
		return fmt.Errorf("path must use POSIX separators")
	}
	if !path.IsAbs(remotePath) || path.Clean(remotePath) != remotePath {
		return fmt.Errorf("path must be a clean absolute POSIX path")
	}
	if remotePath == "/" {
		return fmt.Errorf("refusing to scan /")
	}
	return nil
}
