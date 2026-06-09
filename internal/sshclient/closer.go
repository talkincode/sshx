package sshclient

import (
	"errors"
	"io"

	"github.com/talkincode/sshx/pkg/errutil"
	"github.com/talkincode/sshx/pkg/logger"
)

// CloseIgnore closes the closer and handles errors appropriately.
// It will ignore errors in the ignore list and merge other errors into errp.
// This is useful for defer statements where we want to handle close errors
// but allow certain expected errors to be silently ignored.
//
// Usage example:
//
//	func handle(r io.ReadCloser) (err error) {
//	    defer CloseIgnore(&err, r, net.ErrClosed)
//	    // ... read ...
//	    return
//	}
//
// Deprecated: Use errutil.HandleCloseError instead which automatically handles common ignorable errors.
func CloseIgnore(errp *error, c io.Closer, ignore ...error) {
	if c == nil {
		return
	}

	if cerr := c.Close(); cerr != nil {
		// Check if the error is in the ignore list
		for _, ig := range ignore {
			if errors.Is(cerr, ig) {
				return
			}
		}

		// Check if it's a common ignorable error
		if errutil.IsIgnorableError(cerr) {
			return
		}

		// Not in ignore list: merge into return error
		if errp != nil {
			if *errp == nil {
				*errp = cerr
			} else {
				*errp = errors.Join(*errp, cerr)
			}
		}
	}
}

// MustClose 关闭资源，如果失败则记录警告日志
// 适用于 defer 语句中不需要返回错误的场景
func MustClose(closer io.Closer, resourceName string) {
	if closer == nil {
		return
	}

	if err := closer.Close(); err != nil && !errutil.IsIgnorableError(err) {
		logger.GetLogger().Warning("Failed to close %s: %v", resourceName, err)
	}
}

// SafeCloseMultiple 安全地关闭多个资源
// 返回所有非可忽略的错误的组合
func SafeCloseMultiple(closers ...io.Closer) error {
	return errutil.SafeCloseMultiple(closers...)
}
