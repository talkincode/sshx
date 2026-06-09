package errutil

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

// 预定义的错误类型
var (
	// ErrConnectionClosed 表示连接已关闭（正常情况）
	ErrConnectionClosed = errors.New("connection closed")

	// ErrSessionClosed 表示会话已关闭（正常情况）
	ErrSessionClosed = errors.New("session closed")

	// ErrInvalidConfig 表示配置无效
	ErrInvalidConfig = errors.New("invalid configuration")

	// ErrConnectionFailed 表示连接失败
	ErrConnectionFailed = errors.New("connection failed")

	// ErrAuthFailed 表示认证失败
	ErrAuthFailed = errors.New("authentication failed")

	// ErrCommandFailed 表示命令执行失败
	ErrCommandFailed = errors.New("command execution failed")
)

// ErrorCategory 错误分类
type ErrorCategory int

const (
	// CategoryIgnorable 可忽略的错误（如正常的连接关闭）
	CategoryIgnorable ErrorCategory = iota

	// CategoryRetriable 可重试的错误（如临时网络问题）
	CategoryRetriable

	// CategoryFatal 致命错误（如认证失败）
	CategoryFatal
)

// 预定义的可忽略错误列表
var defaultIgnorableErrors = []error{
	io.EOF,
	net.ErrClosed,
	ErrConnectionClosed,
	ErrSessionClosed,
}

// IsIgnorableError 检查错误是否可忽略
func IsIgnorableError(err error) bool {
	if err == nil {
		return true
	}

	// 检查预定义的可忽略错误
	for _, ignorable := range defaultIgnorableErrors {
		if errors.Is(err, ignorable) {
			return true
		}
	}

	// 检查 SSH 特定的正常关闭错误
	if isNormalEOF(err) {
		return true
	}

	return false
}

// IsRetriableError 检查错误是否可重试
func IsRetriableError(err error) bool {
	if err == nil {
		return false
	}

	// 网络相关的超时错误通常可重试
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// 连接超时可重试
	if netErr != nil && netErr.Timeout() {
		return true
	}

	// 连接被拒绝可重试（可能服务暂时不可用）
	errStr := err.Error()
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") {
		return true
	}

	return false
}

// CategorizeError 对错误进行分类
func CategorizeError(err error) ErrorCategory {
	if err == nil || IsIgnorableError(err) {
		return CategoryIgnorable
	}

	if IsRetriableError(err) {
		return CategoryRetriable
	}

	return CategoryFatal
}

// isNormalEOF 检查是否是正常的 EOF（会话正常结束）
// 在使用 PTY 的情况下，EOF 通常表示会话正常关闭
func isNormalEOF(err error) bool {
	if err == nil {
		return false
	}

	// 直接的 EOF 错误
	if errors.Is(err, io.EOF) {
		return true
	}

	// 检查错误消息是否只是 "EOF"
	// 这是 SSH 库在会话正常关闭时返回的
	errStr := err.Error()
	return errStr == "EOF"
}

// IsEOFError 检查是否是 EOF 相关的错误
func IsEOFError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, io.EOF) || err.Error() == "EOF"
}

// WrapError 包装错误并添加上下文信息
func WrapError(err error, context string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", context, err)
}

// JoinErrors 合并多个错误
func JoinErrors(errs ...error) error {
	var nonNilErrors []error
	for _, err := range errs {
		if err != nil {
			nonNilErrors = append(nonNilErrors, err)
		}
	}

	if len(nonNilErrors) == 0 {
		return nil
	}

	if len(nonNilErrors) == 1 {
		return nonNilErrors[0]
	}

	return errors.Join(nonNilErrors...)
}

// SafeClose 安全地关闭资源，忽略可忽略的错误
// 返回需要关注的错误
func SafeClose(closer io.Closer) error {
	if closer == nil {
		return nil
	}

	err := closer.Close()
	if IsIgnorableError(err) {
		return nil
	}

	return err
}

// HandleCloseError 处理 defer 中的 close 错误
// 自动忽略可忽略的错误，合并其他错误到返回值
func HandleCloseError(errp *error, closer io.Closer) {
	if closer == nil {
		return
	}

	if cerr := closer.Close(); cerr != nil && !IsIgnorableError(cerr) {
		if errp != nil {
			if *errp == nil {
				*errp = cerr
			} else {
				*errp = errors.Join(*errp, cerr)
			}
		}
	}
}

// ConvertExitError 将 SSH 退出错误转换为更友好的错误消息
func ConvertExitError(err error) error {
	if err == nil {
		return nil
	}

	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Errorf("command exited with code %d", exitErr.ExitStatus())
	}

	return err
}

// EnhanceError 增强错误信息，添加更多上下文
func EnhanceError(err error, stdout, stderr string) error {
	if err == nil {
		return nil
	}

	// 如果是正常的 EOF，检查是否有输出
	if IsEOFError(err) {
		if stdout != "" || stderr != "" {
			// 有输出说明命令执行成功，EOF 只是会话终止信号
			return nil
		}
		// 无输出的 EOF 通常表示连接问题
		return fmt.Errorf("connection closed unexpectedly (EOF) - check SSH credentials")
	}

	// 构建详细的错误消息
	var errMsg strings.Builder
	errMsg.WriteString(err.Error())

	if stderr != "" {
		fmt.Fprintf(&errMsg, "\nStderr: %s", stderr)
	}

	if stdout != "" {
		fmt.Fprintf(&errMsg, "\nStdout: %s", stdout)
	}

	// 添加退出码信息
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		fmt.Fprintf(&errMsg, "\nExit Code: %d", exitErr.ExitStatus())
	}

	return fmt.Errorf("%s", errMsg.String())
}

// SafeCloseMultiple 安全地关闭多个资源
// 返回所有非可忽略的错误的组合
func SafeCloseMultiple(closers ...io.Closer) error {
	var errs []error
	for _, closer := range closers {
		if err := SafeClose(closer); err != nil {
			errs = append(errs, err)
		}
	}
	return JoinErrors(errs...)
}
