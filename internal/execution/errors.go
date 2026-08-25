package execution

import (
	"errors"
	"fmt"
	"strings"

	"github.com/talkincode/sshx/internal/sshclient"
)

// Classify maps an error to a stable machine-readable kind.
// Typed/sentinel errors are preferred; free-form matching is only a fallback
// at external-library boundaries.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, sshclient.ErrCommandTimeout):
		return ErrorKindTimeout
	case errors.Is(err, sshclient.ErrNoExitStatus):
		return ErrorKindExitMissing
	case errors.Is(err, ErrConfig):
		return ErrorKindConfig
	case errors.Is(err, ErrLocalIO):
		return ErrorKindLocalIO
	case errors.Is(err, ErrRemoteIO):
		return ErrorKindRemoteIO
	case errors.Is(err, ErrBlocked):
		return ErrorKindBlocked
	case errors.Is(err, sshclient.ErrPrecondition):
		return ErrorKindPrecondition
	case errors.Is(err, sshclient.ErrApplyBlocked):
		return ErrorKindBlocked
	case errors.Is(err, sshclient.ErrInvalidBind):
		return ErrorKindConfig
	}
	var blocked *sshclient.CommandBlockedError
	if errors.As(err, &blocked) {
		return ErrorKindBlocked
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "known_hosts"), strings.Contains(msg, "host key"):
		return ErrorKindHostKey
	case strings.Contains(msg, "unable to authenticate"),
		strings.Contains(msg, "no authentication"),
		strings.Contains(msg, "no supported methods"),
		strings.Contains(msg, "password fallback"),
		strings.Contains(msg, "handshake"):
		return ErrorKindAuth
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "failed to connect"),
		strings.Contains(msg, "dial"):
		return ErrorKindConnect
	case strings.Contains(msg, "sftp"), strings.Contains(msg, "remote file"), strings.Contains(msg, "remote path"):
		return ErrorKindRemoteIO
	case strings.Contains(msg, "read "), strings.Contains(msg, "open "), strings.Contains(msg, "write "):
		return ErrorKindLocalIO
	default:
		return ErrorKindUnknown
	}
}

// BuildError constructs ErrorInfo with retry classification based on action intent
// and completion certainty.
func BuildError(err error, kind, intent, completion string) *ErrorInfo {
	if err == nil && kind == "" {
		return nil
	}
	if kind == "" {
		kind = Classify(err)
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	info := &ErrorInfo{
		Kind:        kind,
		Message:     msg,
		Retryable:   false,
		RetrySafety: RetryUnknown,
	}
	switch kind {
	case ErrorKindTimeout, ErrorKindConnect, ErrorKindProtocol:
		info.Retryable = true
		info.RetrySafety = RetryVerifyFirst
	case ErrorKindAuth, ErrorKindHostKey, ErrorKindBlocked, ErrorKindConfig, ErrorKindLocalIO, ErrorKindPrecondition:
		info.Retryable = false
		info.RetrySafety = RetryUnsafe
	case ErrorKindRemoteExit:
		info.Retryable = false
		info.RetrySafety = RetryVerifyFirst
	case ErrorKindExitMissing:
		info.Retryable = false
		info.RetrySafety = RetryVerifyFirst
	}

	switch completion {
	case CompletionCompletedUnconfirmed, CompletionPartial, CompletionUnknown:
		if intent == IntentChange {
			info.Retryable = false
			if info.RetrySafety == RetrySafe {
				info.RetrySafety = RetryVerifyFirst
			}
			if info.RetrySafety == "" || info.RetrySafety == RetryUnknown {
				info.RetrySafety = RetryVerifyFirst
			}
			if completion == CompletionPartial || completion == CompletionUnknown {
				info.RetrySafety = RetryUnsafe
				if completion == CompletionPartial {
					info.RetrySafety = RetryVerifyFirst
				}
			}
		}
	case CompletionNotStarted:
		if kind == ErrorKindConnect || kind == ErrorKindTimeout || kind == ErrorKindAuth {
			// Auth failures are not safely auto-retried without inspection.
			if kind == ErrorKindConnect {
				info.Retryable = true
				info.RetrySafety = RetrySafe
			}
		}
	case CompletionCompleted:
		if kind == ErrorKindRemoteExit {
			info.RetrySafety = RetryVerifyFirst
		}
	}

	// Uncertain change actions never report safe automatic retry.
	if intent == IntentChange && (completion == CompletionPartial ||
		completion == CompletionCompletedUnconfirmed ||
		completion == CompletionUnknown) {
		if info.RetrySafety == RetrySafe {
			info.RetrySafety = RetryVerifyFirst
		}
		info.Retryable = false
	}
	return info
}

var (
	// ErrConfig indicates a request/schema/selector configuration failure.
	ErrConfig = errors.New("execution config error")
	// ErrLocalIO indicates a local file/stdin failure before network access.
	ErrLocalIO = errors.New("local io error")
	// ErrRemoteIO indicates a remote filesystem/protocol I/O failure.
	ErrRemoteIO = errors.New("remote io error")
	// ErrBlocked indicates the safety policy refused the action.
	ErrBlocked = errors.New("action blocked by safety policy")
	// ErrNoTargets indicates selector resolution matched zero hosts.
	ErrNoTargets = fmt.Errorf("%w: no targets matched", ErrConfig)
)

// CompletionFor maps phase + error kind onto observed execution certainty.
func CompletionFor(phase, kind string, remoteStarted bool, exitObserved bool) string {
	if !remoteStarted {
		switch phase {
		case PhaseResolve, PhaseAdmission, PhaseConnect, PhaseAuthenticate:
			return CompletionNotStarted
		default:
			if kind == ErrorKindBlocked || kind == ErrorKindConfig || kind == ErrorKindLocalIO {
				return CompletionNotStarted
			}
		}
	}
	if exitObserved {
		return CompletionCompleted
	}
	switch kind {
	case ErrorKindExitMissing:
		return CompletionCompletedUnconfirmed
	case ErrorKindTimeout:
		if remoteStarted {
			return CompletionPartial
		}
		return CompletionNotStarted
	case ErrorKindProtocol, ErrorKindConnect:
		if remoteStarted {
			return CompletionUnknown
		}
		return CompletionNotStarted
	case "":
		return CompletionCompleted
	default:
		if remoteStarted {
			return CompletionUnknown
		}
		return CompletionNotStarted
	}
}
