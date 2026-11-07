// Package errs defines domain errors. Each maps to one HTTP status and a stable machine-readable code.
package errs

import (
	"errors"
	"fmt"
)

// Error is a domain error carried from services to the API and MCP layers.
type Error struct {
	Status int
	Code   string
	Detail string
	cause  error
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }
func (e *Error) Unwrap() error { return e.cause }

func newf(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Wrap attaches a cause while keeping the domain status and code.
func (e *Error) Wrap(cause error) *Error { e.cause = cause; return e }

func Unauthenticated(f string, a ...any) *Error { return newf(401, "unauthenticated", f, a...) }
func Forbidden(f string, a ...any) *Error       { return newf(403, "forbidden", f, a...) }
func ContentWithheld(f string, a ...any) *Error { return newf(403, "content_withheld", f, a...) }
func NotFound(f string, a ...any) *Error        { return newf(404, "not_found", f, a...) }
func Conflict(f string, a ...any) *Error        { return newf(409, "conflict", f, a...) }
func PreconditionFailed(f string, a ...any) *Error {
	return newf(412, "precondition_failed", f, a...)
}
func PayloadTooLarge(f string, a ...any) *Error { return newf(413, "payload_too_large", f, a...) }
func Invalid(f string, a ...any) *Error         { return newf(422, "validation_failed", f, a...) }
func PreconditionRequired(f string, a ...any) *Error {
	return newf(428, "precondition_required", f, a...)
}

// Integrity marks ciphertext, wrapped keys or the audit chain failing authentication. Treat as a security event.
func Integrity(f string, a ...any) *Error { return newf(500, "integrity_violation", f, a...) }
func Internal(f string, a ...any) *Error  { return newf(500, "internal_error", f, a...) }

// TooManyRequests is a rate or in-flight limit; RetryAfter is in seconds.
func TooManyRequests(f string, a ...any) *Error { return newf(429, "rate_limited", f, a...) }

// Unavailable is a transient dependency failure (pool exhausted, KMS down).
func Unavailable(f string, a ...any) *Error { return newf(503, "unavailable", f, a...) }

// QuotaExceeded is a durable per-app budget.
func QuotaExceeded(f string, a ...any) *Error { return newf(507, "quota_exceeded", f, a...) }

// Coded is a conflict-class error with a specific machine-readable code.
func Coded(status int, code, f string, a ...any) *Error { return newf(status, code, f, a...) }
func Config(f string, a ...any) *Error                  { return newf(500, "configuration_error", f, a...) }

// As returns the domain error inside err, if any.
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// Is reports whether err carries a domain error with the given code.
func Is(err error, code string) bool {
	e, ok := As(err)
	return ok && e.Code == code
}
