package httperror

import (
	"fmt"
)

type HTTPError interface {
	Error() string
	Message() string
	Code() int
}

type httpError struct {
	message string
	code    int
}

func (e httpError) Error() string {
	return fmt.Sprintf("HTTP Error: %s", e.message)
}

func (e httpError) Code() int {
	return e.code
}

func (e httpError) Message() string {
	return e.message
}

func New(message string, code int) HTTPError {
	return httpError{message, code}
}
