package errors

import "errors"

var (
	ErrNilEbpfMap = errors.New("nil ebpf map")
	ErrEmptyGroup = errors.New("empty group")
	ErrEmptyName  = errors.New("empty name")
)
