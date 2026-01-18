package ironsession

import "fmt"

var (
	ErrInvalidSession       = fmt.Errorf("invalid session")
	ErrDecryptionFailed     = fmt.Errorf("decryption failed")
	ErrIntegrityCheckFailed = fmt.Errorf("integrity check failed")
	ErrSessionExpired       = fmt.Errorf("session expired")
	ErrInvalidOptions       = fmt.Errorf("invalid options")
)

type SessionError struct {
	Op  string
	Err error
	Msg string
}

func (e *SessionError) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("ironsession: %s: %v: %s", e.Op, e.Err, e.Msg)
	}
	return fmt.Sprintf("ironsession: %s: %v", e.Op, e.Err)
}

func (e *SessionError) Unwrap() error {
	return e.Err
}

func NewSessionError(op string, err error, msg string) *SessionError {
	return &SessionError{
		Op:  op,
		Err: err,
		Msg: msg,
	}
}
