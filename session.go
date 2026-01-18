package ironsession

import (
	"context"
	"net/http"
	"time"
)

type Session struct {
	data     map[string]interface{}
	modified bool
	opts     *Options
	name     string
}

func (s *Session) Get(key string) interface{} {
	return s.data[key]
}

func (s *Session) Set(key string, value interface{}) {
	s.data[key] = value
	s.modified = true
}

func (s *Session) Delete(key string) {
	delete(s.data, key)
	s.modified = true
}

func (s *Session) Clear() {
	s.data = make(map[string]interface{})
	s.modified = true
}

func (s *Session) Destroy(w http.ResponseWriter) {
	s.data = make(map[string]interface{})
	s.modified = true

	// Set cookie with expired time
	cookie := &http.Cookie{
		Name:     s.name,
		Value:    "",
		Path:     s.opts.Path,
		Domain:   s.opts.Domain,
		MaxAge:   -1,
		Expires:  time.Now().Add(-24 * time.Hour),
		Secure:   s.opts.Secure,
		HttpOnly: s.opts.HttpOnly,
		SameSite: s.opts.SameSite,
	}
	http.SetCookie(w, cookie)
}

func (s *Session) Has(key string) bool {
	_, exists := s.data[key]
	return exists
}

func (s *Session) Keys() []string {
	keys := make([]string, 0, len(s.data))
	for k := range s.data {
		keys = append(keys, k)
	}
	return keys
}

func (s *Session) Data() map[string]interface{} {
	data := make(map[string]interface{})
	for k, v := range s.data {
		data[k] = v
	}
	return data
}

func (s *Session) Save(is *IronSession, w http.ResponseWriter) error {
	return is.Save(s, w)
}

type contextKey string

const sessionContextKey contextKey = "ironsession"

func contextWithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, session)
}

func GetSessionFromContext(ctx context.Context) (*Session, bool) {
	session, ok := ctx.Value(sessionContextKey).(*Session)
	return session, ok
}
