package ironsession

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIronSession(t *testing.T) {
	opts := DefaultOptions().
		WithPassword("super-secret-password-that-is-very-long").
		WithTTL(3600).
		WithSecure(false) // For testing

	is, err := New(opts)
	if err != nil {
		t.Fatalf("Failed to create IronSession: %v", err)
	}

	// Test creating and encoding session
	session := is.NewSession("test-session")
	session.Set("user_id", 123)
	session.Set("username", "john_doe")
	session.Set("authenticated", true)

	encoded, err := is.EncodeSession(session)
	if err != nil {
		t.Fatalf("Failed to encode session: %v", err)
	}

	// Test decoding session
	decoded, err := is.DecodeSession(encoded, "test-session")
	if err != nil {
		t.Fatalf("Failed to decode session: %v", err)
	}

	// Verify data - NOTE numbers become float64
	if decoded.Get("user_id") != 123. {
		t.Errorf("Expected user_id 123, got %v", decoded.Get("user_id"))
	}

	if decoded.Get("username") != "john_doe" {
		t.Errorf("Expected username john_doe, got %v", decoded.Get("username"))
	}

	if !decoded.Get("authenticated").(bool) {
		t.Error("Expected authenticated to be true")
	}

	// Test HTTP integration
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Test middleware
	handler := is.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := GetSessionFromContext(r.Context())
		if !ok {
			t.Error("Session not found in context")
			return
		}

		session.Set("visited", true)
		session.Save(is, w)
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	// Check cookie was set
	result := w.Result()
	defer result.Body.Close()
	cookies := result.Cookies()
	if len(cookies) == 0 {
		t.Error("No cookie was set")
	}
}

func TestSessionMethods(t *testing.T) {
	opts := DefaultOptions().
		WithPassword("another-very-long-password-for-testing").
		WithSecure(false)

	is, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}

	session := is.NewSession("test")

	// Test Set/Get
	session.Set("key1", "value1")
	session.Set("key2", 42)
	session.Set("key3", []string{"a", "b", "c"})

	if session.Get("key1") != "value1" {
		t.Error("Get failed for key1")
	}

	if session.Get("key2") != 42 {
		t.Error("Get failed for key2")
	}

	// Test Has
	if !session.Has("key1") {
		t.Error("Has should return true for existing key")
	}

	if session.Has("nonexistent") {
		t.Error("Has should return false for nonexistent key")
	}

	// Test Delete
	session.Delete("key1")
	if session.Has("key1") {
		t.Error("Delete failed")
	}

	// Test Keys
	keys := session.Keys()
	if len(keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(keys))
	}

	// Test Clear
	session.Clear()
	if len(session.Data()) != 0 {
		t.Error("Clear failed")
	}
}

func TestOptionsValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    *Options
		wantErr bool
	}{
		{
			name:    "valid options",
			opts:    DefaultOptions().WithPassword("very-long-password-here"),
			wantErr: false,
		},
		{
			name:    "missing password",
			opts:    DefaultOptions(),
			wantErr: true,
		},
		{
			name:    "short password",
			opts:    DefaultOptions().WithPassword("short"),
			wantErr: true,
		},
		{
			name: "negative TTL",
			opts: DefaultOptions().
				WithPassword("password").
				WithTTL(-1),
			wantErr: true,
		},
		{
			name: "low iterations",
			opts: &Options{
				Password:   "password",
				Iterations: 500,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
