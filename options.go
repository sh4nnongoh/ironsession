package ironsession

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"hash"
	"net/http"
)

// Options holds configuration for IronSession
type Options struct {
	// Required: Password for encryption (min 32 chars recommended)
	Password string

	// Optional: Salt for key derivation (auto-generated if empty)
	Salt string

	// Optional: Cookie name (default: "ironsession")
	CookieName string

	// Optional: Time to live in seconds (default: 86400 = 24 hours)
	TTL int

	// Optional: Cookie path (default: "/")
	Path string

	// Optional: Cookie domain
	Domain string

	// Optional: Secure flag (HTTPS only) (default: true in production)
	Secure bool

	// Optional: HttpOnly flag (default: true)
	HttpOnly bool

	// Optional: SameSite policy (default: http.SameSiteLaxMode)
	SameSite http.SameSite

	// Optional: MaxAge for cookie (overrides TTL)
	MaxAge int

	// Optional: PBKDF2 iterations (default: 10000)
	Iterations int

	// Optional: Hash function for PBKDF2 (default: sha256.New)
	HashFunc func() hash.Hash

	// Optional: Cipher function (default: aes.NewCipher)
	CipherFunc func(key []byte) (cipher.Block, error)
}

// DefaultOptions returns sensible default options
func DefaultOptions() *Options {
	return &Options{
		CookieName: "ironsession",
		TTL:        86400, // 24 hours
		Path:       "/",
		Secure:     true,
		HttpOnly:   true,
		SameSite:   http.SameSiteLaxMode,
		Iterations: 1000,
		HashFunc:   sha256.New,
		CipherFunc: aes.NewCipher,
	}
}

// Validate checks if options are valid
func (o *Options) Validate() error {
	if o.Password == "" {
		return errors.New("password is required")
	}

	if len(o.Password) < 16 {
		return errors.New("password must be at least 16 characters")
	}

	if o.TTL < 0 {
		return errors.New("TTL must be non-negative")
	}

	if o.Iterations < 1000 {
		return errors.New("iterations must be at least 1000")
	}

	if o.HashFunc == nil {
		return errors.New("HashFunc cannot be nil")
	}

	if o.CipherFunc == nil {
		return errors.New("CipherFunc cannot be nil")
	}

	return nil
}

// WithPassword sets the password and returns Options for chaining
func (o *Options) WithPassword(password string) *Options {
	o.Password = password
	return o
}

// WithCookieName sets the cookie name
func (o *Options) WithCookieName(name string) *Options {
	o.CookieName = name
	return o
}

// WithTTL sets the time to live
func (o *Options) WithTTL(ttl int) *Options {
	o.TTL = ttl
	return o
}

// WithSecure sets the secure flag
func (o *Options) WithSecure(secure bool) *Options {
	o.Secure = secure
	return o
}

// WithHttpOnly sets the HttpOnly flag
func (o *Options) WithHttpOnly(httpOnly bool) *Options {
	o.HttpOnly = httpOnly
	return o
}

// WithSameSite sets the SameSite policy
func (o *Options) WithSameSite(sameSite http.SameSite) *Options {
	o.SameSite = sameSite
	return o
}

// WithIterations sets the PBKDF2 iterations
func (o *Options) WithIterations(iterations int) *Options {
	o.Iterations = iterations
	return o
}

// WithHashFunc sets the hash function
func (o *Options) WithHashFunc(hashFunc func() hash.Hash) *Options {
	o.HashFunc = hashFunc
	return o
}

// WithCipherFunc sets the cipher function
func (o *Options) WithCipherFunc(cipherFunc func(key []byte) (cipher.Block, error)) *Options {
	o.CipherFunc = cipherFunc
	return o
}
