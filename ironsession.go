package ironsession

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/pbkdf2"
)

type IronSession struct {
	opts        *Options
	secureCodec *securecookie.SecureCookie
	aesGCM      cipher.AEAD
}

func New(opts *Options) (*IronSession, error) {
	if opts == nil {
		opts = DefaultOptions()
	}

	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	salt := []byte(opts.Salt)
	if len(salt) == 0 {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}
		opts.Salt = base64.StdEncoding.EncodeToString(salt)
	}

	encryptionKey := pbkdf2.Key(
		[]byte(opts.Password),
		salt,
		opts.Iterations,
		32, // AES-256 key size
		opts.HashFunc,
	)

	integrityKey := pbkdf2.Key(
		[]byte(opts.Password),
		salt,
		opts.Iterations,
		32, // SHA-256 HMAC key size
		opts.HashFunc,
	)

	blockCipher, err := opts.CipherFunc(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create secure cookie codec for integrity
	secureCodec := securecookie.New(integrityKey, nil)
	secureCodec.MaxAge(opts.TTL)

	return &IronSession{
		opts:        opts,
		secureCodec: secureCodec,
		aesGCM:      aesGCM,
	}, nil
}

func (is *IronSession) GetSession(r *http.Request, name string) (*Session, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		if err == http.ErrNoCookie {
			return is.NewSession(name), nil
		}
		return nil, fmt.Errorf("failed to get cookie: %w", err)
	}

	return is.DecodeSession(cookie.Value, name)
}

func (is *IronSession) NewSession(name string) *Session {
	return &Session{
		data:     make(map[string]interface{}),
		modified: true,
		opts:     is.opts,
		name:     name,
	}
}

func (is *IronSession) DecodeSession(encrypted string, name string) (*Session, error) {
	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	var verified []byte
	if err := is.secureCodec.Decode(name, string(decoded), &verified); err != nil {
		return nil, fmt.Errorf("integrity check failed: %w", err)
	}

	nonceSize := is.aesGCM.NonceSize()
	if len(verified) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := verified[:nonceSize], verified[nonceSize:]
	plaintext, err := is.aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("json unmarshal failed: %w", err)
	}

	return &Session{
		data:     data,
		modified: false,
		opts:     is.opts,
		name:     name,
	}, nil
}

func (is *IronSession) Save(session *Session, w http.ResponseWriter) error {
	if !session.modified {
		return nil
	}

	encoded, err := is.EncodeSession(session)
	if err != nil {
		return fmt.Errorf("failed to encode session: %w", err)
	}

	cookie := &http.Cookie{
		Name:     session.name,
		Value:    encoded,
		Path:     is.opts.Path,
		Domain:   is.opts.Domain,
		MaxAge:   is.opts.TTL,
		Secure:   is.opts.Secure,
		HttpOnly: is.opts.HttpOnly,
		SameSite: is.opts.SameSite,
	}

	if is.opts.MaxAge > 0 {
		cookie.MaxAge = is.opts.MaxAge
	}

	http.SetCookie(w, cookie)
	session.modified = false
	return nil
}

func (is *IronSession) EncodeSession(session *Session) (string, error) {
	jsonData, err := json.Marshal(session.data)
	if err != nil {
		return "", fmt.Errorf("json marshal failed: %w", err)
	}

	nonce := make([]byte, is.aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := is.aesGCM.Seal(nonce, nonce, jsonData, nil)

	encoded, err := is.secureCodec.Encode(session.name, ciphertext)
	if err != nil {
		return "", fmt.Errorf("integrity encoding failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString([]byte(encoded)), nil
}

func (is *IronSession) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := is.GetSession(r, is.opts.CookieName)
		if err != nil {
			// Log error but continue without session
			fmt.Printf("Session error: %v\n", err)
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		ctx = contextWithSession(ctx, session)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
