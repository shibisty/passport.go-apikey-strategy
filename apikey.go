// Package apikey authenticates API clients by key. gtr package:
// passport-apikey.
//
//	key, hash, err := apikey.Generate("sk_live")  // show key once, store hash
//	s := apikey.New(func(ctx context.Context, hash string) (*passport.Identity, error) {
//	    return lookupKey(ctx, hash) // passport.ErrInvalidCredentials if unknown or revoked
//	})
//	a.Use(s)
//	api := apikey.Middleware(s, "")(handler)  // X-API-Key or Authorization: Bearer
//
// Keys are a prefix and 32 random bytes; only their SHA-256 is stored, so the
// table of keys is useless to whoever reads it. A fast hash is enough here
// (unlike passwords): the key has 256 bits of entropy.
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"passport"
	"passport/httpauth"
)

// Header is where Middleware looks for the key by default.
const Header = "X-API-Key"

// LookupFunc finds the client of a key by its hash (Hash); it returns
// passport.ErrInvalidCredentials for an unknown or revoked key.
type LookupFunc func(ctx context.Context, hash string) (*passport.Identity, error)

// Strategy is the "apikey" passport.CredentialStrategy.
type Strategy struct{ lookup LookupFunc }

// New makes the strategy.
func New(lookup LookupFunc) *Strategy { return &Strategy{lookup: lookup} }

// Name is "apikey".
func (s *Strategy) Name() string { return "apikey" }

// Authenticate expects credentials{"api_key": key}.
func (s *Strategy) Authenticate(ctx context.Context, credentials map[string]string) (*passport.Identity, error) {
	key := strings.TrimSpace(credentials["api_key"])
	if !wellFormed(key) {
		return nil, passport.ErrInvalidCredentials
	}
	id, err := s.lookup(ctx, Hash(key))
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, passport.ErrInvalidCredentials
	}
	if id.Provider == "" {
		id.Provider = "apikey"
	}
	return id, nil
}

var prefixRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// Generate makes a key "<prefix>_<43 base64url characters>" and the hash to
// store. The prefix tells keys apart in logs and secret scanners
// (sk_live, sk_test); the key itself is shown to the user once.
func Generate(prefix string) (key, hash string, err error) {
	if !prefixRe.MatchString(prefix) {
		return "", "", errors.New("apikey: prefix must be lowercase letters, digits and _, starting with a letter")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	key = prefix + "_" + base64.RawURLEncoding.EncodeToString(raw)
	return key, Hash(key), nil
}

// Hash is the stored form of a key: SHA-256, hex.
func Hash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func wellFormed(key string) bool {
	i := strings.LastIndexByte(key, '_')
	return i > 0 && len(key)-i-1 == 43 && len(key) < 100
}

// Middleware authenticates a request by its key in header (default
// X-API-Key) or an Authorization: Bearer key, and stores the Identity for
// httpauth.FromContext. A missing or wrong key leaves the request
// anonymous; use httpauth.RequireAuth after it.
func Middleware(s *Strategy, header string) func(http.Handler) http.Handler {
	if header == "" {
		header = Header
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get(header)
			if key == "" {
				if scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
					key = strings.TrimSpace(tok)
				}
			}
			if key != "" {
				if id, err := s.Authenticate(r.Context(), map[string]string{"api_key": key}); err == nil {
					r = r.WithContext(httpauth.WithIdentity(r.Context(), id))
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

var _ passport.CredentialStrategy = (*Strategy)(nil)
