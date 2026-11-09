package apikey_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"passport"
	apikey "passport-apikey"
	"passport/httpauth"
)

func TestKeys(t *testing.T) {
	key, hash, err := apikey.Generate("sk_test")
	if err != nil || !strings.HasPrefix(key, "sk_test_") || len(key) != len("sk_test_")+43 || hash != apikey.Hash(key) || strings.Contains(hash, key) {
		t.Fatalf("Generate: %q %q %v", key, hash, err)
	}
	if k2, _, _ := apikey.Generate("sk_test"); k2 == key {
		t.Fatal("same key twice")
	}
	for _, bad := range []string{"", "Upper", "1abc", "a-b", strings.Repeat("a", 40)} {
		if _, _, err := apikey.Generate(bad); err == nil {
			t.Errorf("prefix %q accepted", bad)
		}
	}
	store := map[string]*passport.Identity{hash: {ProviderUserID: "client-1"}}
	boom := errors.New("db down")
	s := apikey.New(func(_ context.Context, h string) (*passport.Identity, error) {
		if h == "fail" {
			return nil, boom
		}
		if id, ok := store[h]; ok {
			c := *id
			return &c, nil
		}
		if h == apikey.Hash("nil_"+strings.Repeat("a", 43)) {
			return nil, nil
		}
		return nil, passport.ErrInvalidCredentials
	})
	id, err := s.Authenticate(context.Background(), map[string]string{"api_key": " " + key + " "})
	if err != nil || id.ProviderUserID != "client-1" || id.Provider != "apikey" || s.Name() != "apikey" {
		t.Fatalf("Authenticate: %+v %v", id, err)
	}
	other, _, _ := apikey.Generate("sk_test")
	for _, k := range []string{"", "garbage", other, "nil_" + strings.Repeat("a", 43)} {
		if _, err := s.Authenticate(context.Background(), map[string]string{"api_key": k}); !errors.Is(err, passport.ErrInvalidCredentials) {
			t.Errorf("%q: %v", k, err)
		}
	}

	h := apikey.Middleware(s, "")(httpauth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := httpauth.FromContext(r.Context())
		w.Write([]byte(id.ProviderUserID))
	})))
	for name, c := range map[string]struct {
		header, auth string
		code         int
	}{
		"header": {key, "", 200}, "bearer": {"", "Bearer " + key, 200},
		"wrong": {other, "", 401}, "none": {"", "", 401}, "basic": {"", "Basic " + key, 401},
	} {
		req := httptest.NewRequest("GET", "/", nil)
		if c.header != "" {
			req.Header.Set(apikey.Header, c.header)
		}
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.code {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
}
