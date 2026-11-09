# passport-apikey

API keys for [`passport`](https://github.com/shibisty/passport.go). Go package: `apikey`.

## Installation

```bash
gtr add github:shibisty/passport.go github:shibisty/passport.go-apikey-strategy
```

## Usage

```go
key, hash, err := apikey.Generate("sk_live") // show key once; store hash with the client

s := apikey.New(func(ctx context.Context, hash string) (*passport.Identity, error) {
    // look the hash up; passport.ErrInvalidCredentials if unknown or revoked
})
a.Use(s)

api := apikey.Middleware(s, "")(httpauth.RequireAuth(handler)) // X-API-Key or Authorization: Bearer
```

- A key is `<prefix>_` and 32 random bytes (base64url); only its SHA-256 is stored. A fast
  hash is right here: unlike a password, the key has 256 bits of entropy.
- The prefix (`sk_live`, `sk_test`) tells keys apart in logs and secret scanners.
- `Middleware` leaves a request without a valid key anonymous; follow it with
  `httpauth.RequireAuth`. `a.Credential(ctx, "apikey", {"api_key": key})` works too.

## License

MIT
