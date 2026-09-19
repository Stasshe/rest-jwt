// Package hmaccodec is a hand-rolled JWT codec (no library) used to teach
// the wire format itself: header.payload.signature, each part base64url
// encoded, joined by dots.
//
// It has one configurable bug, used by two different stages:
//
//   - AllowAlgNone: the verifier trusts the attacker-controlled "alg"
//     header and skips signature checking entirely when it says "none".
//     This is the classic 2015-era alg:none vulnerability class.
//   - a short Secret: verification itself is correct, but the HMAC key is
//     weak enough to be found by brute force / dictionary attack.
//
// Issue always signs correctly with HS256; only Verify can be broken, which
// mirrors how these bugs happen in real code (a permissive verifier, not a
// permissive issuer).
package hmaccodec

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"rest-jwt/internal/authserver"
)

type Codec struct {
	Secret       []byte
	AllowAlgNone bool // stage2: verifier bug
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func b64(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (c Codec) Issue(claims authserver.Claims) (string, error) {
	now := time.Now()
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(15 * time.Minute).Unix()

	h, err := b64(header{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	p, err := b64(claims)
	if err != nil {
		return "", err
	}
	signingInput := h + "." + p
	mac := hmac.New(sha256.New, c.Secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig, nil
}

func (c Codec) Verify(token string) (authserver.Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return authserver.Claims{}, errors.New("malformed token")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return authserver.Claims{}, errors.New("malformed header")
	}
	var h header
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return authserver.Claims{}, errors.New("malformed header")
	}

	switch h.Alg {
	case "HS256":
		mac := hmac.New(sha256.New, c.Secret)
		mac.Write([]byte(parts[0] + "." + parts[1]))
		want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(want), []byte(parts[2])) {
			return authserver.Claims{}, errors.New("signature mismatch")
		}
	case "none":
		if !c.AllowAlgNone {
			return authserver.Claims{}, errors.New(`alg "none" rejected`)
		}
		// BUG: alg=none means there is nothing to verify — the token's
		// signature part is ignored entirely.
	default:
		return authserver.Claims{}, errors.New("unsupported alg")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return authserver.Claims{}, errors.New("malformed payload")
	}
	var claims authserver.Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return authserver.Claims{}, errors.New("malformed payload")
	}
	if time.Now().Unix() > claims.ExpiresAt {
		return authserver.Claims{}, errors.New("token expired")
	}
	return claims, nil
}
