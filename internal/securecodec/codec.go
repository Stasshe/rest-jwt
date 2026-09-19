// Package securecodec is the fixed implementation: golang-jwt/v5 with an
// explicit algorithm allow-list (never trust the token's own "alg"
// header), a long random secret, and a short-lived access token backed by
// a server-side refresh session — so a compromised access token expires in
// minutes, and logout can actually revoke something (the refresh session),
// which is the thing plain stateless JWTs can't do.
package securecodec

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"rest-jwt/internal/authserver"
)

const (
	accessTokenTTL  = 2 * time.Minute
	refreshTokenTTL = 30 * time.Minute
)

type refreshSession struct {
	Subject   string
	Role      string
	ExpiresAt time.Time
}

type Codec struct {
	secret []byte

	mu       sync.Mutex
	sessions map[string]refreshSession
}

func New(secret []byte) *Codec {
	return &Codec{secret: secret, sessions: map[string]refreshSession{}}
}

func (c *Codec) Issue(claims authserver.Claims) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  claims.Subject,
		"role": claims.Role,
		"iat":  now.Unix(),
		"exp":  now.Add(accessTokenTTL).Unix(),
	})
	return token.SignedString(c.secret)
}

func (c *Codec) Verify(tokenStr string) (authserver.Claims, error) {
	// WithValidMethods is the fix for stage2/stage4: the algorithm is
	// pinned by the server, never read from the token's own header.
	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return c.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !parsed.Valid {
		return authserver.Claims{}, errors.New("invalid token")
	}
	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return authserver.Claims{}, errors.New("invalid claims")
	}
	sub, _ := mapClaims["sub"].(string)
	role, _ := mapClaims["role"].(string)
	if sub == "" {
		return authserver.Claims{}, errors.New("missing subject")
	}
	return authserver.Claims{Subject: sub, Role: role}, nil
}

func (c *Codec) IssueRefresh(subject, role string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	c.mu.Lock()
	c.sessions[token] = refreshSession{Subject: subject, Role: role, ExpiresAt: time.Now().Add(refreshTokenTTL)}
	c.mu.Unlock()
	return token, nil
}

func (c *Codec) Refresh(refreshToken string) (string, error) {
	c.mu.Lock()
	s, ok := c.sessions[refreshToken]
	c.mu.Unlock()
	if !ok || time.Now().After(s.ExpiresAt) {
		return "", errors.New("refresh session expired or unknown")
	}
	return c.Issue(authserver.Claims{Subject: s.Subject, Role: s.Role})
}

func (c *Codec) Revoke(refreshToken string) {
	c.mu.Lock()
	delete(c.sessions, refreshToken)
	c.mu.Unlock()
}
