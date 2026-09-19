// Package authserver is the shared HTTP plumbing for every JWT stage
// (stage2-5). Only the Codec differs between stages — login/me/admin/logout
// routing, cookie handling, and status codes stay identical, so each stage
// isolates exactly one verification bug (or its fix).
package authserver

import (
	"encoding/json"
	"net/http"

	"rest-jwt/internal/userstore"
)

// Claims is the payload every codec issues and verifies.
type Claims struct {
	Subject   string `json:"sub"`
	Role      string `json:"role"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// Codec turns Claims into a token string and back. Each stage supplies a
// different implementation; that is the only thing that changes.
type Codec interface {
	Issue(c Claims) (token string, err error)
	Verify(token string) (Claims, error)
}

// PublicKeyPublisher is implemented by codecs that expose a public key
// (stage4: the RS256/HS256 confusion target). authserver registers
// GET /pubkey only when the codec supports it.
type PublicKeyPublisher interface {
	PublicKeyPEM() []byte
}

// Refresher is implemented by codecs that support short-lived access
// tokens backed by a server-side refresh session (stage5).
type Refresher interface {
	IssueRefresh(subject, role string) (refreshToken string, err error)
	Refresh(refreshToken string) (accessToken string, err error)
	Revoke(refreshToken string)
}

const (
	accessCookie  = "access_token"
	refreshCookie = "refresh_token"
)

// New builds the mux for one stage.
func New(codec Codec) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", handleLogin(codec))
	mux.HandleFunc("POST /logout", handleLogout(codec))
	mux.HandleFunc("GET /me", handleMe(codec))
	mux.HandleFunc("GET /admin", handleAdmin(codec))

	if r, ok := codec.(Refresher); ok {
		mux.HandleFunc("POST /refresh", handleRefresh(r))
	}
	if p, ok := codec.(PublicKeyPublisher); ok {
		mux.HandleFunc("GET /pubkey", func(w http.ResponseWriter, r *http.Request) {
			w.Write(p.PublicKeyPEM())
		})
	}
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func handleLogin(codec Codec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Username, Password string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		u, err := userstore.Authenticate(body.Username, body.Password)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}

		access, err := codec.Issue(Claims{Subject: u.Username, Role: u.Role})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "issue failed"})
			return
		}
		setCookie(w, accessCookie, access, "/")

		if r, ok := codec.(Refresher); ok {
			refresh, err := r.IssueRefresh(u.Username, u.Role)
			if err == nil {
				setCookie(w, refreshCookie, refresh, "/refresh")
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "logged in"})
	}
}

func handleLogout(codec Codec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if rf, ok := codec.(Refresher); ok {
			if c, err := r.Cookie(refreshCookie); err == nil {
				rf.Revoke(c.Value)
			}
		}
		clearCookie(w, accessCookie, "/")
		clearCookie(w, refreshCookie, "/refresh")
		w.WriteHeader(http.StatusOK)
	}
}

func handleMe(codec Codec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := verifyRequest(w, codec, r)
		if !ok {
			return
		}
		u, found := userstore.Lookup(claims.Subject)
		if !found {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unknown subject"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"username": u.Username, "role": u.Role})
	}
}

// handleAdmin authorizes purely on the role claim inside the token — no
// database lookup. That is deliberate: it is the shortest path from "broken
// verification" to "privilege escalation" in these exercises.
func handleAdmin(codec Codec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := verifyRequest(w, codec, r)
		if !ok {
			return
		}
		if claims.Role != "admin" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"secret": "🚩 welcome, admin"})
	}
}

func handleRefresh(r Refresher) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		c, err := req.Cookie(refreshCookie)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no refresh token"})
			return
		}
		access, err := r.Refresh(c.Value)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "refresh rejected"})
			return
		}
		setCookie(w, accessCookie, access, "/")
		writeJSON(w, http.StatusOK, map[string]string{"status": "refreshed"})
	}
}

func verifyRequest(w http.ResponseWriter, codec Codec, r *http.Request) (Claims, bool) {
	c, err := r.Cookie(accessCookie)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return Claims{}, false
	}
	claims, err := codec.Verify(c.Value)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return Claims{}, false
	}
	return claims, true
}

func setCookie(w http.ResponseWriter, name, value, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: path, MaxAge: -1})
}
