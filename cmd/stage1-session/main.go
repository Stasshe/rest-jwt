// Stage 1: stage0と同じ/itemsリソースに、古典的なサーバ側セッション
// Cookieで認証を1枚重ねる。安全なメソッド(GET)は素通し、副作用のある
// メソッド(POST/PUT/DELETE)だけをセッションミドルウェアでガードする
// — RESTの意味論(安全性・べき等性)と認証の境界線がどこで交わるかを
// 見る回。実行: go run ./cmd/stage1-session
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"rest-jwt/internal/itemsresource"
	"rest-jwt/internal/userstore"
)

// --- セッションストア -----------------------------------------------------

type session struct {
	Username string
	Role     string
}

var (
	sessionsMu sync.Mutex
	sessions   = map[string]session{}
)

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func currentSession(r *http.Request) (session, bool) {
	c, err := r.Cookie("session_id")
	if err != nil {
		return session{}, false
	}
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	s, ok := sessions[c.Value]
	return s, ok
}

// requireSession は副作用のあるハンドラの前段に挟むミドルウェア。
// セッションが無ければ401を返してnextを呼ばない。
func requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := currentSession(r); !ok {
			http.Error(w, `{"error":"login required"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// --- 認証ハンドラ ----------------------------------------------------------

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	u, err := userstore.Authenticate(body.Username, body.Password)
	if err != nil {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	id := newSessionID()
	sessionsMu.Lock()
	sessions[id] = session{Username: u.Username, Role: u.Role}
	sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged in"})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("session_id"); err == nil {
		sessionsMu.Lock()
		delete(sessions, c.Value)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "", Path: "/", MaxAge: -1})
	w.WriteHeader(http.StatusOK)
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	s, ok := currentSession(r)
	if !ok {
		http.Error(w, `{"error":"login required"}`, http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"username": s.Username, "role": s.Role})
}

func main() {
	store := itemsresource.NewStore()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("POST /logout", handleLogout)
	mux.HandleFunc("GET /me", handleMe)

	// 安全なメソッドはガード無し、副作用のあるメソッドだけ認証必須にする。
	mux.HandleFunc("GET /items", itemsresource.ListHandler(store))
	mux.HandleFunc("GET /items/{id}", itemsresource.GetHandler(store))
	mux.HandleFunc("POST /items", requireSession(itemsresource.CreateHandler(store)))
	mux.HandleFunc("PUT /items/{id}", requireSession(itemsresource.ReplaceHandler(store)))
	mux.HandleFunc("DELETE /items/{id}", requireSession(itemsresource.DeleteHandler(store)))

	log.Println("stage1-session listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
