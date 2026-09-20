// Stage 2: セッション固定(session fixation)によるハイジャック。
// 正しい実装ならログイン成功時に必ず新しいsession_idを発行し直す
// べきだが、このハンドラはクライアントが既にsession_idクッキーを
// 持っていればそれをそのまま使い回し、無ければ新規発行する
// — というだけの分岐になっている。攻撃者が先に決めたIDを被害者に
// 持たせておけば、被害者がログインした瞬間そのIDが「認証済み」に
// 昇格し、攻撃者自身も同じIDで本人になれる。
// 実行: go run ./cmd/stage2-session-hijack — docs/02_session_hijack.md 参照
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"rest-jwt/internal/userstore"
)

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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// バグ本体。ログイン成功時にidを「常に新規発行」していない —
// クライアントが送ってきたsession_idがあれば、それをそのまま
// 認証済みセッションのキーとして採用してしまう。
func handleLogin(w http.ResponseWriter, r *http.Request) {
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

	id := ""
	if c, err := r.Cookie("session_id"); err == nil {
		id = c.Value // バグ: 既存のIDをローテーションせずそのまま使う
	}
	if id == "" {
		id = newSessionID()
	}

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
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged in"})
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
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": s.Username, "role": s.Role})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("POST /logout", handleLogout)
	mux.HandleFunc("GET /me", handleMe)

	log.Println("stage2-session-hijack listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
