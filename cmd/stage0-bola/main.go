// Stage 0: BOLA (Broken Object Level Authorization)。ログイン自体は
// 正しく機能する — セッションが無ければ/ordersに触れない。しかし
// ハンドラは「誰かがログイン済みか」しか見ておらず、「その注文が
// ログイン中の本人のものか」を一度も確認していない。ログイン済み
// なら誰の注文IDでもGET/PUT/DELETEできてしまう。
// 実行: go run ./cmd/stage0-bola — docs/00_bola.md 参照
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

// --- セッション ------------------------------------------------------------

type session struct {
	Username string
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

func requireSession(next func(w http.ResponseWriter, r *http.Request, s session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := currentSession(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		next(w, r, s)
	}
}

// --- 注文リソース ----------------------------------------------------------
// Orderは必ず1人のOwnerに属する。これがBOLAの前提 — 所有者の概念が
// 無いリソースにBOLAは存在しない。

type Order struct {
	ID     string `json:"id"`
	Owner  string `json:"owner"`
	Item   string `json:"item"`
	Amount int    `json:"amount"`
}

var (
	ordersMu sync.Mutex
	orders   = map[string]Order{
		"1001": {ID: "1001", Owner: "alice", Item: "keyboard", Amount: 8000},
		"1002": {ID: "1002", Owner: "bob", Item: "monitor", Amount: 32000},
	}
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// --- 認証ハンドラ ----------------------------------------------------------

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

	id := newSessionID()
	sessionsMu.Lock()
	sessions[id] = session{Username: u.Username}
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

// --- 注文ハンドラ ----------------------------------------------------------
// バグ: 3つとも requireSession でログインは確認しているが、
// order.Owner == s.Username を一度も比較していない。IDが分かれば
// 他人の注文を読める・書き換えられる・消せる。

func handleGetOrder(w http.ResponseWriter, r *http.Request, s session) {
	ordersMu.Lock()
	o, ok := orders[r.PathValue("id")]
	ordersMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, o)
}

func handleReplaceOrder(w http.ResponseWriter, r *http.Request, s session) {
	var body struct {
		Item   string
		Amount int
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	id := r.PathValue("id")
	ordersMu.Lock()
	o, ok := orders[id]
	if ok {
		o.Item, o.Amount = body.Item, body.Amount
		orders[id] = o
	}
	ordersMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, o)
}

func handleDeleteOrder(w http.ResponseWriter, r *http.Request, s session) {
	ordersMu.Lock()
	delete(orders, r.PathValue("id"))
	ordersMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("POST /logout", handleLogout)
	mux.HandleFunc("GET /orders/{id}", requireSession(handleGetOrder))
	mux.HandleFunc("PUT /orders/{id}", requireSession(handleReplaceOrder))
	mux.HandleFunc("DELETE /orders/{id}", requireSession(handleDeleteOrder))

	log.Println("stage0-bola listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
