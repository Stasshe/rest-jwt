// Stage 1: IDOR (Insecure Direct Object Reference)。stage0のBOLAとは
// バグの場所が違う — こちらはセッションで本人確認はできているのに、
// 「表示する請求書は誰のものか」をセッションからではなく、リクエスト
// が渡してきた user パラメータからそのまま決めてしまっている。
// ログインは本人確認の手段であるはずなのに、その後の判定で
// 使われていない。
// 実行: go run ./cmd/stage1-idor — docs/01_idor.md 参照
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

// --- 請求書リソース ---------------------------------------------------------

type Invoice struct {
	ID     string `json:"id"`
	Owner  string `json:"owner"`
	Amount int    `json:"amount"`
}

var invoices = []Invoice{
	{ID: "inv-alice-1", Owner: "alice", Amount: 4500},
	{ID: "inv-bob-1", Owner: "bob", Amount: 91000},
	{ID: "inv-bob-2", Owner: "bob", Amount: 12000},
}

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

// --- 請求書ハンドラ ----------------------------------------------------------
// バグ: ログインは必須にしているが、「誰の請求書を返すか」は
// s.Username(本人)ではなく r.URL.Query().Get("user")(クライアントが
// 送ってきた値)で決めている。ログインチェックが「関所」ではなく
// 「入場券の有無チェック」にしかなっていない。

func handleInvoices(w http.ResponseWriter, r *http.Request) {
	if _, ok := currentSession(r); !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return
	}

	target := r.URL.Query().Get("user")
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user query param required"})
		return
	}

	var result []Invoice
	for _, inv := range invoices {
		if inv.Owner == target {
			result = append(result, inv)
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("GET /invoices", handleInvoices)

	log.Println("stage1-idor listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
