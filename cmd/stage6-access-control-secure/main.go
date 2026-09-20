// Stage 6: stage0(BOLA)・stage1(IDOR)・stage2(セッション固定)の
// 3つを、同じ注文/請求書アプリの正しい実装として1本に直したもの。
// 3つとも根はセッション管理と権限判定の話であり、直し方も同じ
// 場所に集まる — ログインごとに毎回セッションIDを再生成し、
// リソースへの操作は必ずセッションの本人と対象オブジェクトの
// Ownerを比較する。
// 実行: go run ./cmd/stage6-access-control-secure — docs/07_access_control_defense.md 参照
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

// --- セッション --------------------------------------------------------
// stage2の修正: ログイン成功時、クライアントが何を送ってきていても
// 無視して必ず新規IDを発行する(ローテーション)。これがセッション
// 固定を防ぐ唯一のポイント。

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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

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

	id := newSessionID() // 常に新規発行。クライアントが送ってきたIDは見ない。
	sessionsMu.Lock()
	sessions[id] = session{Username: u.Username}
	sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure: true, // 本番はHTTPS前提なので必須。ローカルhttpのため今回は外している。
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

// --- 注文リソース(stage0のBOLAを直す) ------------------------------------

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

// 修正: stage0はここでOwnerを見ていなかった。3ハンドラとも
// 「セッションの本人 == 対象オブジェクトのOwner」を必ず確認する。
func handleGetOrder(w http.ResponseWriter, r *http.Request, s session) {
	ordersMu.Lock()
	o, ok := orders[r.PathValue("id")]
	ordersMu.Unlock()
	if !ok || o.Owner != s.Username {
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
	if ok && o.Owner == s.Username {
		o.Item, o.Amount = body.Item, body.Amount
		orders[id] = o
	}
	ordersMu.Unlock()
	if !ok || o.Owner != s.Username {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, o)
}

func handleDeleteOrder(w http.ResponseWriter, r *http.Request, s session) {
	id := r.PathValue("id")
	ordersMu.Lock()
	o, ok := orders[id]
	if ok && o.Owner == s.Username {
		delete(orders, id)
	}
	ordersMu.Unlock()
	if !ok || o.Owner != s.Username {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- 請求書リソース(stage1のIDORを直す) -----------------------------------

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

// 修正: stage1はクエリパラメータuserで対象を決めていた。ここでは
// 完全に無視し、セッションの本人(s.Username)だけを使う。
func handleInvoices(w http.ResponseWriter, r *http.Request, s session) {
	var result []Invoice
	for _, inv := range invoices {
		if inv.Owner == s.Username {
			result = append(result, inv)
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("POST /logout", handleLogout)
	mux.HandleFunc("GET /orders/{id}", requireSession(handleGetOrder))
	mux.HandleFunc("PUT /orders/{id}", requireSession(handleReplaceOrder))
	mux.HandleFunc("DELETE /orders/{id}", requireSession(handleDeleteOrder))
	mux.HandleFunc("GET /invoices", requireSession(handleInvoices))

	log.Println("stage6-access-control-secure listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
