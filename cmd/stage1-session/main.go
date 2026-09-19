// Stage 1: baseline REST resource protected by classic server-side session
// cookies. No JWT yet — this is the reference point every later stage gets
// compared against. Run: go run ./cmd/stage1-session
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"

	"rest-jwt/internal/userstore"
)

// --- REST resource: /items -------------------------------------------------

type item struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

var (
	itemsMu sync.Mutex
	items   = map[string]item{"1": {ID: "1", Name: "first item"}}
	nextID  = 2
)

// --- session store -----------------------------------------------------

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

func requireSession(w http.ResponseWriter, r *http.Request) (session, bool) {
	s, ok := currentSession(r)
	if !ok {
		http.Error(w, `{"error":"login required"}`, http.StatusUnauthorized)
	}
	return s, ok
}

// --- handlers ------------------------------------------------------------

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
	s, ok := requireSession(w, r)
	if !ok {
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"username": s.Username, "role": s.Role})
}

func handleItemsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		itemsMu.Lock()
		defer itemsMu.Unlock()
		list := make([]item, 0, len(items))
		for _, it := range items {
			list = append(list, it)
		}
		_ = json.NewEncoder(w).Encode(list)

	case http.MethodPost:
		if _, ok := requireSession(w, r); !ok {
			return
		}
		var body struct{ Name string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			http.Error(w, `{"error":"name required"}`, http.StatusBadRequest)
			return
		}
		itemsMu.Lock()
		id := strconv.Itoa(nextID)
		it := item{ID: id, Name: body.Name}
		items[id] = it
		nextID++
		itemsMu.Unlock()
		w.Header().Set("Location", "/items/"+id)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(it)
	}
}

func handleItem(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	switch r.Method {
	case http.MethodPut:
		if _, ok := requireSession(w, r); !ok {
			return
		}
		var body struct{ Name string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			http.Error(w, `{"error":"name required"}`, http.StatusBadRequest)
			return
		}
		itemsMu.Lock()
		items[id] = item{ID: id, Name: body.Name} // idempotent: same body -> same end state
		itemsMu.Unlock()
		w.WriteHeader(http.StatusOK)

	case http.MethodDelete:
		if _, ok := requireSession(w, r); !ok {
			return
		}
		itemsMu.Lock()
		delete(items, id)
		itemsMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("POST /logout", handleLogout)
	mux.HandleFunc("GET /me", handleMe)
	mux.HandleFunc("/items", handleItemsCollection)
	mux.HandleFunc("/items/{id}", handleItem)

	log.Println("stage1-session listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
