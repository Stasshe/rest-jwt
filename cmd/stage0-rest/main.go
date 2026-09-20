// Stage 0: 認証なし、素のREST。GET/POST/PUT/DELETEの意味論
// (安全性・べき等性)とステータスコードだけに集中するための土台で、
// 以降のstageはこのリソースに認証を1枚ずつ重ねていく。
//
// net/httpはHTTPのパース(リクエストライン・ヘッダ・ボディの読み取り)
// だけに使い、「どのURIにどのメソッドが来たら何を返すか」という
// RESTの振り分けはServeMuxのパターン("GET /items/{id}")に頼らず自前で書く。
// ServeMuxは404・405・Allowヘッダを黙ってやってくれるが、それがまさに
// この章で理解したい中身なので、ここでは全部手で書いている。
// 実行: go run ./cmd/stage0-rest — docs/01_rest.md 参照
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// --- リソース: /items ------------------------------------------------------

type item struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// store はメモリ上の/itemsコレクション。
type store struct {
	mu     sync.Mutex
	items  map[string]item
	nextID int
}

func newStore() *store {
	return &store{
		items:  map[string]item{"1": {ID: "1", Name: "first item"}},
		nextID: 2,
	}
}

func (s *store) list() []item {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]item, 0, len(s.items))
	for _, it := range s.items {
		list = append(list, it)
	}
	return list
}

func (s *store) get(id string) (item, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[id]
	return it, ok
}

// create はサーバがidを採番する(POSTはコレクションに対する「追加」)。
func (s *store) create(name string) item {
	s.mu.Lock()
	defer s.mu.Unlock()
	it := item{ID: strconv.Itoa(s.nextID), Name: name}
	s.nextID++
	s.items[it.ID] = it
	return it
}

// replace はクライアントが指定したidの中身を置き換える。存在しなければ
// 作る — PUTは「このURIの中身をこれにする」という宣言なので、何度
// 叩いても最終状態は同じ(べき等)。
func (s *store) replace(id, name string) item {
	s.mu.Lock()
	defer s.mu.Unlock()
	it := item{ID: id, Name: name}
	s.items[id] = it
	return it
}

// remove は「無い状態にする」操作。既に無くてもエラーにしない(べき等)。
func (s *store) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
}

// --- レスポンス補助 -------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// methodNotAllowed は「そのURIは存在するが、そのメソッドは対応していない」
// を表す405。404(URIが無い)とは別物で、RFC 9110はAllowヘッダで
// 対応メソッドを必ず知らせるよう求めている。
func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// readName はリクエストボディから name を取り出す。POSTとPUTで共通。
func readName(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body struct{ Name string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return "", false
	}
	return body.Name, true
}

// --- ルーティング ---------------------------------------------------------
// 判断の順序: URIを見る(無ければ404) → メソッドを見る(未対応なら405)
// → 中身を見る(不正なら400) → 実行。

func route(s *store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/items" {
			serveCollection(s, w, r)
			return
		}
		id, ok := strings.CutPrefix(r.URL.Path, "/items/")
		if !ok || id == "" || strings.Contains(id, "/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		serveMember(s, w, r, id)
	}
}

// serveCollection は /items(コレクション)を扱う。
func serveCollection(s *store, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.list())
	case http.MethodPost:
		name, ok := readName(w, r)
		if !ok {
			return
		}
		it := s.create(name)
		// 201 Created + 作ったリソースのURIをLocationで教える。
		w.Header().Set("Location", "/items/"+it.ID)
		writeJSON(w, http.StatusCreated, it)
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

// serveMember は /items/{id}(メンバー)を扱う。
func serveMember(s *store, w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		it, found := s.get(id)
		if !found {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeJSON(w, http.StatusOK, it)
	case http.MethodPut:
		name, ok := readName(w, r)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, s.replace(id, name))
	case http.MethodDelete:
		s.remove(id)
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func main() {
	log.Println("stage0-rest listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", route(newStore())))
}
