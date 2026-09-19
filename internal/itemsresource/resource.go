// Package itemsresource は/itemsという1つのRESTリソースを、認証の
// あるなしに関わらず全stageで使い回すために切り出したもの。
// stage0は認証なしでそのままこのハンドラを登録し、stage1は
// 作成/更新/削除だけをセッションミドルウェアでラップする。
// リソース自体のCRUDロジックとメソッドの意味論(安全・べき等)は
// stage間で変わらない — 変わるのは「誰が呼べるか」だけ。
package itemsresource

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
)

// Item はこのリソースが表現する唯一のデータ型。
type Item struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Store はメモリ上の/itemsコレクション。
type Store struct {
	mu     sync.Mutex
	items  map[string]Item
	nextID int
}

// NewStore は初期データ1件入りのストアを作る。
func NewStore() *Store {
	return &Store{
		items:  map[string]Item{"1": {ID: "1", Name: "first item"}},
		nextID: 2,
	}
}

func (s *Store) List() []Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]Item, 0, len(s.items))
	for _, it := range s.items {
		list = append(list, it)
	}
	return list
}

func (s *Store) Get(id string) (Item, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[id]
	return it, ok
}

func (s *Store) Create(name string) Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := strconv.Itoa(s.nextID)
	s.nextID++
	it := Item{ID: id, Name: name}
	s.items[id] = it
	return it
}

// Replace はidをキーに置き換える。存在しなければ新規作成する
// (PUTは「このURIの中身をこれにする」という宣言であり、そのURIが
// まだ無ければ作ってよい — べき等性は崩れない)。
func (s *Store) Replace(id, name string) Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	it := Item{ID: id, Name: name}
	s.items[id] = it
	return it
}

// Delete は存在すればtrueを返す。存在しなくてもエラーにはしない
// — 「無い状態にする」という目的から見れば、既に無いのも成功。
func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, existed := s.items[id]
	delete(s.items, id)
	return existed
}

// --- HTTPハンドラ ---------------------------------------------------------
// 各ハンドラは1メソッド1関数。ServeMuxのパターン("GET /items"等)で
// メソッドごとに振り分けるので、ハンドラ内でr.Methodを見るswitchは
// 要らない。

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func ListHandler(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.List())
	}
}

func GetHandler(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		it, ok := s.Get(r.PathValue("id"))
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, it)
	}
}

func CreateHandler(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Name string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		it := s.Create(body.Name)
		w.Header().Set("Location", "/items/"+it.ID)
		writeJSON(w, http.StatusCreated, it)
	}
}

func ReplaceHandler(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Name string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		it := s.Replace(r.PathValue("id"), body.Name)
		writeJSON(w, http.StatusOK, it)
	}
}

func DeleteHandler(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.Delete(r.PathValue("id"))
		w.WriteHeader(http.StatusNoContent)
	}
}
