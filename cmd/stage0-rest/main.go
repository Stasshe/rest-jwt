// Stage 0: 認証なし、素のREST。GET/POST/PUT/DELETEの意味論
// (安全性・べき等性)とステータスコードだけに集中するための土台で、
// 以降のstageはこのリソースに認証を1枚ずつ重ねていく。
// 実行: go run ./cmd/stage0-rest — docs/01_rest.md 参照
package main

import (
	"log"
	"net/http"

	"rest-jwt/internal/itemsresource"
)

func main() {
	store := itemsresource.NewStore()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /items", itemsresource.ListHandler(store))
	mux.HandleFunc("POST /items", itemsresource.CreateHandler(store))
	mux.HandleFunc("GET /items/{id}", itemsresource.GetHandler(store))
	mux.HandleFunc("PUT /items/{id}", itemsresource.ReplaceHandler(store))
	mux.HandleFunc("DELETE /items/{id}", itemsresource.DeleteHandler(store))

	log.Println("stage0-rest listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
