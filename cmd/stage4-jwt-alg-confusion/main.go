// Stage 4: server issues RS256 tokens and publishes its public key at
// GET /pubkey (as real JWKS endpoints do). Its verifier still trusts the
// token's own "alg" header, so an HS256 token signed with that same public
// key is accepted. Run: go run ./cmd/stage4-jwt-alg-confusion
// see docs/07_attack_alg_confusion.md
package main

import (
	"log"
	"net/http"

	"rest-jwt/internal/authserver"
	"rest-jwt/internal/confusioncodec"
)

func main() {
	codec, err := confusioncodec.New()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("stage4-jwt-alg-confusion listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", authserver.New(codec)))
}
