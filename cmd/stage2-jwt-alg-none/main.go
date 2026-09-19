// Stage 2: JWT auth whose verifier trusts the "alg" header from the
// attacker and accepts alg=none, skipping signature checking entirely.
// Run: go run ./cmd/stage2-jwt-alg-none  — see docs/05_attack_alg_none.md
package main

import (
	"log"
	"net/http"

	"rest-jwt/internal/authserver"
	"rest-jwt/internal/hmaccodec"
)

func main() {
	codec := hmaccodec.Codec{
		Secret:       []byte("s0m3-r4nd0m-s3rv3r-secret!"),
		AllowAlgNone: true, // <- the bug
	}
	log.Println("stage2-jwt-alg-none listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", authserver.New(codec)))
}
