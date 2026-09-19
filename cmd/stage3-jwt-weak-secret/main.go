// Stage 3: verification itself is correct (alg=none is rejected), but the
// HMAC secret is short enough to find by dictionary attack.
// Run: go run ./cmd/stage3-jwt-weak-secret — see docs/06_attack_weak_secret.md
package main

import (
	"log"
	"net/http"

	"rest-jwt/internal/authserver"
	"rest-jwt/internal/hmaccodec"
)

func main() {
	codec := hmaccodec.Codec{
		Secret:       []byte("sunny"), // <- the bug: guessable, in tools/bruteforce/wordlist.txt
		AllowAlgNone: false,
	}
	log.Println("stage3-jwt-weak-secret listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", authserver.New(codec)))
}
