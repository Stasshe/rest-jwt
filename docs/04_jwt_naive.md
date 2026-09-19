# 04. JWT認証サーバを動かす

ここから3つの攻撃(5〜7章)は、すべて同じ目標を狙う。

> **管理者アカウントのパスワードを知らないまま、`GET /admin`を通す。**

`userstore`(`internal/userstore/store.go`)を見ると分かる通り、そもそも`admin`というアカウントは存在しない。`GET /admin`はトークンの`role`クレームが`"admin"`かどうかだけを見て判定する(`internal/authserver/server.go`の`handleAdmin`)。これは実務でもよくあるRBAC実装そのもの — DBに問い合わせずトークンの中身だけで権限判定する。**JWTを使うということは、この判定を全面的に信頼するということ**であり、検証(署名チェック)が破られた瞬間、認可も同時に破られる。

## コードを読む

`internal/hmaccodec/codec.go`を開く。`Issue`(発行)と`Verify`(検証)の非対称性に注目する。

- `Issue`: 常に正しく`HS256`で署名する
- `Verify`: トークンの`header`に書かれた`alg`を**信用して分岐する**

この「検証側がheaderのalgを信用する」という設計そのものが、次章の脆弱性の根っこ。stage2ではさらに`AllowAlgNone: true`が立っており、`alg:"none"`のときは署名チェックを完全にスキップする。

## 通常のログインフローを確認

```
go run ./cmd/stage2-jwt-alg-none
```

```
curl -c /tmp/cookies.txt -X POST localhost:8080/login \
  -d '{"Username":"alice","Password":"password123"}'

curl -b /tmp/cookies.txt localhost:8080/me
curl -i -b /tmp/cookies.txt localhost:8080/admin   # 403のはず(aliceはuser)
```

正規のログインでは403になることを確認してから、5章で攻撃に入る。
