# 08. 正しい実装: JWTの3攻撃への対策

`stage6`を止め、`stage7-jwt-secure`を起動する。

```
go run ./cmd/stage7-jwt-secure
```

`cmd/stage7-jwt-secure/main.go`を開きながら読む。ライブラリは`github.com/golang-jwt/jwt/v5`(04〜06章の手実装で中身を理解した上で、実運用では信頼された実装に任せる)。

## 直っている点

**1. 検証アルゴリズムをサーバが固定する**

```go
jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
    return secret, nil
}, jwt.WithValidMethods([]string{"HS256"}))
```

`WithValidMethods`で許可するアルゴリズムをサーバ側の設定として固定している。トークンの`alg`ヘッダに何と書かれていようと、許可リストにない方式は即座に拒否される。04章(none)と06章(RS256/HS256混同)は両方これで防げる — 原因が同じだったので対策も一つで済む。

**2. 十分な長さのランダム鍵**

32バイトの暗号論的乱数を鍵にしている。辞書にもブルートフォースにも耐える鍵空間になり、05章の攻撃が成立しなくなる。

**3. 短命なアクセストークン + サーバ側で失効できるリフレッシュセッション**

JWTの弱点は「即時失効が難しい」ことだった(03章の比較表)。ここでは:

- アクセストークン(JWT本体)は**2分**で失効する短命トークン。漏洩しても被害の時間が限定される
- リフレッシュトークンは不透明なランダム文字列で、サーバ側のメモリ(`sessions`マップ)に紐づく。Cookieセッション(02・06章)と同じ仕組み

つまりJWTの「ステートレスな検証の速さ」と、セッションの「サーバ側で握り潰せる」という利点を、役割分担で両取りしている。ログアウト(`POST /logout`)はこのリフレッシュセッションを削除するだけで、以後リフレッシュできなくなる。

**4. Cookie属性**

`setCookie`は`HttpOnly`と`SameSite=Lax`を毎回付けている。JWTだからといってlocalStorageに保存する必要はない — むしろHttpOnly Cookieに入れておけばXSSからは読めない。その代わりCSRFの検討は引き続き必要になる(このAPIは`Content-Type: application/json`を要求する設計にしており、単純なHTMLフォームからは送れない、というのも軽減策の一つ)。

## 3つの攻撃が通らないことを確認する

```
# 04章と同じalg:none攻撃
EXP=$(($(date +%s)+600))
T1=$(go run ./tools/forge -header '{"alg":"none","typ":"JWT"}' \
  -payload "{\"sub\":\"mallory\",\"role\":\"admin\",\"exp\":$EXP}")
curl -i --cookie "access_token=$T1" localhost:8080/admin   # 401になるはず

# 05章と同じ弱い鍵での偽造
T2=$(go run ./tools/forge -header '{"alg":"HS256","typ":"JWT"}' \
  -payload "{\"sub\":\"mallory\",\"role\":\"admin\",\"exp\":$EXP}" -secret sunny)
curl -i --cookie "access_token=$T2" localhost:8080/admin   # 401になるはず

# 06章のpubkey混同攻撃(そもそもこのサーバは/pubkeyを持たない)
curl -i localhost:8080/pubkey   # 404になるはず
```

## 動かして確かめる演習

`cmd/stage7-jwt-secure/main.go`の`accessTokenTTL`を`2*time.Minute`から`10*time.Second`に変えて`stage7`を再起動する。ログインしてすぐ`/me`が通り、10秒待ってから叩くと401になることを確認する。その後`POST /refresh`を叩けば新しいアクセストークンが発行され、また`/me`が通るようになる — アクセストークンとリフレッシュトークンの役割分担を、実際の時間経過で体感する。
