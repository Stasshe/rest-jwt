# 02. セッションハイジャック(セッション固定)

`stage1`を止め、`stage2-session-hijack`を起動する。

```
go run ./cmd/stage2-session-hijack
```

## 理論

`cmd/stage2-session-hijack/main.go`の`handleLogin`を見る。

```go
id := ""
if c, err := r.Cookie("session_id"); err == nil {
    id = c.Value // バグ: 既存のIDをローテーションせずそのまま使う
}
if id == "" {
    id = newSessionID()
}
```

正しいログイン処理は、成功した瞬間に**必ず新しいセッションIDを発行**しなければならない。このサーバは逆で、クライアントが既に`session_id`Cookieを持っていれば、それをそのまま「認証済み」に昇格させてしまう。これがセッション固定(session fixation)。

攻撃の筋書き:

1. 攻撃者が適当な`session_id`の値(例: `deadbeefdeadbeef`)を決める
2. 何らかの方法(共有端末、罠のリンク、サブドメインでのCookie設定など — このハンズオンでは省略し、被害者が既にそのIDをブラウザに持っている状態から始める)で、被害者のブラウザにこのIDをCookieとして持たせる
3. 被害者がそのブラウザで普通にログインする。サーバは既存のCookie値をそのまま使い回すので、`deadbeefdeadbeef`が「被害者としてログイン済み」になる
4. 攻撃者は最初から知っているこの値を使い、被害者としてAPIを叩ける

鍵を盗む攻撃(3〜5章のJWT攻撃)とは違う。**盗む前から鍵の値を知っている**という点が固定攻撃の特徴。

## 攻撃

```
FIXED=deadbeefdeadbeef

# 被害者役: このIDを持ったまま普通にログインする
curl -c /tmp/victim.txt -b "session_id=$FIXED" -X POST localhost:8080/login \
  -d '{"Username":"alice","Password":"password123"}'

# 攻撃者役: ログインを一度もせず、最初から知っているIDだけでaliceになる
curl -b "session_id=$FIXED" localhost:8080/me
```

`{"username":"alice",...}`が返る。攻撃者は`alice`のパスワードを一切知らない。

## 何が起きたか

セッションIDそのものの生成(`newSessionID`のcrypto/rand)は安全 — 推測されて破られたわけではない。壊れているのは「ログイン成功時に必ず作り直す」という**ローテーションの欠落**。これは"ID自体の強さ"と"IDの発行タイミング"が別の防御であることを示す。修正(07章)は、クライアントが何を送ってきていても無視して、ログインごとに常に新規発行する。
