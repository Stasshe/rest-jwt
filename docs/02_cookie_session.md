# 02. Cookieセッション認証

`stage1-session`の実装(`cmd/stage1-session/main.go`)を読みながら進める。`/items`リソース自体は1章の`stage0-rest`と完全に同じ(`internal/itemsresource`を共有している)。違うのは、安全なメソッド(GET)はそのまま素通しし、副作用のあるメソッド(POST/PUT/DELETE)だけを`requireSession`というミドルウェアでガードしている点。RESTの意味論(安全性・べき等性)と認証の境界線がどこで交わるかを、このstageで見る。

## 仕組み

1. `POST /login`でID/パスワードを検証
2. サーバがランダムな`session_id`を生成し、`username`と`role`に紐づけてメモリに保持(`sessions`マップ)
3. `Set-Cookie: session_id=...`をレスポンスに乗せる
4. ブラウザは以降そのオリジンへの全リクエストに、このCookieを自動で付ける
5. サーバは`session_id`をキーにサーバ側の状態を引き、誰かを判定する

認証情報の実体(`username`, `role`)はサーバ側にしかない。クライアントが持っているのはただのランダム文字列。**これがCookieセッションとJWTの最大の違い**で、次章以降で効いてくる。

## Cookie属性

`http.SetCookie`で設定している属性を確認する。

- `HttpOnly` — `document.cookie`からJavaScriptで読めなくする。XSSが発生してもCookie値そのものは盗めない
- `SameSite=Lax` — 他サイトからのナビゲーション以外(クロスサイトの`<form>`送信や`fetch`)ではCookieを送らない。CSRF対策の一つ
- `Path` — Cookieを送る対象パスを絞る
- `Secure`(このハンズオンでは未設定。本番では必須) — HTTPS接続でのみ送信する

## なぜCookieは危険と隣り合わせか

Cookieは「ブラウザが自動で付けてくれる」のが利点であり弱点。ログイン中のユーザーが悪意あるサイトを開くと、そのサイトからのリクエストにも同じCookieが自動で乗る。これがCSRF(Cross-Site Request Forgery)。`SameSite`属性はこれを軽減するが、GETに副作用を持たせる設計ミス(1章参照)があると回避されうる。

HttpOnlyはXSS(サイトに悪意あるJSが注入される)からCookie値を守るが、XSSそのものを防ぐわけではない。XSSが起きれば、Cookieが自動で付く性質を悪用して「ログイン中のブラウザから」APIを叩かれる。

## ハンズオン

```
go run ./cmd/stage1-session
```

```
# 1章と同じGETは認証なしで通る(安全なメソッドはガード対象外)
curl -i localhost:8080/items

# 同じPOSTが今度は401になる — stage0との違いはここだけ
curl -i -X POST localhost:8080/items -d '{"Name":"x"}'

# -v でレスポンスヘッダを見る。Set-Cookie: session_id=... と HttpOnly を確認
curl -v -c /tmp/cookies.txt -X POST localhost:8080/login \
  -d '{"Username":"alice","Password":"password123"}'

# ログイン後は同じPOSTが201で通る
curl -i -b /tmp/cookies.txt -X POST localhost:8080/items -d '{"Name":"widget"}'

# 保存したCookieで自分の情報を取得
curl -b /tmp/cookies.txt localhost:8080/me

# ログアウト後は使えなくなることを確認
curl -X POST -b /tmp/cookies.txt localhost:8080/logout
curl -i -b /tmp/cookies.txt localhost:8080/me
```

`/tmp/cookies.txt`の中身も見る。ブラウザが送っているものの実体はこれだけで、サーバ側に状態がある限りこの文字列自体には何の意味もない — この「無意味な参照キー」という性質が、次章のJWT(意味を持つ自己完結トークン)との対比になる。
