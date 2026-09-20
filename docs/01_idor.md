# 01. IDOR (Insecure Direct Object Reference)

`stage0`を止め、`stage1-idor`を起動する。

```
go run ./cmd/stage1-idor
```

## 理論

`cmd/stage1-idor/main.go`の`handleInvoices`を見る。00章のBOLAとはバグの場所が違う。

```go
if _, ok := currentSession(r); !ok { ... }        // ログインだけは確認する
target := r.URL.Query().Get("user")               // バグ: 対象をクライアントの入力から決めている
```

ログインしているかどうかのチェックはある。しかし「誰の請求書を返すか」を、セッションに紐づく本人(`s.Username`)からではなく、**リクエストが送ってきた`user`パラメータ**から決めている。ログインという関所を通った後、身分証をもう一度クライアントに聞き直しているようなもの — クライアントは自分の身分証の代わりに他人の名前を書ける。

BOLA(00章)は「対象オブジェクトの所有者チェックを忘れた」。IDORはより一般的な形で、**「本人確認の結果(セッション)を無視して、クライアントが渡した識別子をそのまま信用した」**。表示用パラメータ、隠しフィールド、APIのuser_id/account_idなど、どんな形でも起こる。

## 攻撃

`alice`としてログインする。

```
curl -c /tmp/alice.txt -X POST localhost:8080/login \
  -d '{"Username":"alice","Password":"password123"}'
```

自分の請求書は見える。

```
curl -b /tmp/alice.txt "localhost:8080/invoices?user=alice"
```

`user`パラメータを`bob`に変えるだけで、bobの請求書(合計10万円超)が同じセッションのまま見える。

```
curl -i -b /tmp/alice.txt "localhost:8080/invoices?user=bob"
```

## 何が起きたか

「ログイン必須」を実装しても、**その後の処理でセッションの本人を実際に使っているか**は別問題。認証状態はあるのに、認可判定の入力として使われていない。修正(07章)は単純 — クライアントからの`user`パラメータを完全に無視し、常にセッションの本人だけを使う。
