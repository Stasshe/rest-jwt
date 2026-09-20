# 07. 正しい実装: BOLA・IDOR・セッション固定への対策

`stage5`を止め、`stage6-access-control-secure`を起動する。

```
go run ./cmd/stage6-access-control-secure
```

`cmd/stage6-access-control-secure/main.go`を開きながら読む。00〜02章の3つの攻撃は、実は直し方が2箇所に集まる。

## 直っている点

**1. ログインごとにセッションIDを常に再発行する(02章の固定攻撃への対策)**

```go
id := newSessionID() // 常に新規発行。クライアントが送ってきたIDは見ない。
```

02章のバグは「クライアントが送ってきたIDをそのまま使い回す」ことだった。ここでは`r.Cookie("session_id")`を一切読まず、ログイン成功のたびに無条件で新しいランダムIDを発行する。攻撃者が事前に知っているIDを被害者に持たせても、ログインした瞬間そのIDは捨てられ、無関係な新しいIDに置き換わる。

**2. 対象オブジェクトのOwnerと本人を必ず比較する(00章のBOLAへの対策)**

```go
if !ok || o.Owner != s.Username {
    writeJSON(w, http.StatusNotFound, ...)
    return
}
```

`handleGetOrder`, `handleReplaceOrder`, `handleDeleteOrder`の3つとも、セッションの本人確認だけでなく**この操作対象が本人のものか**を毎回チェックしている。見つからない場合と権限が無い場合を同じ404で返しているのは、「そのIDの注文が存在すること自体」を他人に教えないための意図的な選択(401 vs 403 vs 404の判断は`docs`の他章で触れた通り、正解が一つに決まる話ではない)。

**3. クライアントの入力ではなく本人を認可の根拠にする(01章のIDORへの対策)**

```go
func handleInvoices(w http.ResponseWriter, r *http.Request, s session) {
    for _, inv := range invoices {
        if inv.Owner == s.Username { // クエリパラメータuserは受け取っていない
```

01章のサーバは`r.URL.Query().Get("user")`を対象決定に使っていた。このハンドラはそのパラメータ自体を受け取らない — 認可の根拠になり得るのはセッション由来の値だけ、という原則をルーティングの形で強制している。

## 3つの攻撃が通らないことを確認する

```
# 00章と同じBOLA攻撃
curl -c /tmp/alice.txt -X POST localhost:8080/login \
  -d '{"Username":"alice","Password":"password123"}'
curl -i -b /tmp/alice.txt localhost:8080/orders/1002   # 404になるはず

# 01章と同じIDOR攻撃(そもそもuserパラメータを受け取らない)
curl -b /tmp/alice.txt "localhost:8080/invoices?user=bob"   # aliceの請求書だけが返る

# 02章と同じセッション固定攻撃
FIXED=deadbeefdeadbeef
curl -c /tmp/victim.txt -b "session_id=$FIXED" -X POST localhost:8080/login \
  -d '{"Username":"alice","Password":"password123"}'
curl -i -b "session_id=$FIXED" localhost:8080/orders/1001   # 401になるはず(IDは捨てられている)
```

## 一般化できる原則

3つの攻撃は表面上別物に見えたが、直し方は結局2つの問いに集約される。

- **このリクエストは誰からのものか、を毎回サーバ自身が決め直しているか**(クライアントの入力を信用していないか)
- **その「誰か」が、対象オブジェクトに対して権限を持っているか、を毎回確認しているか**

認証(誰か)と認可(その対象への権限)を別工程として毎回両方通す、という一点に尽きる。
