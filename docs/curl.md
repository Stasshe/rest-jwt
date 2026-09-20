# curl オプション早見

`docs/` で使っているオプションだけを扱う。

| オプション | 役割 | 使用章 |
|---|---|---|
| `-v` | リクエスト/レスポンスの生のやり取りを全部表示 | 01, 02 |
| `-i` | レスポンスヘッダをbodyの前に表示 | 01, 02, 04〜08 |
| `-s` | 進捗・エラー表示を消す | 07 |
| `-o FILE` | レスポンスbodyをファイルに保存 | 07 |
| `-X METHOD` | HTTPメソッドを指定 | 01, 02, 03, 04, 06 |
| `-d DATA` | リクエストbodyを送る | 01, 02, 03, 04, 06 |
| `-c FILE` | 受け取った Cookie をファイルに保存 | 02, 03, 04, 06 |
| `-b FILE\|STR` / `--cookie` | Cookie を送る | 02, 04, 05〜08 |

## 表示系

### `-v` (`--verbose`)

通信の全体を標準エラーに出す。行頭の記号で区別する。

- `*` 接続情報 (接続先、接続成功など)
- `>` 送ったリクエスト (リクエスト行 + ヘッダ)
- `<` 受け取ったレスポンス (ステータス行 + ヘッダ)

bodyは通常どおり標準出力に出る。1往復の中身を観察したいときに使う。

### `-i` (`--include`)

レスポンスのステータス行とヘッダを、bodyの前に標準出力へ含める。ステータスコードと `Location` `Set-Cookie` を見たいときに使う。`-v` と違い、送ったリクエスト側は出ない。

### `-s` (`--silent`)

進捗メーターとエラーメッセージを出さない。`-o` でファイルに保存するとき、進捗表示が混ざらないようにするために使う。

### `-o FILE` (`--output`)

レスポンスbodyを標準出力ではなく `FILE` に書く。

```bash
curl -s localhost:8080/pubkey -o /tmp/pubkey.pem
```

## リクエスト系

### `-X METHOD` (`--request`)

HTTPメソッドを上書きする。`-d` を付けると自動で `POST` になるので、`POST` では省略できる。この教材では、`PUT` `DELETE` で必要になる。`POST` は、メソッドを明示して読みやすくするために付けている。

```bash
curl -i -X DELETE localhost:8080/items/1
```

### `-d DATA` (`--data`)

`DATA` をリクエストbodyとして送る。メソッドは `POST` になり、`Content-Type` は明示しない限り `application/x-www-form-urlencoded` になる。

この教材のサーバは `Content-Type` を見ずにbodyをJSONとして読むため、`-H 'Content-Type: application/json'` なしで動く。JSONを送る本来の書き方は `-H` を付ける。

```bash
curl -X POST localhost:8080/items -d '{"Name":"widget"}'
```

## Cookie系

### `-c FILE` (`--cookie-jar`)

レスポンスの `Set-Cookie` を `FILE` (cookie jar) に書き出す。ログインで発行されたトークンを保存する用途。

形式は Netscape 形式のタブ区切り。1行1Cookieで、7列目が値。`HttpOnly` のCookieは行頭に `#HttpOnly_` が付くが、`grep access_token` にはそのまま一致する。

```bash
curl -c /tmp/cookies.txt -X POST localhost:8080/login -d '{"Username":"alice","Password":"password123"}'
grep access_token /tmp/cookies.txt | awk '{print $7}'   # トークンの値
```

### `-b FILE|STR` (`--cookie`)

リクエストに `Cookie` ヘッダを付ける。引数の形で挙動が分かれる。

- `=` を含まない → cookie jar ファイル名として読み、該当するCookieを送る (`-b /tmp/cookies.txt`)
- `=` を含む → `name=value` をそのまま `Cookie` ヘッダに入れる (`--cookie "access_token=$TOKEN"`)

前者は `-c` で保存した本物のセッションを再利用する使い方、後者は偽造したトークンを直接差し込む攻撃の使い方 (5〜8章)。

## 組み合わせの読み方

```bash
curl -v -c /tmp/cookies.txt -X POST localhost:8080/login \
  -d '{"Username":"alice","Password":"password123"}'
```

- `-v` 通信全体を見る
- `-c` 発行されたCookieを保存する
- `-X POST` `-d` ログイン情報をbodyに入れて送る

なお `\` はシェルの行継続で、curl のオプションではない。
