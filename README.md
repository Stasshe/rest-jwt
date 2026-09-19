# REST × JWT 徹底理解ハンズオン(セキュリティ講座)

REST APIの認証をセッションCookieからJWTへ置き換える過程を、実際に動くGoサーバへの**攻撃**を通じて理解する。目的は実装力ではなく、「JWTが中で何をしていて、どこが壊れると何が起きるか」を体に入れること。

## 前提

- TCP/HTTPの基礎は習得済み(このハンズオンはHTTPリクエスト/レスポンスの中身から始まる)
- Go, curlが使える環境
- 自分のPC上で自分が起動したローカルサーバ(`localhost:8080`)以外には攻撃コードを向けない

## 全体像

| # | サーバ | 学ぶこと |
|---|--------|----------|
| 1 | `cmd/stage1-session` | RESTのメソッド/ステータスコード、Cookieセッション認証 |
| 2 | `cmd/stage2-jwt-alg-none` | JWTの構造、`alg:none`偽造 |
| 3 | `cmd/stage3-jwt-weak-secret` | 署名鍵の総当たり攻撃 |
| 4 | `cmd/stage4-jwt-alg-confusion` | RS256/HS256混同攻撃 |
| 5 | `cmd/stage5-jwt-secure` | 正しい検証・鍵管理・失効設計 |

各stageは同じ`:8080`で1つずつ起動する(複数同時起動しない)。サーバコードはstage間で使い回せる部分を`internal/authserver`に共通化し、stageごとの違いは`internal/*codec`の検証ロジック1点に絞ってある。攻撃には`tools/forge`(トークン偽造)と`tools/bruteforce`(鍵の総当たり)を使う。

## 進め方(目安 約4時間20分)

1. `docs/01_rest.md` — RESTの仕組みとフロー(40分)
2. `docs/02_cookie_session.md` — Cookieセッション認証(40分)
3. `docs/03_jwt_structure.md` — JWTの構造(30分)
4. `docs/04_jwt_naive.md` — JWT認証サーバを動かす(20分)
5. `docs/05_attack_alg_none.md` — 攻撃1: alg:none偽造(30分)
6. `docs/06_attack_weak_secret.md` — 攻撃2: 鍵の総当たり(30分)
7. `docs/07_attack_alg_confusion.md` — 攻撃3: RS256/HS256混同(30分)
8. `docs/08_defense.md` — 正しい実装と設計判断(40分)
9. `docs/09_wrapup.md` — まとめ(10分)

## 起動方法

```
go run ./cmd/stage1-session
```

起動したまま別ターミナルで`curl`や`tools/forge`を実行する。次のstageに進むときは`Ctrl+C`で止めてから次のコマンドを打つ(ポート`8080`は1つのstageしか使えない)。
