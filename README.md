# BOLA / IDOR / JWT / セッションハイジャック 実験ハンズオン(セキュリティ講座)

REST APIによくある4つの認証・認可の壊れ方を、実際に動くGoサーバへの**攻撃**を通じて理解する。目的は実装力ではなく、「何を確認すべきで、実際は何が確認できていなかったか」を体に入れること。

## 前提

- HTTP/REST、JSONの基礎は習得済み
- Go, curlが使える環境
- 自分のPC上で自分が起動したローカルサーバ(`localhost:8080`)以外には攻撃コードを向けない

## 全体像

| # | サーバ | 学ぶこと |
|---|--------|----------|
| 0 | `cmd/stage0-bola` | BOLA: 対象オブジェクトの所有者チェック漏れ |
| 1 | `cmd/stage1-idor` | IDOR: 認可の根拠にクライアント入力を使ってしまう |
| 2 | `cmd/stage2-session-hijack` | セッション固定によるハイジャック |
| 3 | `cmd/stage3-jwt-alg-none` | JWTの構造、`alg:none`偽造 |
| 4 | `cmd/stage4-jwt-weak-secret` | 署名鍵の総当たり攻撃 |
| 5 | `cmd/stage5-jwt-alg-confusion` | RS256/HS256混同攻撃 |
| 6 | `cmd/stage6-access-control-secure` | BOLA・IDOR・セッション固定の正しい実装 |
| 7 | `cmd/stage7-jwt-secure` | JWTの正しい検証・鍵管理・失効設計 |

各stageは同じ`:8080`で1つずつ起動する(複数同時起動しない)。`internal/userstore`(アカウント一覧)だけを全stage共通にし、それ以外は`cmd/stageN.../main.go`1本に発行・検証・HTTPハンドラを全部書いている — ファイルを跨がず上から下に読めば追える構成にしてある。JWT攻撃には`tools/forge`(トークン偽造)と`tools/bruteforce`(鍵の総当たり)を使う。

## 進め方(目安 約4時間)

1. `docs/00_bola.md` — BOLA(30分)
2. `docs/01_idor.md` — IDOR(30分)
3. `docs/02_session_hijack.md` — セッション固定(30分)
4. `docs/03_jwt_structure.md` — JWTの構造(30分)
5. `docs/04_jwt_alg_none.md` — 攻撃: alg:none偽造(25分)
6. `docs/05_jwt_weak_secret.md` — 攻撃: 鍵の総当たり(25分)
7. `docs/06_jwt_alg_confusion.md` — 攻撃: RS256/HS256混同(25分)
8. `docs/07_access_control_defense.md` — BOLA・IDOR・セッション固定の対策(25分)
9. `docs/08_jwt_defense.md` — JWTの対策(25分)
10. `docs/09_wrapup.md` — まとめ(10分)

## 起動方法

```
go run ./cmd/stage0-bola
```

起動したまま別ターミナルで`curl`や`tools/forge`, `tools/bruteforce`を実行する。次のstageに進むときは`Ctrl+C`で止めてから次のコマンド(`go run ./cmd/stage1-idor`など)を打つ(ポート`8080`は1つのstageしか使えない)。
