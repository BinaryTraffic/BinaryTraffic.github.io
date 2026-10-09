# smkn apps（アプリ一覧ハブ）

https://git.smkn.net/ で公開している、作成したアプリの一覧ページです。  
GitHub Pages のユーザーサイトとして動作し、**WebAuthn（パスキー）による生体認証**を搭載しています。

## 🔐 認証システム

Cloudflare Workers + D1 による自己ホスト型のパスキー認証システムです。

- **パスキー（WebAuthn）**: Face ID、Windows Hello、デバイス生体認証
- **Discoverable credentials**: ユーザー名入力不要
- **複数デバイス対応**: ログイン後に追加のパスキーを登録可能
- **セキュアなセッション**: HttpOnly + Secure Cookie（30日間有効）

## 📁 ファイル構成

```
.
├── index.html          # 公開トップページ
├── login.html          # ログインページ（パスキー認証）
├── register.html       # 新規登録ページ（セットアップコード必須）
├── hub.html            # 認証後のアプリ一覧ページ（保護）
├── apps.json           # 掲載するアプリのリスト
├── CNAME               # 独自ドメイン git.smkn.net
├── .nojekyll           # Jekyll 無効化
├── worker/             # Cloudflare Worker（認証 API）
│   ├── src/
│   │   └── index.ts    # Worker メインコード
│   ├── migrations/
│   │   └── 0001_initial_schema.sql  # D1 データベーススキーマ
│   ├── package.json
│   ├── tsconfig.json
│   └── wrangler.toml   # Cloudflare 設定
└── .github/workflows/
    └── deploy-worker.yml  # GitHub Actions（Worker 自動デプロイ）
```

## 🚀 初回セットアップ（必須）

### 1. Cloudflare D1 データベースを作成

```bash
cd worker
npm install

# D1 データベースを作成
wrangler d1 create git-smkn-auth
```

出力された `database_id` をコピーして、`wrangler.toml` の `database_id` を更新してください。

```toml
[[d1_databases]]
binding = "DB"
database_name = "git-smkn-auth"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # ここに貼り付け
```

### 2. マイグレーションを適用

```bash
# 本番環境にマイグレーション適用
wrangler d1 migrations apply git-smkn-auth

# ローカル開発用（オプション）
wrangler d1 migrations apply git-smkn-auth --local
```

### 3. セットアップコードを設定

新規ユーザー登録時に必要なセットアップコード（パスワード）を設定します。

```bash
# シークレットを設定（プロンプトが表示されます）
wrangler secret put SETUP_CODE

# 入力例: my-secure-setup-code-2024
```

このコードは新規登録時に必要になります。**必ず安全な場所に保管してください。**

### 4. Worker をデプロイ

```bash
wrangler deploy
```

デプロイが成功すると、Worker の URL が表示されます（例: `https://git-smkn-auth.your-subdomain.workers.dev`）

### 5. Cloudflare でルーティングを設定

#### 方法A: Dashboard から設定（推奨）

1. Cloudflare Dashboard → `smkn.net` ゾーンを開く
2. **DNS** → `git` レコードを探す（現在: `CNAME binarytraffic.github.io`）
3. **Proxy status** を **Proxied**（オレンジの雲）に変更
   - これにより Cloudflare が git.smkn.net をプロキシします
   - GitHub Pages の証明書ではなく Cloudflare の証明書を使用します
4. **Workers Routes** → **Add route**
   - Route: `git.smkn.net/api/*`
   - Service: `git-smkn-auth`（デプロイした Worker 名）
   - Zone: `smkn.net`
5. 保存

#### 方法B: wrangler.toml で設定

`wrangler.toml` に以下を追加:

```toml
routes = [
  { pattern = "git.smkn.net/api/*", zone_name = "smkn.net" }
]
```

そして再デプロイ:

```bash
wrangler deploy
```

### 6. 動作確認

1. https://git.smkn.net/register.html にアクセス
2. ユーザー名とセットアップコードを入力
3. 「パスキーを登録」をクリック → Face ID / Windows Hello で登録
4. ログイン後、https://git.smkn.net/hub.html にリダイレクト
5. 「デバイスを追加」で別のデバイスからもログイン可能に

## 🤖 GitHub Actions による自動デプロイ（オプション）

Worker の変更を `main` ブランチに push すると自動的にデプロイされます。

### 設定手順

1. Cloudflare API Token を作成
   - Cloudflare Dashboard → **My Profile** → **API Tokens** → **Create Token**
   - Template: **Edit Cloudflare Workers**
   - Zone Resources: `smkn.net` を含める
   - Account Resources: アカウント全体を含める
   - 作成後、トークンをコピー

2. GitHub リポジトリシークレットを設定
   - このリポジトリ → **Settings** → **Secrets and variables** → **Actions**
   - **New repository secret** で以下を追加:
     - `CLOUDFLARE_API_TOKEN`: 先ほど作成した API Token
     - `CLOUDFLARE_ACCOUNT_ID`: Cloudflare の Account ID（Dashboard の右サイドバーに表示）

3. Worker コードを編集して push

```bash
# worker/ 内のコードを編集
git add worker/
git commit -m "Update worker"
git push origin main

# GitHub Actions が自動的にデプロイ
```

## 🔧 ローカル開発

```bash
cd worker

# ローカルで Worker を起動
npm run dev

# 別のターミナルで、ルートディレクトリで HTTP サーバーを起動
cd ..
python3 -m http.server 8000
```

ブラウザで http://localhost:8000 を開いて動作確認できます。  
API は http://localhost:8787/api/* でアクセスできます（wrangler dev のデフォルトポート）。

## 🎨 アプリを追加する方法

1. アプリ用のリポジトリ（例: `my-app`）を作り、Settings → Pages で公開
   - `Deploy from a branch` → `main` / `(root)`
   - 自動的に `https://git.smkn.net/my-app/` で公開されます

2. このリポジトリの `apps.json` に追加:

```json
[
  {
    "name": "My App",
    "description": "アプリの短い説明",
    "url": "/my-app/",
    "icon": "🚀",
    "tags": ["ツール"]
  }
]
```

3. コミットして `main` に push → 1〜2 分で反映

## 📝 データベーススキーマ

D1 データベースには以下のテーブルがあります:

### `users`
| カラム | 型 | 説明 |
| --- | --- | --- |
| id | TEXT | ユーザー ID (UUID) |
| username | TEXT | ユーザー名（一意） |
| created_at | INTEGER | 作成日時（Unix timestamp） |

### `credentials`
| カラム | 型 | 説明 |
| --- | --- | --- |
| id | TEXT | 認証情報 ID (UUID) |
| user_id | TEXT | ユーザー ID（外部キー） |
| credential_id | TEXT | WebAuthn Credential ID（一意） |
| public_key | TEXT | 公開鍵（Base64） |
| counter | INTEGER | 署名カウンター |
| transports | TEXT | サポートされているトランスポート（JSON） |
| created_at | INTEGER | 作成日時 |

### `challenges`
| カラム | 型 | 説明 |
| --- | --- | --- |
| challenge | TEXT | WebAuthn チャレンジ（主キー） |
| user_id | TEXT | ユーザー ID（登録時のみ） |
| expires_at | INTEGER | 有効期限（5分） |

### `sessions`
| カラム | 型 | 説明 |
| --- | --- | --- |
| session_id | TEXT | セッション ID（主キー） |
| user_id | TEXT | ユーザー ID（外部キー） |
| expires_at | INTEGER | 有効期限（30日） |

## 🔒 セキュリティ

- **パスキー**: FIDO2/WebAuthn 標準準拠、フィッシング耐性あり
- **RP ID**: `git.smkn.net` （または `smkn.net` でも動作可能）
- **Origin**: `https://git.smkn.net` （HTTPS 必須）
- **User Verification**: Required（生体認証または PIN が必須）
- **Discoverable Credentials**: Required（パスワードレスログイン）
- **Session Cookie**: HttpOnly + Secure + SameSite=Lax
- **セットアップコード**: Worker Secret として保管（環境変数非公開）

## ⚠️ 重要な注意事項

### DNS プロキシ設定

- `git.smkn.net` を **Proxied**（オレンジの雲）に変更すると、GitHub Pages の証明書は使用されなくなります
- 代わりに Cloudflare の証明書（Universal SSL）が使用されます
- **Cloudflare の SSL/TLS 設定は「Full」または「Full (strict)」にしてください**
- DNS only（グレーの雲）のままでは `/api/*` ルーティングが動作しません

### Worker コストについて

- **Cloudflare Workers 無料枠**: 1日 100,000 リクエストまで無料
- **D1 無料枠**: 5 GB ストレージ、500万行読み込み/日、10万行書き込み/日
- 個人用途では十分なスペックです

### セキュリティベストプラクティス

- **SETUP_CODE は絶対に公開しないでください**（Git にコミットしない）
- 定期的にセッションをローテーションする場合は、D1 の `sessions` テーブルを手動でクリーンアップ
- 本番環境では wrangler.toml の `database_id` を環境変数化することを推奨

## 🆘 トラブルシューティング

### 「認証が必要です」エラー

→ Cookie が設定されていない可能性があります。ブラウザの開発者ツールで Cookie を確認してください。

### パスキー登録ができない

→ HTTPS でアクセスしているか確認（`http://` ではパスキーは動作しません）  
→ RP ID が `git.smkn.net` と一致しているか確認

### /api/* が 404 エラー

→ Cloudflare Workers Routes が正しく設定されているか確認  
→ `git.smkn.net` が Proxied（オレンジの雲）になっているか確認

### D1 マイグレーションエラー

```bash
# マイグレーションの状態を確認
wrangler d1 migrations list git-smkn-auth

# 強制的に再適用（注意: データが失われる可能性があります）
wrangler d1 execute git-smkn-auth --file=migrations/0001_initial_schema.sql
```

### GitHub Actions がデプロイに失敗

→ `CLOUDFLARE_API_TOKEN` と `CLOUDFLARE_ACCOUNT_ID` が正しく設定されているか確認  
→ API Token に必要な権限があるか確認（Workers の Edit 権限）

## 📚 参考リンク

- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)
- [Cloudflare D1 Database](https://developers.cloudflare.com/d1/)
- [SimpleWebAuthn Documentation](https://simplewebauthn.dev/)
- [WebAuthn Guide](https://webauthn.guide/)
- [GitHub Pages カスタムドメイン設定](https://docs.github.com/ja/pages/configuring-a-custom-domain-for-your-github-pages-site)

---

© 2024 smkn
