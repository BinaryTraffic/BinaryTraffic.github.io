// Clerk 認証設定
// 
// セットアップ手順:
// 1. https://clerk.com でアカウントを作成
// 2. 新しいアプリケーションを作成
// 3. Dashboard → API Keys から Publishable key をコピー
// 4. 下記の YOUR_PUBLISHABLE_KEY_HERE を置き換え
// 5. Dashboard → Settings で Allowed origins に https://git.smkn.net を追加

window.CLERK_CONFIG = {
  publishableKey: 'pk_test_ZmVhc2libGUtc2VhZ3VsbC04NTEzLmNsZXJrLmFjY291bnRzLmRldiQ',
  frontendApi: 'feasible-seagull-8513.clerk.accounts.dev'
};

// 認証設定完了
