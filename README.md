# lambda-for-codeflow

## デプロイ手順

### 前提条件
- AWS CLI がインストール・設定済み
- SAM CLI がインストール済み

### デプロイ

```bash
# ビルド
sam build

# デプロイ
sam deploy --guided
```

初回デプロイ時は `--guided` オプションで設定を行い、以降は以下のコマンドでデプロイできます：

```bash
sam deploy
```