# AGENTS.md

## プロジェクト概要

このプロジェクトは、ローカルデスクトップGUIアプリケーション向けの **APIキー等の機密情報を安全に管理する仕組み** を構築するための実験・実装リポジトリです。

当初は単純な難読化（XOR + 固定シードの擬似乱数）のサンプルとして作成されましたが、現在は本格的な暗号化ベースのローカルVault機能へと移行・拡張を進めています。

## 目的

- APIキー等の機密情報を、PIN入力を条件に安全に暗号化/復号する
- OSが提供するセキュアストレージを優先的に利用する
- OSセキュアストレージが利用できない環境では、暗号化ファイルによるフォールバックを提供する
- 1Password API を使った外部キー保存も選択肢として残す
- アプリ本体はQtだが、APIキー管理機能（Vaultモジュール）の Qt 依存は `QtCore` のみに抑える

## 技術的制約

- GUIフレームワーク: Qt（継続）
- APIキー管理機能の Qt 依存: `QtCore` のみ
  - `QByteArray`, `QCryptographicHash`, `QFile`, `QSaveFile` 等は使用可能
  - `QtGui`, `QtWidgets` への依存は GUI レイヤーに限定
- 暗号化アルゴリズム: libsodium の XChaCha20-Poly1305（AEAD）
- 鍵導出: libsodium の Argon2id（opslimit 3、memlimit 64 MiB）
- 乱数・安全な消去・メモリロック: libsodium
- 対象プラットフォーム: Linux, macOS, Windows（マルチプラットフォーム対応）

## 現状のコード

### 既存ファイル

| ファイル | 内容 |
|---|---|
| `main.cpp` | 自己テスト用エントリーポイント、およびGUIデモ |
| `vault/SecureBuffer.h/cpp` | libsodiumの安全な消去・メモリロックを使用する機密メモリコンテナ |
| `vault/SecretStorage.h` | セキュアストレージバックエンド I/F（Phase 2 で追加） |
| `vault/Vault.h/cpp` | Argon2id / XChaCha20-Poly1305を用いる2段階鍵体系Vaultコア |
| `storage/FileBackend.h/cpp` | ファイルベースフォールバックバックエンド（Phase 2 で追加） |
| `storage/SystemKeychainBackend.h/cpp` | OSセキュアストレージバックエンド（Phase 3 で追加） |
| `gui/PinDialog.h/cpp` | PIN入力ダイアログ（Phase 4 で追加） |
| `localvault.pro` | Qt qmake プロジェクトファイル。`QT += core widgets` |

### 実装済みフェーズ

- **Phase 1**: 暗号化基盤（SecureBuffer）
- **Phase 2**: Vault コア + FileBackend
- **Phase 3**: SystemKeychainBackend（Linux libsecret / macOS Keychain / Windows DPAPI）
- **Phase 4**: PIN 入力ダイアログ + GUI デモ統合
- **Phase 5**: libsodiumを導入し、Argon2id / XChaCha20-Poly1305へ移行。EMK形式のバージョン化、`decryptToSecureBuffer()`、ロック済みバッファの再配置防止を追加

### 既知の課題

- 旧難読化・独自暗号プリミティブは削除済み。新規の機密データ保存はVault APIのみを使用する

## 推奨アーキテクチャ

### 鍵体系

```
┌─────────┐  Argon2id + salt  ┌─────┐
│   PIN   │ ─────────────────> │ KEK │
└─────────┘                    └─────┘
                                   │
┌─────────┐ XChaCha20-Poly1305    ▼
│    MK   │ <──────────────────  EMK
│(random) │                    (secure storage)
└────┬────┘
     │ XChaCha20-Poly1305
     ▼
[encrypted data file]
```

- **MK（Master Key）**: ランダムに生成された 256bit 鍵。実際の機密データを暗号化する
- **KEK（Key Encryption Key）**: PINからArgon2idで導出される32 byte鍵
- **EMK（Encrypted Master Key）**: KEKでXChaCha20-Poly1305認証付き暗号化されたMK
- EMK はセキュアストレージバックエンドに保存する
- PIN 変更時は EMK のみ再暗号化すればよく、全データの再暗号化は不要

### レイヤー構成

```
┌─────────────────────────────────────┐
│ GUI Layer (QtWidgets)               │
│  - PIN入力ダイアログ                  │
│  - Vaultの操作を呼び出す              │
├─────────────────────────────────────┤
│ Application Layer                   │
│  - Vault API                        │
├─────────────────────────────────────┤
│ Core Vault Module (QtCore only)     │
│  - SecureBuffer                     │
│  - libsodium (Argon2id / AEAD)      │
│  - SecureBuffer                     │
├─────────────────────────────────────┤
│ Storage Backends (QtCore only)      │
│  - SystemKeychainBackend            │
│  - OnePasswordBackend               │
│  - FileBackend (fallback)           │
└─────────────────────────────────────┘
```

## 実装計画

### Phase 1: 暗号化基盤の整備

1. **SecureBuffer の実装**
   - `std::vector<uint8_t>` ベースのセキュアメモリコンテナ
   - 解放時に確実にゼロクリア（`sodium_memzero`/`SecureZeroMemory`/`memset_s` のような処理）
   - 可能であれば `mlock` / `VirtualLock` でメモリロック
   - Qt 依存なし

2. **AEAD / KDF の実装**
   - libsodiumのArgon2idとXChaCha20-Poly1305を使用する
   - 自作の暗号合成・タグ比較を行わない

### Phase 2: Vault コアの実装

1. **Vault クラスの設計・実装**
   - 2段階鍵体系（MK / KEK / EMK）を実装
   - 以下の API を提供
     - `bool setup(const SecureBuffer &pin)` — 初回セットアップ
     - `bool unlock(const SecureBuffer &pin)` — PIN で Vault を解除
     - `void lock()` — メモリ上の MK を消去
     - `QByteArray encrypt(const QByteArray &plain)` — データ暗号化
     - `SecureBuffer decryptToSecureBuffer(const QByteArray &cipher)` — 推奨のデータ復号API
     - `QByteArray decrypt(const QByteArray &cipher)` — 互換用。平文コピーを生成するため新規コードでは避ける
     - `bool changePin(const SecureBuffer &oldPin, const SecureBuffer &newPin)` — PIN変更
     - `bool reset(const SecureBuffer &newPin)` — 既存EMKを破棄して再セットアップする不可逆操作
   - QtCore のみ

2. **セキュアストレージバックエンドの抽象インターフェース**
   - `ISecretStorageBackend` を定義
   - QtCore のみ

### Phase 3: ストレージバックエンドの実装

1. **SystemKeychainBackend**
   - Linux: libsecret（Secret Service API）
   - macOS: Keychain Services（Security.framework）
   - Windows: DPAPI（`CryptProtectData` / `CryptUnprotectData`）
   - プラットフォーム判定は `Q_OS_LINUX`, `Q_OS_MACOS`, `Q_OS_WIN` を使用

2. **OnePasswordBackend**
   - 1Password API を利用して EMK を外部保存
   - 既存の実験コードを統合

3. **FileBackend**
   - OSセキュアストレージが使えない環境のフォールバック
   - EMK をファイルに保存し、パーミッション `0600` を設定
   - `QSaveFile` 等を使用して安全に書き込み

### Phase 4: GUI とアプリケーション統合

1. **PIN 入力ダイアログ**
   - `QtWidgets` を使用
   - Vault モジュールから分離し、必要に応じて `SecureBuffer` として PIN を渡す

2. **main.cpp の更新**
   - 旧 `localvault` モジュールの呼び出しを新しい `Vault` API に置き換え
   - または、テスト用のエントリーポイントとして残す

3. **旧モジュールの整理**
   - 旧難読化・独自暗号プリミティブは削除済み

### Phase 5: ビルド設定とテスト

1. **localvault.pro の更新**
   - `QT += core` を維持
   - プラットフォーム別のライブラリを追加
   - 新しいソースファイルを追加

2. **テストの追加**
   - 暗号化/復号のラウンドトリップテスト
   - 各バックエンドの store/load/remove テスト
   - PIN 変更後の復号テスト
   - 改ざんデータの検出テスト

3. **ドキュメントの更新**
   - 本ファイルの内容を都度更新
   - 必要に応じて README を作成

## 想定するファイル構成

```
localvault/
├── AGENTS.md                           # 本ファイル
├── .gitignore
├── localvault.pro                     # Qt qmake プロジェクト
├── main.cpp                            # アプリエントリーポイント
├── vault/                              # QtCore のみのVaultコア
│   ├── SecureBuffer.h/cpp
│   ├── Vault.h/cpp
│   └── SecretStorage.h
├── storage/                            # ストレージバックエンド
│   ├── FileBackend.h/cpp               # Phase 2 で追加
│   ├── SystemKeychainBackend.h/cpp     # Phase 3 で追加
│   └── OnePasswordBackend.h/cpp        # 未実装
├── gui/                                # GUIレイヤー（QtWidgets）
│   └── PinDialog.h/cpp                 # Phase 4 で追加
└── tests/                              # テスト（必要に応じて）
```

## ビルド手順

### 前提

- Qt 6（または Qt 5.12 以上）とlibsodium開発ファイルがインストールされていること
- 各プラットフォームの開発ツールが整っていること

### Linux

libsecret 等の開発ファイルが必要な場合があります。

```bash
# Ubuntu/Debian の例
sudo apt-get install libsodium-dev libsecret-1-dev libglib2.0-dev

# ビルド
qmake localvault.pro
make

# 既存Vaultを削除（不可逆）
./localvault --reset --yes
```

### macOS

```bash
qmake localvault.pro
make
```

### Windows

```bash
qmake localvault.pro
nmake  # または mingw32-make
```

## セキュリティ上の注意

- Vaultの新規データはXChaCha20-Poly1305 AEADで保護される。独自のChaCha20/HMAC合成を新規実装で使用しないこと
- Argon2idのコストはEMKヘッダに記録する。ヘッダ改ざんによる過大なメモリ・CPU消費を避けるため、実装は受入上限を設けている
- 形式は `VLT2` / version 2。試作版のversion 1のEMK・暗号文には互換性がない
- Vaultのリセットは既存MKを失わせ、旧暗号文を復号不能にする。GUIでは確認・新PIN入力を必須とし、CLIでは`--reset --yes`を必須とする
- 復号後の機密情報（APIキー等）は `SecureBuffer` で管理し、使用後は即座に消去すること
- スワップファイルへの漏洩を防ぐため、可能な限りメモリロックを行うこと
- OSセキュアストレージが利用できない場合の `FileBackend` は、あくまで最後の手段として位置づけること

## 今後の検討事項

- 生体認証（Touch ID / Windows Hello）との統合
- ハードウェアセキュリティモジュール（TPM / Secure Enclave）の活用
- タイムベースな暗号化鍵ローテーション
- 監査ログの記録

## 参考

- [RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439)
- [RFC 8018 - PKCS #5: Password-Based Cryptography Specification Version 2.1](https://tools.ietf.org/html/rfc8018)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
