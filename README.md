# Local Vault

ローカルデスクトップGUIアプリケーション向けの、APIキー等の機密情報を安全に管理するための実装サンプルです。

単純な難読化（XOR + 固定シード）から脱却し、libsodium の XChaCha20-Poly1305 AEAD と Argon2id を用いた暗号化ベースの Vault 機能へ移行・拡張したものです。

## 目的

- APIキー等の機密情報を、PIN入力を条件に安全に暗号化/復号する
- OSが提供するセキュアストレージを優先的に利用する
- OSセキュアストレージが利用できない環境では、暗号化ファイルによるフォールバックを提供する
- Vault コアは QtCore のみに依存し、GUI 部分は QtWidgets に限定する

## アーキテクチャ

### 2段階鍵体系

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

- **MK（Master Key）**: ランダム 256bit。実際の機密データを暗号化
- **KEK（Key Encryption Key）**: PIN からArgon2idで導出（opslimit 3、memlimit 64 MiB）
- **EMK（Encrypted Master Key）**: KEK で XChaCha20-Poly1305 により認証付き暗号化された MK。セキュアストレージバックエンドに保存
- PIN 変更時は EMK のみ再暗号化すればよく、全データの再暗号化は不要

### レイヤー構成

```
┌─────────────────────────────────────┐
│ GUI Layer (QtWidgets)               │
│  - PinDialog                          │
├─────────────────────────────────────┤
│ Application Layer                   │
│  - Vault API                          │
├─────────────────────────────────────┤
│ Core Vault Module (QtCore only)     │
│  - SecureBuffer, libsodium             │
├─────────────────────────────────────┤
│ Storage Backends (QtCore only)      │
│  - SystemKeychainBackend              │
│  - FileBackend (fallback)             │
└─────────────────────────────────────┘
```

## ファイル構成

```
localvault/
├── AGENTS.md                    # エージェント向け詳細設計書
├── README.md                    # 本ファイル
├── qmake/
│   └── localvault.pro          # Qt qmake プロジェクト
└── src/
    ├── main.cpp                 # テストランナー / GUI デモ
    ├── vault/                   # QtCore のみの Vault コア
    │   ├── SecureBuffer.h/cpp
    │   ├── Vault.h/cpp
    │   └── SecretStorage.h
    ├── storage/                 # ストレージバックエンド
    │   ├── FileBackend.h/cpp
    │   └── SystemKeychainBackend.h/cpp
    └── gui/                     # GUI レイヤー（QtWidgets）
        └── PinDialog.h/cpp
```

## ビルド手順

### 前提

- Qt 5.12 以上、または Qt 6
- libsodium の開発ファイル
- Linux では libsecret / glib の開発ファイル

### Linux

```bash
# Ubuntu/Debian の例
sudo apt-get install libsodium-dev libsecret-1-dev libglib2.0-dev

# ビルド
cd qmake
qmake localvault.pro
make

# テスト実行
./localvault --test

# GUI デモ実行
./localvault

# 既存Vaultを削除（不可逆。次回GUI起動時に再セットアップ）
./localvault --reset --yes
```

### macOS

```bash
cd qmake
qmake localvault.pro
make
```

### Windows

```bash
cd qmake
qmake localvault.pro
nmake  # または mingw32-make
```

## クラスの使い方

### SecureBuffer

機密データを保持するコンテナ。libsodiumで解放時にゼロクリアし、可能であればメモリロックを行う。ロック中は再配置を招く`resize`、`assign`、`append`を拒否する。

```cpp
#include "vault/SecureBuffer.h"

SecureBuffer buf(32);                          // 32バイト確保
std::fill(buf.begin(), buf.end(), 0xab);       // データ書き込み
buf.lock();                                    // スワップ防止（可能な場合）
// ... 使用 ...
buf.clear();                                   // 明示的に消去
```

### Vault

Vault は `ISecretStorageBackend` を通じて EMK を保存する。アプリ側でバックエンドを選択する。

```cpp
#include "storage/SystemKeychainBackend.h"
#include "storage/FileBackend.h"
#include "vault/Vault.h"
#include "vault/SecureBuffer.h"

// バックエンドを選択：OSセキュアストレージ優先、不可ならファイルフォールバック
std::unique_ptr<ISecretStorageBackend> backend;
auto systemBackend = std::make_unique<SystemKeychainBackend>();
if (systemBackend->isAvailable()) {
    backend = std::move(systemBackend);
} else {
    backend = std::make_unique<FileBackend>("/path/to/emk/dir");
}

Vault vault(backend.get(), "my-app-emk");

// 初回セットアップ
SecureBuffer pin;
pin.assign("1234", 4);
if (!vault.isSetup()) {
    vault.setup(pin);
}

// 解除
vault.unlock(pin);

// 機密データの暗号化/復号
QByteArray secret = "API_KEY=sk-1234567890";
QByteArray encrypted = vault.encrypt(secret);
SecureBuffer decrypted = vault.decryptToSecureBuffer(encrypted);

// PIN 変更
SecureBuffer newPin;
newPin.assign("5678", 4);
vault.changePin(pin, newPin);

// 既存Vaultを破棄して新しいPINで再セットアップ（不可逆）
vault.reset(newPin);

// 使用後はロック
vault.lock();
```

### PinDialog

QtWidgets の PIN 入力ダイアログ。Vault から独立しており、`SecureBuffer` で PIN を返す。

```cpp
#include "gui/PinDialog.h"

// セットアップ時（2回入力で確認）
bool ok = false;
SecureBuffer pin = PinDialog::setupPin(parent, &ok);
if (ok) {
    vault.setup(pin);
}

// 解除時
SecureBuffer pin = PinDialog::requestPin(parent, &ok);
if (ok) {
    vault.unlock(pin);
}
```

## 形式と互換性

EMK と暗号文には、magic、形式バージョン、レコード種別、暗号方式、KDF方式・計算/メモリコスト（EMKのみ）を含め、ヘッダ全体をAEADの追加認証データとして保護する。現行形式は `VLT2` / version 2 である。

初期の試作版（ChaCha20 + HMAC、version 1）のEMKおよび暗号文とは互換性がない。試作版のデータを利用している場合は、その版で復号してから本版で再セットアップ・再暗号化すること。新規の`setup()`は既存EMKを上書きしない。

## Vaultのリセット

リセットは既存EMKを削除し、新しいMKでVaultを作り直す不可逆操作である。旧MKで暗号化したデータは復号できなくなるため、必要なデータは先に復号・退避すること。

- GUIでは、既存Vaultを検出した際に「Reset Vault」を選択し、警告確認後に新PINを設定する。
- CLIでは`./localvault --reset --yes`を実行する。CLI操作はEMKを削除し、次の通常起動時にGUIで新規セットアップを行う。`--yes`なしでは何も削除しない。
- アプリケーションコードからは`Vault::reset(const SecureBuffer &newPin)`を使用する。

### バックエンドの直接利用

```cpp
#include "storage/SystemKeychainBackend.h"
#include "storage/FileBackend.h"

SystemKeychainBackend backend;
if (backend.isAvailable()) {
    backend.store("my-key", QByteArray("encrypted-master-key-blob"));
    QByteArray loaded = backend.load("my-key");
    backend.remove("my-key");
}
```

## プラットフォームごとのセキュアストア動作の流れ

### Linux: libsecret（Secret Service API）

```
[Vault]
   │ store(EMK)
   ▼
[SystemKeychainBackend]
   │ Base64 エンコード
   ▼
[libsecret]
   │ D-Bus Secret Service
   ▼
[GNOME Keyring / KDE Wallet / keepassxc-secret-service 等]
```

- `secret_password_store_sync` でデフォルトコレクションに保存
- 属性 `key` を使って項目を識別
- 実行時に `isAvailable()` で Secret Service への接続可否を確認
- デスクトップセッションでキーリングがロックされている場合、保存/読み出しに失敗する

### macOS: Keychain Services

```
[Vault]
   │ store(EMK)
   ▼
[SystemKeychainBackend]
   ▼
[Security.framework]
   │ SecItemAdd / SecItemCopyMatching / SecItemDelete
   ▼
[macOS Keychain]
```

- `kSecClassGenericPassword` として保存
- `kSecAttrService` にアプリ識別子、`kSecAttrAccount` にキー名を使用
- ユーザーがキーチェーンをロックしている場合、OS のダイアログで解除を求められる

### Windows: DPAPI + ローカルファイル

```
[Vault]
   │ store(EMK)
   ▼
[SystemKeychainBackend]
   │ CryptProtectData（ユーザー資格情報で暗号化）
   ▼
[ローカルファイル]
   │ %AppData%/<appname>/emk/<key>
```

- DPAPI で EMK を暗号化（保護対象は現在ログイン中のユーザー）
- 暗号化済みバイナリを `%AppData%` 以下に保存
- ファイルパーミッションは OS に委ねる（必要に応じて追加設定）
- ログイン中のユーザーでないと復号できない

## セキュリティ上の注意

- 本実装はあくまで実験・サンプルコードです。本番利用の前にセキュリティレビューを行ってください。
- KEKはArgon2id（opslimit 3、memlimit 64 MiB）で導出します。コストはEMKに格納され、受入値には上限があります。
- 新規コードでは`decrypt()`ではなく、平文を通常メモリへコピーしない`decryptToSecureBuffer()`を使用してください。
- `FileBackend` は OS セキュアストレージが使えない場合の最後の手段として位置づけてください。
- 復号後の機密情報は `SecureBuffer` で管理し、使用後は即座に消去してください。
- 可能な限りメモリロック（`mlock` / `VirtualLock`）を利用し、スワップファイルへの漏洩を防いでください。

## ライセンス

このプロジェクトは実験的なサンプルコードです。ライセンスは別途指定がない限り、プロジェクトの所有者に帰属します。
